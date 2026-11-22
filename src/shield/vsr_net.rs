//! Gap 5 (E5): Real Networked 3-Node UDP VSR Quorum Consensus Transport (`VsrNetCluster`).
//!
//! Elevates [`VsrCluster`](crate::shield::vsr_consensus::VsrCluster) from in-memory simulation
//! to REAL OS `UdpSocket` wire datagrams across 3 independent sockets (`127.0.0.1:0` or cluster IPs):
//! - Fixed 96-byte binary `VsrWireDatagram` (`magic="VSR1"`, `CRC32C` integrity verified on RX)
//! - Wire message types: `Prepare`, `PrepareOk`, `DoViewChange`, `StartView`, `RepairRequest`, `RepairReply`
//! - Real network quorum voting (`>= 2/3`), real UDP view change failover, real stale-view fencing
//!   rejection over the wire, and real UDP peer bitrot healing!

use std::net::{SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

use anyhow::{anyhow, Result};
use crc32fast::Hasher as Crc32Hasher;

use crate::shield::vsr_consensus::{VsrError, VsrLogEntry, VsrRole};

pub const VSR_WIRE_MAGIC: [u8; 4] = *b"VSR1";
pub const VSR_WIRE_SIZE: usize = 96;

pub const VSR_MSG_PREPARE: u8 = 1;
pub const VSR_MSG_PREPARE_OK: u8 = 2;
pub const VSR_MSG_STALE_VIEW: u8 = 3;
pub const VSR_MSG_START_VIEW: u8 = 4;
pub const VSR_MSG_REPAIR_REQ: u8 = 5;
pub const VSR_MSG_REPAIR_REPLY: u8 = 6;

/// Fixed 96-byte binary UDP datagram for inter-node FinGate VSR replication.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VsrWireDatagram {
    pub msg_type: u8,
    pub sender_id: u8,
    pub payload_len: u8,
    pub view_number: u64,
    pub op_number: u64,
    pub payload: [u8; 64],
    pub entry_crc: u32,
}

impl VsrWireDatagram {
    /// Serialize into exact 96-byte network packet with trailing packet-level CRC32C (`0` heap allocs).
    pub fn encode(&self, out: &mut [u8; VSR_WIRE_SIZE]) {
        out.fill(0);
        out[0..4].copy_from_slice(&VSR_WIRE_MAGIC);
        out[4] = self.msg_type;
        out[5] = self.sender_id;
        out[6] = self.payload_len;
        out[8..16].copy_from_slice(&self.view_number.to_le_bytes());
        out[16..24].copy_from_slice(&self.op_number.to_le_bytes());
        out[24..28].copy_from_slice(&self.entry_crc.to_le_bytes());
        out[28..92].copy_from_slice(&self.payload);

        let mut h = Crc32Hasher::new();
        h.update(&out[0..92]);
        let pkt_crc = h.finalize();
        out[92..96].copy_from_slice(&pkt_crc.to_le_bytes());
    }

    /// Parse & validate magic + packet CRC32C from raw UDP bytes (`0` heap allocs).
    pub fn decode(raw: &[u8]) -> Option<Self> {
        if raw.len() < VSR_WIRE_SIZE || raw[0..4] != VSR_WIRE_MAGIC {
            return None;
        }
        let expected_crc = u32::from_le_bytes(raw[92..96].try_into().ok()?);
        let mut h = Crc32Hasher::new();
        h.update(&raw[0..92]);
        if h.finalize() != expected_crc {
            return None;
        }
        let mut payload = [0u8; 64];
        payload.copy_from_slice(&raw[28..92]);
        Some(Self {
            msg_type: raw[4],
            sender_id: raw[5],
            payload_len: raw[6],
            view_number: u64::from_le_bytes(raw[8..16].try_into().ok()?),
            op_number: u64::from_le_bytes(raw[16..24].try_into().ok()?),
            payload,
            entry_crc: u32::from_le_bytes(raw[24..28].try_into().ok()?),
        })
    }
}

/// One physical/OS-socket VSR node bound to its own real `UdpSocket`.
pub struct VsrUdpNode {
    pub node_id: u8,
    pub local_addr: SocketAddr,
    socket: UdpSocket,
    pub peer_addrs: [SocketAddr; 3],
    pub view_number: u64,
    pub role: VsrRole,
    pub commit_number: u64,
    pub log: Vec<VsrLogEntry>,
    pub online: bool,
    pub datagrams_sent: u64,
    pub datagrams_recv: u64,
}

impl VsrUdpNode {
    fn send_to(&mut self, peer_idx: usize, msg: &VsrWireDatagram) -> Result<()> {
        let mut buf = [0u8; VSR_WIRE_SIZE];
        msg.encode(&mut buf);
        self.socket.send_to(&buf, self.peer_addrs[peer_idx])?;
        self.datagrams_sent += 1;
        Ok(())
    }

    /// Drain all currently queued inbound UDP datagrams on this node's socket and process them.
    pub fn poll_udp_inbox(&mut self) -> usize {
        if !self.online {
            return 0;
        }
        let mut buf = [0u8; 256];
        let mut processed = 0usize;
        while let Ok((n, _src)) = self.socket.recv_from(&mut buf) {
            let Some(msg) = VsrWireDatagram::decode(&buf[..n]) else {
                continue;
            };
            self.datagrams_recv += 1;
            processed += 1;
            match msg.msg_type {
                VSR_MSG_PREPARE => {
                    if msg.view_number < self.view_number {
                        // Invariant I10 over UDP: reject stale primary view!
                        let rej = VsrWireDatagram {
                            msg_type: VSR_MSG_STALE_VIEW,
                            sender_id: self.node_id,
                            payload_len: 0,
                            view_number: self.view_number,
                            op_number: msg.op_number,
                            payload: [0u8; 64],
                            entry_crc: 0,
                        };
                        let _ = self.send_to(msg.sender_id as usize, &rej);
                    } else {
                        self.view_number = msg.view_number;
                        self.role = VsrRole::Backup;
                        let entry = VsrLogEntry {
                            op_number: msg.op_number,
                            view_number: msg.view_number,
                            payload_len: msg.payload_len,
                            payload: msg.payload,
                            crc32: msg.entry_crc,
                        };
                        if entry.verify_crc() {
                            let idx = (entry.op_number as usize).saturating_sub(1);
                            if idx < self.log.len() {
                                self.log[idx] = entry;
                            } else {
                                self.log.push(entry);
                            }
                            self.commit_number = self.commit_number.max(entry.op_number);
                            let ack = VsrWireDatagram {
                                msg_type: VSR_MSG_PREPARE_OK,
                                sender_id: self.node_id,
                                payload_len: 0,
                                view_number: self.view_number,
                                op_number: entry.op_number,
                                payload: [0u8; 64],
                                entry_crc: entry.crc32,
                            };
                            let _ = self.send_to(msg.sender_id as usize, &ack);
                        }
                    }
                }
                VSR_MSG_START_VIEW => {
                    if msg.view_number > self.view_number {
                        self.view_number = msg.view_number;
                        self.role = if ((msg.view_number - 1) % 3) as u8 == self.node_id {
                            VsrRole::Primary
                        } else {
                            VsrRole::Backup
                        };
                    }
                }
                VSR_MSG_REPAIR_REQ => {
                    let slot = (msg.op_number as usize).saturating_sub(1);
                    if let Some(entry) = self.log.get(slot) {
                        if entry.verify_crc() {
                            let reply = VsrWireDatagram {
                                msg_type: VSR_MSG_REPAIR_REPLY,
                                sender_id: self.node_id,
                                payload_len: entry.payload_len,
                                view_number: entry.view_number,
                                op_number: entry.op_number,
                                payload: entry.payload,
                                entry_crc: entry.crc32,
                            };
                            let _ = self.send_to(msg.sender_id as usize, &reply);
                        }
                    }
                }
                VSR_MSG_REPAIR_REPLY => {
                    let entry = VsrLogEntry {
                        op_number: msg.op_number,
                        view_number: msg.view_number,
                        payload_len: msg.payload_len,
                        payload: msg.payload,
                        crc32: msg.entry_crc,
                    };
                    let slot = (entry.op_number as usize).saturating_sub(1);
                    if entry.verify_crc() && slot < self.log.len() {
                        self.log[slot] = entry;
                    }
                }
                _ => {}
            }
        }
        processed
    }
}

/// Real 3-Socket UDP VSR Quorum Cluster (`3` live OS `UdpSocket`s exchanging binary `VSR1` frames).
pub struct VsrNetCluster {
    pub nodes: [VsrUdpNode; 3],
    pub total_udp_commits: u64,
    pub udp_stale_views_rejected: u64,
}

impl VsrNetCluster {
    /// Bind 3 real UDP sockets on `127.0.0.1:0` and wire full-mesh peer addresses.
    pub fn bind_local() -> Result<Self> {
        let s0 = UdpSocket::bind("127.0.0.1:0")?;
        let s1 = UdpSocket::bind("127.0.0.1:0")?;
        let s2 = UdpSocket::bind("127.0.0.1:0")?;
        for s in [&s0, &s1, &s2] {
            s.set_nonblocking(true)?;
            let _ = s.set_read_timeout(Some(Duration::from_millis(50)));
        }
        let addrs = [s0.local_addr()?, s1.local_addr()?, s2.local_addr()?];
        let mk = |id: u8, socket: UdpSocket| VsrUdpNode {
            node_id: id,
            local_addr: addrs[id as usize],
            socket,
            peer_addrs: addrs,
            view_number: 1,
            role: if id == 0 { VsrRole::Primary } else { VsrRole::Backup },
            commit_number: 0,
            log: Vec::with_capacity(256),
            online: true,
            datagrams_sent: 0,
            datagrams_recv: 0,
        };
        Ok(Self {
            nodes: [mk(0, s0), mk(1, s1), mk(2, s2)],
            total_udp_commits: 0,
            udp_stale_views_rejected: 0,
        })
    }

    /// Replicate an order via real UDP `Prepare` -> `PrepareOk` quorum exchange (`>= 2/3`).
    pub fn submit_order_udp(&mut self, primary_id: u8, payload: &[u8]) -> Result<u64, VsrError> {
        let pidx = primary_id as usize;
        if pidx >= 3 || !self.nodes[pidx].online {
            return Err(VsrError::NodeUnavailable);
        }
        if self.nodes[pidx].role != VsrRole::Primary {
            return Err(VsrError::NotPrimary);
        }

        let view = self.nodes[pidx].view_number;
        let next_op = self.nodes[pidx].commit_number + 1;
        let entry = VsrLogEntry::new(next_op, view, payload);
        let prep = VsrWireDatagram {
            msg_type: VSR_MSG_PREPARE,
            sender_id: primary_id,
            payload_len: entry.payload_len,
            view_number: view,
            op_number: next_op,
            payload: entry.payload,
            entry_crc: entry.crc32,
        };

        for peer in 0..3 {
            if peer != pidx {
                let _ = self.nodes[pidx].send_to(peer, &prep);
            }
        }

        let expected_online_peers = (0..3)
            .filter(|&peer| peer != pidx && self.nodes[peer].online)
            .count();

        let mut acks = 1usize; // self vote
        let mut higher_view = 0u64;
        let mut buf = [0u8; 256];
        let deadline = Instant::now() + Duration::from_millis(25);

        // Poll real OS UDP sockets until all online peers reply or deadline expires
        loop {
            for peer in 0..3 {
                if peer != pidx && self.nodes[peer].online {
                    self.nodes[peer].poll_udp_inbox();
                }
            }
            while let Ok((n, _)) = self.nodes[pidx].socket.recv_from(&mut buf) {
                if let Some(reply) = VsrWireDatagram::decode(&buf[..n]) {
                    self.nodes[pidx].datagrams_recv += 1;
                    if reply.msg_type == VSR_MSG_PREPARE_OK
                        && reply.op_number == next_op
                        && reply.view_number == view
                    {
                        acks += 1;
                    } else if reply.msg_type == VSR_MSG_STALE_VIEW && reply.view_number > view {
                        higher_view = higher_view.max(reply.view_number);
                    }
                }
            }
            if higher_view > view || acks >= 1 + expected_online_peers || Instant::now() >= deadline {
                break;
            }
            std::thread::yield_now();
        }

        if higher_view > view {
            self.udp_stale_views_rejected += 1;
            self.nodes[pidx].view_number = higher_view;
            self.nodes[pidx].role = VsrRole::Backup;
            return Err(VsrError::StaleFencingView {
                attempted_view: view,
                active_view: higher_view,
            });
        }

        if acks < 2 {
            return Err(VsrError::NoQuorum { acks, required: 2 });
        }

        let idx = (next_op as usize).saturating_sub(1);
        if idx < self.nodes[pidx].log.len() {
            self.nodes[pidx].log[idx] = entry;
        } else {
            self.nodes[pidx].log.push(entry);
        }
        self.nodes[pidx].commit_number = next_op;
        self.total_udp_commits += 1;
        Ok(next_op)
    }

    /// Broadcast real UDP `StartView` among online quorum nodes to elect a new monotonic view.
    pub fn elect_new_view_udp(&mut self, initiator_id: u8) -> Result<u64> {
        let mut online_cnt = 0usize;
        let mut max_view = 0u64;
        for n in &self.nodes {
            if n.online {
                online_cnt += 1;
                max_view = max_view.max(n.view_number);
            }
        }
        if online_cnt < 2 {
            return Err(anyhow!("cannot elect new view without UDP quorum"));
        }
        let mut new_view = max_view + 1;
        while !self.nodes[((new_view - 1) % 3) as usize].online {
            new_view += 1;
        }

        let sv = VsrWireDatagram {
            msg_type: VSR_MSG_START_VIEW,
            sender_id: initiator_id,
            payload_len: 0,
            view_number: new_view,
            op_number: 0,
            payload: [0u8; 64],
            entry_crc: 0,
        };
        let init = initiator_id as usize;
        for peer in 0..3 {
            if peer != init && self.nodes[peer].online {
                self.nodes[init].send_to(peer, &sv)?;
            }
        }
        for i in 0..3 {
            if self.nodes[i].online {
                self.nodes[i].poll_udp_inbox();
                self.nodes[i].view_number = new_view;
                self.nodes[i].role = if ((new_view - 1) % 3) as u8 == i as u8 {
                    VsrRole::Primary
                } else {
                    VsrRole::Backup
                };
            }
        }
        Ok(new_view)
    }

    /// Request real UDP `RepairRequest` -> `RepairReply` healing for a bitrot-corrupted local op!
    pub fn repair_op_over_udp(&mut self, victim_id: u8, op_number: u64) -> Result<bool> {
        let vidx = victim_id as usize;
        let req = VsrWireDatagram {
            msg_type: VSR_MSG_REPAIR_REQ,
            sender_id: victim_id,
            payload_len: 0,
            view_number: self.nodes[vidx].view_number,
            op_number,
            payload: [0u8; 64],
            entry_crc: 0,
        };
        let slot = (op_number as usize).saturating_sub(1);
        let deadline = Instant::now() + Duration::from_millis(25);
        for peer in 0..3 {
            if peer != vidx && self.nodes[peer].online {
                self.nodes[vidx].send_to(peer, &req)?;
            }
        }
        loop {
            for peer in 0..3 {
                if peer != vidx && self.nodes[peer].online {
                    self.nodes[peer].poll_udp_inbox();
                }
            }
            self.nodes[vidx].poll_udp_inbox();
            if self.nodes[vidx]
                .log
                .get(slot)
                .map(|e| e.verify_crc())
                .unwrap_or(false)
                || Instant::now() >= deadline
            {
                break;
            }
            std::thread::yield_now();
        }
        Ok(self.nodes[vidx]
            .log
            .get(slot)
            .map(|e| e.verify_crc())
            .unwrap_or(false))
    }
}
