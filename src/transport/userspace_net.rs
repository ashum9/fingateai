//! Gap 1 (E1): Zero-Allocation Userspace L2/IPv4/TCP Wire Framing Engine (`UserspaceTcpSession`).
//!
//! Runs directly over ANY kernel-bypass [`WireTransport`] (`AF_XDP`, `DPDK`, Solarflare `ef_vi` CTPIO,
//! or `SimNicTransport`)—completely eliminating `tokio::net::TcpStream` and OS kernel TCP/IP syscalls!
//!
//! Packet Layout (exact 54-byte wire header matching `crates/fingate-xdp-ebpf` XDP filter):
//! - Bytes  0..14: Ethernet II (`dst_mac[6] | src_mac[6] | ethertype=0x0800`)
//! - Bytes 14..34: IPv4 (`ver_ihl=0x45`, `total_len`, `id`, `DF`, `ttl=64`, `proto=6`, RFC 1071 checksum)
//! - Bytes 34..54: TCP (`src_port`, `dst_port`, `seq`, `ack`, `off=0x50`, `PSH|ACK`, `win`, RFC 793 checksum)
//! - Bytes 54..N : Application payload (FIX 4.4 / CME iLink 3 SBE / Nasdaq OUCH 5.0 / Cboe BOE3 / NSE TRIM)

use crate::transport::WireTransport;

pub const ETH_HDR_LEN: usize = 14;
pub const IPV4_HDR_LEN: usize = 20;
pub const TCP_HDR_LEN: usize = 20;
pub const L2_L3_L4_HDR_LEN: usize = ETH_HDR_LEN + IPV4_HDR_LEN + TCP_HDR_LEN; // 54 bytes
pub const ETHERTYPE_IPV4: u16 = 0x0800;
pub const IP_PROTO_TCP: u8 = 6;
pub const TCP_FLAG_ACK: u8 = 0x10;
pub const TCP_FLAG_PSH: u8 = 0x08;

/// Endpoint L2/L3/L4 addressing configuration for a kernel-bypass exchange connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UserspaceTcpConfig {
    pub local_mac: [u8; 6],
    pub remote_mac: [u8; 6],
    pub local_ip: [u8; 4],
    pub remote_ip: [u8; 4],
    pub local_port: u16,
    pub remote_port: u16,
}

impl UserspaceTcpConfig {
    pub fn swap_endpoints(&self) -> Self {
        Self {
            local_mac: self.remote_mac,
            remote_mac: self.local_mac,
            local_ip: self.remote_ip,
            remote_ip: self.local_ip,
            local_port: self.remote_port,
            remote_port: self.local_port,
        }
    }
}

/// RFC 1071 16-bit one's-complement checksum over a byte slice (zero allocs).
#[inline(always)]
pub fn internet_checksum(bytes: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0usize;
    while i + 1 < bytes.len() {
        let word = u16::from_be_bytes([bytes[i], bytes[i + 1]]) as u32;
        sum += word;
        i += 2;
    }
    if i < bytes.len() {
        sum += (bytes[i] as u32) << 8;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

/// Compute RFC 793 TCP checksum covering IPv4 pseudo-header + TCP header + payload.
#[inline(always)]
fn tcp_checksum(src_ip: [u8; 4], dst_ip: [u8; 4], tcp_segment: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    sum += u16::from_be_bytes([src_ip[0], src_ip[1]]) as u32;
    sum += u16::from_be_bytes([src_ip[2], src_ip[3]]) as u32;
    sum += u16::from_be_bytes([dst_ip[0], dst_ip[1]]) as u32;
    sum += u16::from_be_bytes([dst_ip[2], dst_ip[3]]) as u32;
    sum += IP_PROTO_TCP as u32;
    sum += tcp_segment.len() as u32;

    let mut i = 0usize;
    while i + 1 < tcp_segment.len() {
        sum += u16::from_be_bytes([tcp_segment[i], tcp_segment[i + 1]]) as u32;
        i += 2;
    }
    if i < tcp_segment.len() {
        sum += (tcp_segment[i] as u32) << 8;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

/// Zero-copy parsed view of an inbound Ethernet + IPv4 + TCP packet.
#[derive(Debug, Clone, Copy)]
pub struct ParsedTcpFrame<'a> {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq_num: u32,
    pub ack_num: u32,
    pub flags: u8,
    pub payload: &'a [u8],
}

/// Zero-copy parser validating Ethernet II -> IPv4 checksum -> TCP ports & payload slice.
#[inline(always)]
pub fn parse_l2_ipv4_tcp_zero_copy(frame: &[u8]) -> Option<ParsedTcpFrame<'_>> {
    if frame.len() < L2_L3_L4_HDR_LEN {
        return None;
    }
    if u16::from_be_bytes([frame[12], frame[13]]) != ETHERTYPE_IPV4 {
        return None;
    }
    let ver_ihl = frame[14];
    if (ver_ihl >> 4) != 4 {
        return None;
    }
    let ip_hdr_len = ((ver_ihl & 0x0F) as usize) * 4;
    if ip_hdr_len < IPV4_HDR_LEN || frame.len() < ETH_HDR_LEN + ip_hdr_len + TCP_HDR_LEN {
        return None;
    }
    if frame[14 + 9] != IP_PROTO_TCP {
        return None;
    }
    // Validate RFC 1071 IPv4 header checksum (must fold to 0)
    if internet_checksum(&frame[14..14 + ip_hdr_len]) != 0 {
        return None;
    }
    let ip_total_len = u16::from_be_bytes([frame[16], frame[17]]) as usize;
    let frame_end = (ETH_HDR_LEN + ip_total_len).min(frame.len());
    let tcp_start = ETH_HDR_LEN + ip_hdr_len;
    if frame_end < tcp_start + TCP_HDR_LEN {
        return None;
    }
    let tcp_hdr_len = ((frame[tcp_start + 12] >> 4) as usize) * 4;
    if tcp_hdr_len < TCP_HDR_LEN || tcp_start + tcp_hdr_len > frame_end {
        return None;
    }

    let src_port = u16::from_be_bytes([frame[tcp_start], frame[tcp_start + 1]]);
    let dst_port = u16::from_be_bytes([frame[tcp_start + 2], frame[tcp_start + 3]]);
    let seq_num = u32::from_be_bytes([
        frame[tcp_start + 4],
        frame[tcp_start + 5],
        frame[tcp_start + 6],
        frame[tcp_start + 7],
    ]);
    let ack_num = u32::from_be_bytes([
        frame[tcp_start + 8],
        frame[tcp_start + 9],
        frame[tcp_start + 10],
        frame[tcp_start + 11],
    ]);
    let flags = frame[tcp_start + 13];
    let payload = &frame[tcp_start + tcp_hdr_len..frame_end];

    Some(ParsedTcpFrame {
        src_port,
        dst_port,
        seq_num,
        ack_num,
        flags,
        payload,
    })
}

/// Zero-allocation userspace TCP stream running directly over a kernel-bypass `WireTransport`.
pub struct UserspaceTcpSession<T: WireTransport> {
    pub transport: T,
    pub config: UserspaceTcpConfig,
    pub tx_seq: u32,
    pub rx_ack: u32,
    ip_id: u16,
    /// Pre-formatted 54-byte template header for fast copy on TX (0 heap allocs).
    tx_scratch: [u8; 256],
    pub frames_tx: u64,
    pub frames_rx: u64,
}

impl<T: WireTransport> UserspaceTcpSession<T> {
    pub fn new(transport: T, config: UserspaceTcpConfig) -> Self {
        let mut tx_scratch = [0u8; 256];
        // Pre-populate constant L2/L3/L4 header fields once at setup
        tx_scratch[0..6].copy_from_slice(&config.remote_mac);
        tx_scratch[6..12].copy_from_slice(&config.local_mac);
        tx_scratch[12..14].copy_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
        tx_scratch[14] = 0x45; // IPv4, IHL=5 (20B)
        tx_scratch[15] = 0x00;
        tx_scratch[20] = 0x40; // Don't Fragment
        tx_scratch[21] = 0x00;
        tx_scratch[22] = 64;   // TTL
        tx_scratch[23] = IP_PROTO_TCP;
        tx_scratch[26..30].copy_from_slice(&config.local_ip);
        tx_scratch[30..34].copy_from_slice(&config.remote_ip);
        tx_scratch[34..36].copy_from_slice(&config.local_port.to_be_bytes());
        tx_scratch[36..38].copy_from_slice(&config.remote_port.to_be_bytes());
        tx_scratch[46] = 0x50; // Data offset = 5 (20B TCP hdr)
        tx_scratch[47] = TCP_FLAG_PSH | TCP_FLAG_ACK;
        tx_scratch[48..50].copy_from_slice(&65535u16.to_be_bytes()); // Window

        Self {
            transport,
            config,
            tx_seq: 1,
            rx_ack: 1,
            ip_id: 1,
            tx_scratch,
            frames_tx: 0,
            frames_rx: 0,
        }
    }

    /// Encapsulate `payload` in Ethernet + IPv4 + TCP with valid checksums and transmit inline (`0` allocs).
    #[inline]
    pub fn send_payload_inline(&mut self, payload: &[u8]) -> Result<usize, &'static str> {
        let total_frame_len = L2_L3_L4_HDR_LEN + payload.len();
        if total_frame_len > self.tx_scratch.len() {
            return Err("payload exceeds inline kernel-bypass frame slot");
        }
        let ip_total_len = (IPV4_HDR_LEN + TCP_HDR_LEN + payload.len()) as u16;
        self.tx_scratch[16..18].copy_from_slice(&ip_total_len.to_be_bytes());
        self.tx_scratch[18..20].copy_from_slice(&self.ip_id.to_be_bytes());
        self.ip_id = self.ip_id.wrapping_add(1);
        // Zero IPv4 checksum before computing RFC 1071
        self.tx_scratch[24] = 0;
        self.tx_scratch[25] = 0;
        let ip_cs = internet_checksum(&self.tx_scratch[14..34]);
        self.tx_scratch[24..26].copy_from_slice(&ip_cs.to_be_bytes());

        // TCP seq/ack + payload + RFC 793 checksum
        self.tx_scratch[38..42].copy_from_slice(&self.tx_seq.to_be_bytes());
        self.tx_scratch[42..46].copy_from_slice(&self.rx_ack.to_be_bytes());
        self.tx_scratch[50] = 0;
        self.tx_scratch[51] = 0;
        self.tx_scratch[L2_L3_L4_HDR_LEN..total_frame_len].copy_from_slice(payload);

        let tcp_cs = tcp_checksum(
            self.config.local_ip,
            self.config.remote_ip,
            &self.tx_scratch[34..total_frame_len],
        );
        self.tx_scratch[50..52].copy_from_slice(&tcp_cs.to_be_bytes());

        self.tx_seq = self.tx_seq.wrapping_add(payload.len() as u32);
        self.frames_tx += 1;
        self.transport
            .tx_frame_inline(&self.tx_scratch[..total_frame_len])
    }

    /// Poll `WireTransport` RX ring directly, validating L2/IPv4/TCP and passing zero-copy payload slice.
    #[inline]
    pub fn poll_payload_burst<F: FnMut(&[u8], u64)>(&mut self, max_burst: usize, mut on_payload: F) -> usize {
        let expect_dst = self.config.local_port;
        let expect_src = self.config.remote_port;
        let mut rx_ack = self.rx_ack;
        let mut matched = 0usize;

        self.transport.poll_rx_burst(max_burst, |frame, tsc| {
            if let Some(parsed) = parse_l2_ipv4_tcp_zero_copy(frame) {
                if parsed.dst_port == expect_dst && parsed.src_port == expect_src {
                    rx_ack = parsed.seq_num.wrapping_add(parsed.payload.len() as u32);
                    matched += 1;
                    on_payload(parsed.payload, tsc);
                }
            }
        });

        self.rx_ack = rx_ack;
        self.frames_rx += matched as u64;
        matched
    }
}
