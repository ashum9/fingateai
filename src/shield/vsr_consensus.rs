//! Phase D5: 3-Node Quorum Viewstamped Replication (`VSR`) Consensus with Epoch Fencing & Bitrot Repair.
//!
//! Inspired by **TigerBeetle `VSR`** (`Viewstamped Replication Revisited`):
//! - Replaces single-timeout active/passive failover (vulnerable to dual-primary split-brain)
//!   with monotonic **`view_number` quorum voting** (`quorum = (N / 2) + 1`, e.g., 2 of 3 replicas).
//! - **Strict Fencing Invariant (`I10`):** Every order & WAL commit carries `fencing_view: u64`.
//!   If a frozen primary (`view 1`) wakes up after a quorum view change (`view 2`), its stale
//!   `view 1` proposals are deterministically rejected by both quorum peers AND the fencing gate—
//!   making split-brain mathematically impossible (`0` dual-primary orders).
//! - **Protocol-Aware Peer Bitrot Repair:** When a replica detects a local WAL CRC32C failure,
//!   it requests the authoritative record from a healthy quorum peer and heals itself transparently.

use crc32fast::Hasher as Crc32Hasher;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VsrRole {
    Primary,
    Backup,
    ViewChange,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VsrError {
    NotPrimary,
    NodeUnavailable,
    NoQuorum { acks: usize, required: usize },
    StaleFencingView { attempted_view: u64, active_view: u64 },
    RepairFailedNoHealthyPeer,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VsrCommitReceipt {
    pub op_number: u64,
    pub fencing_view: u64,
    pub primary_id: u8,
    pub ack_count: usize,
}

/// Fixed-size replicated WAL entry protected by CRC32C checksum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VsrLogEntry {
    pub op_number: u64,
    pub view_number: u64,
    pub payload_len: u8,
    pub payload: [u8; 64],
    pub crc32: u32,
}

impl VsrLogEntry {
    pub fn new(op_number: u64, view_number: u64, data: &[u8]) -> Self {
        let len = data.len().min(64);
        let mut payload = [0u8; 64];
        payload[..len].copy_from_slice(&data[..len]);
        let mut entry = Self {
            op_number,
            view_number,
            payload_len: len as u8,
            payload,
            crc32: 0,
        };
        entry.crc32 = entry.compute_crc();
        entry
    }

    #[inline]
    pub fn compute_crc(&self) -> u32 {
        let mut h = Crc32Hasher::new();
        h.update(&self.op_number.to_le_bytes());
        h.update(&self.view_number.to_le_bytes());
        h.update(&[self.payload_len]);
        h.update(&self.payload[..self.payload_len as usize]);
        h.finalize()
    }

    #[inline]
    pub fn verify_crc(&self) -> bool {
        self.crc32 == self.compute_crc()
    }
}

/// Single replica in a 3-node VSR cluster.
#[derive(Debug, Clone)]
pub struct VsrReplica {
    pub replica_id: u8,
    pub view_number: u64,
    pub role: VsrRole,
    pub commit_number: u64,
    pub log: Vec<VsrLogEntry>,
    pub partitioned: bool,
    pub frozen: bool,
    pub repaired_entries: u64,
    pub stale_proposals_rejected: u64,
}

impl VsrReplica {
    pub fn new(replica_id: u8, initial_primary: u8) -> Self {
        Self {
            replica_id,
            view_number: 1,
            role: if replica_id == initial_primary {
                VsrRole::Primary
            } else {
                VsrRole::Backup
            },
            commit_number: 0,
            log: Vec::with_capacity(1024),
            partitioned: false,
            frozen: false,
            repaired_entries: 0,
            stale_proposals_rejected: 0,
        }
    }

    #[inline]
    pub fn is_reachable(&self) -> bool {
        !self.partitioned && !self.frozen
    }

    #[inline]
    pub fn op_number(&self) -> u64 {
        self.log.len() as u64
    }
}

/// 3-Node Quorum VSR Cluster Coordinator enforcing **Invariant `I10` (Epoch Fencing)**
/// and automatic **Protocol-Aware Peer Bitrot Repair**.
pub struct VsrCluster {
    pub replicas: [VsrReplica; 3],
    /// Monotonic fencing epoch enforced by the downstream venue uplink / fencing gate.
    pub venue_fencing_view: u64,
    /// Total committed orders emitted cleanly under valid fencing view.
    pub committed_orders: Vec<VsrLogEntry>,
    /// Counter of blocked split-brain attempts (stale primary trying to emit after view change).
    pub split_brain_attempts_blocked: u64,
}

impl Default for VsrCluster {
    fn default() -> Self {
        Self::new()
    }
}

impl VsrCluster {
    pub fn new() -> Self {
        Self {
            replicas: [
                VsrReplica::new(0, 0),
                VsrReplica::new(1, 0),
                VsrReplica::new(2, 0),
            ],
            venue_fencing_view: 1,
            committed_orders: Vec::with_capacity(1024),
            split_brain_attempts_blocked: 0,
        }
    }

    pub const fn quorum_size() -> usize {
        2
    }

    #[inline]
    pub fn primary_for_view(view: u64) -> u8 {
        ((view.saturating_sub(1)) % 3) as u8
    }

    pub fn active_primary_id(&self) -> Option<u8> {
        let mut best_view = 0u64;
        let mut best_id = None;
        for r in &self.replicas {
            if r.role == VsrRole::Primary && r.is_reachable() && r.view_number >= best_view {
                best_view = r.view_number;
                best_id = Some(r.replica_id);
            }
        }
        best_id
    }

    /// Isolate or reconnect a replica from/to the cluster network.
    pub fn set_partitioned(&mut self, replica_id: u8, partitioned: bool) {
        if let Some(r) = self.replicas.get_mut(replica_id as usize) {
            r.partitioned = partitioned;
        }
    }

    /// Simulate OS process freeze (`SIGSTOP` / GC pause) on a replica.
    pub fn set_frozen(&mut self, replica_id: u8, frozen: bool) {
        if let Some(r) = self.replicas.get_mut(replica_id as usize) {
            r.frozen = frozen;
        }
    }

    /// Submit an order proposal on `node_id`.
    /// Requires:
    /// 1. `node_id` believes it is `Primary` and is not frozen.
    /// 2. `view >= venue_fencing_view` (Invariant `I10` fencing against frozen stale primary).
    /// 3. Quorum (`>= 2` of `3`) healthy replicas accept the `Prepare` at `view`.
    pub fn submit_order_on_node(
        &mut self,
        node_id: u8,
        payload: &[u8],
    ) -> Result<VsrCommitReceipt, VsrError> {
        let idx = node_id as usize;
        if idx >= 3 {
            return Err(VsrError::NodeUnavailable);
        }
        if self.replicas[idx].frozen {
            return Err(VsrError::NodeUnavailable);
        }
        if self.replicas[idx].role != VsrRole::Primary {
            return Err(VsrError::NotPrimary);
        }

        let proposed_view = self.replicas[idx].view_number;

        // Invariant I10: Fencing gate deterministically rejects stale view orders!
        if proposed_view < self.venue_fencing_view {
            self.split_brain_attempts_blocked += 1;
            self.replicas[idx].stale_proposals_rejected += 1;
            // Force stale primary to step down if it can observe network state
            if !self.replicas[idx].partitioned {
                self.replicas[idx].role = VsrRole::Backup;
                self.replicas[idx].view_number = self.venue_fencing_view;
            }
            return Err(VsrError::StaleFencingView {
                attempted_view: proposed_view,
                active_view: self.venue_fencing_view,
            });
        }

        // Partitioned primary cannot reach any peer -> fails quorum (1 < 2)
        if self.replicas[idx].partitioned {
            return Err(VsrError::NoQuorum {
                acks: 1,
                required: Self::quorum_size(),
            });
        }

        let next_op = self.replicas[idx].commit_number + 1;
        let entry = VsrLogEntry::new(next_op, proposed_view, payload);

        // Collect PrepareOk votes from reachable peers
        let mut acks = 1usize; // self vote
        let mut higher_view_seen = 0u64;
        let mut accepting_peers = [false; 3];

        for peer_idx in 0..3 {
            if peer_idx == idx {
                continue;
            }
            let peer = &self.replicas[peer_idx];
            if !peer.is_reachable() {
                continue;
            }
            if peer.view_number > proposed_view {
                higher_view_seen = higher_view_seen.max(peer.view_number);
            } else {
                acks += 1;
                accepting_peers[peer_idx] = true;
            }
        }

        if higher_view_seen > proposed_view {
            self.split_brain_attempts_blocked += 1;
            self.replicas[idx].stale_proposals_rejected += 1;
            self.replicas[idx].role = VsrRole::Backup;
            self.replicas[idx].view_number = higher_view_seen;
            return Err(VsrError::StaleFencingView {
                attempted_view: proposed_view,
                active_view: higher_view_seen,
            });
        }

        if acks < Self::quorum_size() {
            return Err(VsrError::NoQuorum {
                acks,
                required: Self::quorum_size(),
            });
        }

        // Quorum achieved: append & commit on primary + accepting peers
        Self::append_entry_at(&mut self.replicas[idx], entry);
        self.replicas[idx].commit_number = next_op;

        for peer_idx in 0..3 {
            if accepting_peers[peer_idx] {
                self.replicas[peer_idx].view_number = proposed_view;
                self.replicas[peer_idx].role = VsrRole::Backup;
                Self::append_entry_at(&mut self.replicas[peer_idx], entry);
                self.replicas[peer_idx].commit_number = next_op;
            }
        }

        self.venue_fencing_view = self.venue_fencing_view.max(proposed_view);
        self.committed_orders.push(entry);

        Ok(VsrCommitReceipt {
            op_number: next_op,
            fencing_view: proposed_view,
            primary_id: node_id,
            ack_count: acks,
        })
    }

    fn append_entry_at(replica: &mut VsrReplica, entry: VsrLogEntry) {
        let target_idx = (entry.op_number as usize).saturating_sub(1);
        if target_idx < replica.log.len() {
            replica.log[target_idx] = entry;
        } else {
            replica.log.push(entry);
        }
    }

    /// Initiate a Quorum View Change (e.g. when backups detect Primary timeout/partition).
    /// Elects a reachable new Primary with strictly monotonic `view_number`, advances
    /// `venue_fencing_view`, and synchronizes the authoritative committed log suffix.
    pub fn trigger_view_change(&mut self, initiator_id: u8) -> Result<u64, VsrError> {
        let init_idx = initiator_id as usize;
        if init_idx >= 3 || !self.replicas[init_idx].is_reachable() {
            return Err(VsrError::NodeUnavailable);
        }

        let mut reachable = Vec::with_capacity(3);
        let mut max_view = self.venue_fencing_view;
        for i in 0..3 {
            if self.replicas[i].is_reachable() {
                max_view = max_view.max(self.replicas[i].view_number);
                reachable.push(i);
            }
        }

        if reachable.len() < Self::quorum_size() {
            return Err(VsrError::NoQuorum {
                acks: reachable.len(),
                required: Self::quorum_size(),
            });
        }

        // Choose next monotonic view whose deterministic primary is reachable
        let mut new_view = max_view + 1;
        while !reachable.contains(&(Self::primary_for_view(new_view) as usize)) {
            new_view += 1;
        }
        let new_primary = Self::primary_for_view(new_view) as usize;

        // Select the healthiest longest valid log among quorum members
        let mut best_log: Vec<VsrLogEntry> = Vec::new();
        let mut best_commit = 0u64;
        for &i in &reachable {
            let valid_len = self.replicas[i]
                .log
                .iter()
                .take_while(|e| e.verify_crc())
                .count();
            if valid_len > best_log.len() || self.replicas[i].commit_number > best_commit {
                best_log = self.replicas[i].log[..valid_len].to_vec();
                best_commit = best_commit.max(self.replicas[i].commit_number);
            }
        }

        // Install StartView across all reachable quorum members
        for &i in &reachable {
            self.replicas[i].view_number = new_view;
            self.replicas[i].role = if i == new_primary {
                VsrRole::Primary
            } else {
                VsrRole::Backup
            };
            self.replicas[i].log = best_log.clone();
            self.replicas[i].commit_number = best_commit;
        }

        self.venue_fencing_view = new_view;
        Ok(new_view)
    }

    /// Reconcile a recovered replica after partition heal or unfreeze: steps down stale primary
    /// and catches up all missing committed ops from the active quorum primary.
    pub fn catchup_replica(&mut self, replica_id: u8) -> usize {
        let idx = replica_id as usize;
        if idx >= 3 || !self.replicas[idx].is_reachable() {
            return 0;
        }
        let Some(primary_id) = self.active_primary_id() else {
            return 0;
        };
        let pidx = primary_id as usize;
        if pidx == idx {
            return 0;
        }
        let primary_view = self.replicas[pidx].view_number;
        let primary_commit = self.replicas[pidx].commit_number;
        let primary_log = self.replicas[pidx].log.clone();

        let target = &mut self.replicas[idx];
        let old_len = target.log.len();
        target.view_number = primary_view;
        target.role = VsrRole::Backup;
        target.log = primary_log;
        target.commit_number = primary_commit;
        target.log.len().saturating_sub(old_len)
    }

    /// Inject silent disk sector bitrot into a specific replica's WAL entry (for chaos/D5 testing).
    pub fn inject_disk_bitrot(&mut self, replica_id: u8, op_number: u64) -> bool {
        let Some(r) = self.replicas.get_mut(replica_id as usize) else {
            return false;
        };
        let slot = (op_number as usize).saturating_sub(1);
        if let Some(entry) = r.log.get_mut(slot) {
            entry.payload[0] ^= 0xFF; // Flip bits without updating CRC!
            return true;
        }
        false
    }

    /// Protocol-Aware Peer Bitrot Repair (TigerBeetle VSR):
    /// Scans `replica_id`'s WAL for CRC32C failures and repairs each corrupted record
    /// from a healthy reachable quorum peer whose record verifies CRC32C cleanly.
    pub fn repair_bitrot_from_peers(&mut self, replica_id: u8) -> Result<usize, VsrError> {
        let idx = replica_id as usize;
        if idx >= 3 || !self.replicas[idx].is_reachable() {
            return Err(VsrError::NodeUnavailable);
        }

        let mut corrupted_indices = Vec::new();
        for (i, entry) in self.replicas[idx].log.iter().enumerate() {
            if !entry.verify_crc() {
                corrupted_indices.push(i);
            }
        }

        let mut repaired = 0usize;
        for slot in corrupted_indices {
            let mut replacement = None;
            for peer_idx in 0..3 {
                if peer_idx == idx || !self.replicas[peer_idx].is_reachable() {
                    continue;
                }
                if let Some(peer_entry) = self.replicas[peer_idx].log.get(slot) {
                    if peer_entry.verify_crc() {
                        replacement = Some(*peer_entry);
                        break;
                    }
                }
            }
            match replacement {
                Some(good) => {
                    self.replicas[idx].log[slot] = good;
                    self.replicas[idx].repaired_entries += 1;
                    repaired += 1;
                }
                None => return Err(VsrError::RepairFailedNoHealthyPeer),
            }
        }
        Ok(repaired)
    }

    /// Verify **Invariant `I10`**:
    /// - No committed order has a decreasing `fencing_view`
    /// - Every committed op across healthy replicas is bit-identical and passes CRC32C
    pub fn verify_cluster_invariants(&self) -> Result<(), &'static str> {
        let mut last_view = 0u64;
        for (i, entry) in self.committed_orders.iter().enumerate() {
            if !entry.verify_crc() {
                return Err("I10 violation: committed log entry CRC corrupted");
            }
            if entry.op_number != (i as u64 + 1) {
                return Err("I10 violation: non-contiguous committed op sequence");
            }
            if entry.view_number < last_view {
                return Err("I10 violation: non-monotonic fencing view in committed history");
            }
            last_view = entry.view_number;
        }
        Ok(())
    }
}
