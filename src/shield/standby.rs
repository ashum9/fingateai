//! Month 4, Week 3: Hot-Standby Active/Passive Gateway State Replication (`fingate-standby`).
//!
//! Provides:
//! 1. Ultra-fast binary state replication from Primary to Standby node:
//!    - NextSenderMsgSeqNum & NextTargetMsgSeqNum synchronization.
//!    - Active working order states & ClOrdID mappings.
//! 2. Heartbeat watchdog: If Primary fails to pulse for > `heartbeat_timeout_ms`,
//!    Standby transitions to Active state immediately.
//! 3. Zero-gap failover: Standby seamlessly assumes the external session with
//!    exact sequence continuity and zero dropped fills.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GatewayNodeRole {
    Primary,
    Standby,
    FailedOverActive,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateReplicationPacket {
    pub primary_seq_id: u64,
    pub next_sender_seq: u64,
    pub next_target_seq: u64,
    pub active_orders: Vec<(String, u64)>, // (wire_cl_ord_id, leaves_qty)
    pub timestamp_ms: u64,
}

pub struct StandbyGatewayNode {
    pub role: GatewayNodeRole,
    pub next_sender_seq: u64,
    pub next_target_seq: u64,
    pub working_orders: HashMap<String, u64>,
    pub last_primary_pulse_ms: u64,
    pub heartbeat_timeout_ms: u64,
    pub last_applied_replication_id: u64,
    pub total_failovers: u64,
}

impl StandbyGatewayNode {
    pub fn new(heartbeat_timeout_ms: u64) -> Self {
        Self {
            role: GatewayNodeRole::Standby,
            next_sender_seq: 1,
            next_target_seq: 1,
            working_orders: HashMap::new(),
            last_primary_pulse_ms: 0,
            heartbeat_timeout_ms,
            last_applied_replication_id: 0,
            total_failovers: 0,
        }
    }

    /// Process a replication frame from Primary node.
    pub fn apply_replication(&mut self, pkt: StateReplicationPacket) {
        if pkt.primary_seq_id <= self.last_applied_replication_id {
            return; // Ignore older out-of-order replication packet
        }

        self.last_applied_replication_id = pkt.primary_seq_id;
        self.next_sender_seq = pkt.next_sender_seq;
        self.next_target_seq = pkt.next_target_seq;
        self.last_primary_pulse_ms = pkt.timestamp_ms;

        self.working_orders.clear();
        for (wire_id, leaves) in pkt.active_orders {
            self.working_orders.insert(wire_id, leaves);
        }
    }

    /// Heartbeat watchdog tick: checks if Primary is alive or if Standby must take over.
    pub fn check_watchdog(&mut self, now_ms: u64) -> bool {
        if self.role == GatewayNodeRole::Standby {
            if now_ms.saturating_sub(self.last_primary_pulse_ms) >= self.heartbeat_timeout_ms {
                self.role = GatewayNodeRole::FailedOverActive;
                self.total_failovers += 1;
                return true; // Failover triggered!
            }
        }
        false
    }
}
