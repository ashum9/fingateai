//! Month 4, Week 1: N:1 Strategy Pod Multiplexer & Bidirectional `ClOrdID` Routing Table.
//!
//! Provides:
//! 1. Multi-pod ingress multiplexer: Strategy pods connect locally (via UDS or loopback),
//!    while FinGate maintains the single sequence-locked session to the exchange.
//! 2. Bidirectional O(1) `ClOrdID` Router:
//!    - Translates internal pod `ClOrdID` (e.g. `pod_ord_1`) into an exchange-unique wire ID (`FG-pod_id-pod_ord_1`).
//!    - Routes venue execution reports (`35=8`) back to the originating strategy pod in `< 2 µs`.
//! 3. Pod session lifecycle tracking: active, disconnected, or grace-period recovery.

use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PodStatus {
    Active,
    Disconnected { disconnected_at_ms: u64 },
    Recovered,
}

#[derive(Debug, Clone)]
pub struct PodOrderMetadata {
    pub pod_id: String,
    pub original_cl_ord_id: String,
    pub wire_cl_ord_id: String,
    pub symbol: String,
    pub leaves_qty: u64,
    pub price: u64,
    pub is_buy: bool,
    pub submitted_at_ms: u64,
}

pub struct ClOrdIdRouter {
    pub gateway_prefix: String,
    // wire_cl_ord_id -> PodOrderMetadata
    pub wire_to_pod: HashMap<String, PodOrderMetadata>,
    // (pod_id, original_cl_ord_id) -> wire_cl_ord_id
    pub pod_to_wire: HashMap<(String, String), String>,
    pub next_wire_seq: u64,
}

impl ClOrdIdRouter {
    pub fn new(gateway_prefix: &str) -> Self {
        Self {
            gateway_prefix: gateway_prefix.to_string(),
            wire_to_pod: HashMap::with_capacity(16384),
            pod_to_wire: HashMap::with_capacity(16384),
            next_wire_seq: 1,
        }
    }

    /// Register an outbound order from an internal strategy pod and generate the exchange wire ID.
    pub fn register_outbound_order(
        &mut self,
        pod_id: &str,
        pod_cl_ord_id: &str,
        symbol: &str,
        leaves_qty: u64,
        price: u64,
        is_buy: bool,
        now_ms: u64,
    ) -> String {
        let wire_id = format!("{}-{}-{:08}", self.gateway_prefix, pod_id, self.next_wire_seq);
        self.next_wire_seq += 1;

        let meta = PodOrderMetadata {
            pod_id: pod_id.to_string(),
            original_cl_ord_id: pod_cl_ord_id.to_string(),
            wire_cl_ord_id: wire_id.clone(),
            symbol: symbol.to_string(),
            leaves_qty,
            price,
            is_buy,
            submitted_at_ms: now_ms,
        };

        self.wire_to_pod.insert(wire_id.clone(), meta);
        self.pod_to_wire.insert((pod_id.to_string(), pod_cl_ord_id.to_string()), wire_id.clone());

        wire_id
    }

    /// Route an incoming venue ExecutionReport (`35=8`) by wire `ClOrdID`.
    /// Returns the originating (pod_id, original_cl_ord_id, remaining_leaves_qty).
    pub fn route_inbound_fill(&mut self, wire_cl_ord_id: &str, fill_qty: u64) -> Option<(String, String, u64)> {
        if let Some(meta) = self.wire_to_pod.get_mut(wire_cl_ord_id) {
            meta.leaves_qty = meta.leaves_qty.saturating_sub(fill_qty);
            let pod_id = meta.pod_id.clone();
            let original_id = meta.original_cl_ord_id.clone();
            let rem_qty = meta.leaves_qty;

            if rem_qty == 0 {
                // Order completely filled: keep mapping for DropCopy/history lookup
            }

            Some((pod_id, original_id, rem_qty))
        } else {
            None
        }
    }

    pub fn get_order(&self, wire_cl_ord_id: &str) -> Option<&PodOrderMetadata> {
        self.wire_to_pod.get(wire_cl_ord_id)
    }

    pub fn get_wire_id(&self, pod_id: &str, pod_cl_ord_id: &str) -> Option<&String> {
        self.pod_to_wire.get(&(pod_id.to_string(), pod_cl_ord_id.to_string()))
    }
}

pub struct StrategyPodMultiplexer {
    pub router: ClOrdIdRouter,
    pub pods: HashMap<String, PodStatus>,
    pub total_pod_orders: u64,
    pub total_fills_routed: u64,
}

impl StrategyPodMultiplexer {
    pub fn new(gateway_prefix: &str) -> Self {
        Self {
            router: ClOrdIdRouter::new(gateway_prefix),
            pods: HashMap::new(),
            total_pod_orders: 0,
            total_fills_routed: 0,
        }
    }

    pub fn register_pod(&mut self, pod_id: &str) {
        self.pods.insert(pod_id.to_string(), PodStatus::Active);
    }

    pub fn on_pod_disconnect(&mut self, pod_id: &str, now_ms: u64) {
        if let Some(status) = self.pods.get_mut(pod_id) {
            *status = PodStatus::Disconnected { disconnected_at_ms: now_ms };
        }
    }

    pub fn on_pod_reconnect(&mut self, pod_id: &str) {
        if let Some(status) = self.pods.get_mut(pod_id) {
            *status = PodStatus::Recovered;
        }
    }

    pub fn is_pod_active(&self, pod_id: &str) -> bool {
        matches!(self.pods.get(pod_id), Some(PodStatus::Active | PodStatus::Recovered))
    }
}

/// Phase C3: Stack-resident fixed-width wire ClOrdID (`[u8; 32]`, 0 heap allocations).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FixedWireId {
    pub bytes: [u8; 32],
    pub len: u8,
    pub wire_seq: u64,
}

impl FixedWireId {
    #[inline(always)]
    pub fn as_str(&self) -> &str {
        unsafe { std::str::from_utf8_unchecked(&self.bytes[..self.len as usize]) }
    }

    /// Format `<prefix>-P<pod_slot>-<8-digit seq>` directly into stack `[u8; 32]`.
    #[inline(always)]
    pub fn format_inline(prefix: &[u8], pod_slot: u16, wire_seq: u64) -> Self {
        let mut bytes = [0u8; 32];
        let p_len = prefix.len().min(12);
        bytes[..p_len].copy_from_slice(&prefix[..p_len]);
        let mut cursor = p_len;
        bytes[cursor] = b'-';
        cursor += 1;
        bytes[cursor] = b'P';
        cursor += 1;
        // 3-digit pod slot
        bytes[cursor] = b'0' + ((pod_slot / 100) % 10) as u8;
        bytes[cursor + 1] = b'0' + ((pod_slot / 10) % 10) as u8;
        bytes[cursor + 2] = b'0' + (pod_slot % 10) as u8;
        cursor += 3;
        bytes[cursor] = b'-';
        cursor += 1;
        // 8-digit sequence number
        let mut n = wire_seq;
        for pos in (0..8).rev() {
            bytes[cursor + pos] = b'0' + (n % 10) as u8;
            n /= 10;
        }
        cursor += 8;
        Self {
            bytes,
            len: cursor as u8,
            wire_seq,
        }
    }
}

/// Cache-line-friendly flat order slot for zero-allocation O(1) routing.
#[derive(Debug, Clone, Copy, Default)]
#[repr(align(64))]
pub struct FastPodOrderSlot {
    pub wire_seq: u64,
    pub pod_slot: u16,
    pub is_buy: bool,
    pub pod_cl_ord_id_hash: u64,
    pub leaves_qty: u64,
    pub price: u64,
    pub submitted_at_ms: u64,
}

const FAST_SLAB_LEN: usize = 65_536;
const FAST_SLAB_MASK: usize = FAST_SLAB_LEN - 1;

/// Phase C3: Zero-allocation fixed-slab O(1) ClOrdID router (0 heap allocations on hot path).
pub struct FastClOrdIdRouter {
    prefix_bytes: [u8; 12],
    prefix_len: usize,
    slab: Box<[FastPodOrderSlot]>,
    pub next_wire_seq: u64,
}

impl FastClOrdIdRouter {
    pub fn new(gateway_prefix: &str) -> Self {
        let mut prefix_bytes = [0u8; 12];
        let src = gateway_prefix.as_bytes();
        let prefix_len = src.len().min(12);
        prefix_bytes[..prefix_len].copy_from_slice(&src[..prefix_len]);
        Self {
            prefix_bytes,
            prefix_len,
            slab: vec![FastPodOrderSlot::default(); FAST_SLAB_LEN].into_boxed_slice(),
            next_wire_seq: 1,
        }
    }

    /// Register outbound order in O(1) with zero heap allocations.
    #[inline(always)]
    pub fn register_outbound_fast(
        &mut self,
        pod_slot: u16,
        pod_cl_ord_id_hash: u64,
        leaves_qty: u64,
        price: u64,
        is_buy: bool,
        now_ms: u64,
    ) -> FixedWireId {
        let seq = self.next_wire_seq;
        self.next_wire_seq += 1;
        let idx = (seq as usize) & FAST_SLAB_MASK;
        unsafe {
            *self.slab.get_unchecked_mut(idx) = FastPodOrderSlot {
                wire_seq: seq,
                pod_slot,
                is_buy,
                pod_cl_ord_id_hash,
                leaves_qty,
                price,
                submitted_at_ms: now_ms,
            };
        }
        FixedWireId::format_inline(&self.prefix_bytes[..self.prefix_len], pod_slot, seq)
    }

    /// Route an execution report fill by wire sequence in O(1) (0 allocations, 0 hashing).
    #[inline(always)]
    pub fn route_inbound_fill_fast(&mut self, wire_seq: u64, fill_qty: u64) -> Option<(u16, u64, u64)> {
        let idx = (wire_seq as usize) & FAST_SLAB_MASK;
        let slot = unsafe { self.slab.get_unchecked_mut(idx) };
        if slot.wire_seq != wire_seq {
            return None;
        }
        slot.leaves_qty = slot.leaves_qty.saturating_sub(fill_qty);
        Some((slot.pod_slot, slot.pod_cl_ord_id_hash, slot.leaves_qty))
    }
}
