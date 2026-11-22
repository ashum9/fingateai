//! Phase D2: Multi-Protocol Zero-Copy Codec Suite & 64-Byte `NormalizedOrderEvent` (`fingate::protocol`).
//!
//! Normalizes 6 exchange & ingress protocols with ZERO heap allocations into one
//! single cache-line (64-byte) `NormalizedOrderEvent`:
//! - `ouch5`: Nasdaq OUCH 5.0 (Big-Endian binary)
//! - `boe3`: Cboe BOE3 (Little-Endian binary)
//! - `sbe_ilink3`: CME iLink 3 SBE (Little-Endian templates 514/515/516/527)
//! - `nse_trim`: NSE India Trimmed NNF binary protocol (13-digit AlgoID)
//! - `fast_json`: Zero-allocation byte-slice JSON scanner for REST/WS/AI bots
//! - `FIX 4.4 / 5.0`: via `crate::fix::wire::FixWireView` (including repeating groups)

pub mod boe3;
pub mod fast_json;
pub mod nse_trim;
pub mod ouch5;
pub mod sbe_ilink3;

pub const PROTO_FIX44: u8 = 1;
pub const PROTO_SBE_ILINK3: u8 = 2;
pub const PROTO_OUCH5: u8 = 3;
pub const PROTO_BOE3: u8 = 4;
pub const PROTO_NSE_TRIM: u8 = 5;
pub const PROTO_FAST_JSON: u8 = 6;

pub const SIDE_BUY: u8 = 1;
pub const SIDE_SELL: u8 = 2;

pub const ACTION_NEW: u8 = 0;
pub const ACTION_REPLACE: u8 = 1;
pub const ACTION_CANCEL: u8 = 2;
pub const ACTION_MASS_CANCEL: u8 = 3;

/// Canonical 64-byte (exact 1 cache line) internal order representation shared across
/// all protocols, SHM IPC, C-ABI FFI, Risk Engine, Portfolio Greeks, Order FSM, and DPU.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(C, align(64))]
pub struct NormalizedOrderEvent {
    pub cl_ord_id_hash: u64,      // 0..8
    pub orig_cl_ord_id_hash: u64, // 8..16 (for 35=G Replace / 35=F Cancel linkage)
    pub price_ticks: i64,         // 16..24 (fixed-point integer ticks; never f64)
    pub qty: u64,                 // 24..32
    pub algo_id_hash: u64,        // 32..40 (SEBI Tag 1001 / MiFID AlgoID)
    pub ingress_tsc: u64,         // 40..48
    pub account_slot: u16,        // 48..50
    pub symbol_slot: u16,         // 50..52
    pub pod_slot: u16,            // 52..54
    pub side: u8,                 // 54 (1=Buy, 2=Sell)
    pub action: u8,               // 55 (0=New, 1=Replace, 2=Cancel, 3=MassCancel)
    pub protocol_id: u8,          // 56
    pub flags: u8,                // 57 (bit0=PostOnly, bit1=IOC, bit2=FOK, bit3=PossDup)
    pub _pad: [u8; 6],            // 58..64
}

const _: () = assert!(std::mem::size_of::<NormalizedOrderEvent>() == 64);

/// Fast zero-allocation FNV-1a 64-bit hash for stack byte slices (`ClOrdID`, `Symbol`, `ExecID`, `AlgoID`).
#[inline(always)]
pub const fn fnv1a_64(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    let mut i = 0;
    while i < bytes.len() {
        h ^= bytes[i] as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
        i += 1;
    }
    h
}

/// Convert a validated `FixWireView` into a 64-byte `NormalizedOrderEvent` with 0 heap allocations.
#[inline]
pub fn normalize_fix_view(
    view: &crate::fix::wire::FixWireView<'_>,
    account_slot: u16,
    pod_slot: u16,
    symbol_slot: u16,
    ingress_tsc: u64,
) -> Option<NormalizedOrderEvent> {
    let action = match view.msg_type()? {
        "D" => ACTION_NEW,
        "G" => ACTION_REPLACE,
        "F" => ACTION_CANCEL,
        "q" => ACTION_MASS_CANCEL,
        _ => return None,
    };
    let cl_ord_id_hash = view
        .get_str(11)
        .map(|s| fnv1a_64(s.as_bytes()))
        .unwrap_or_else(|| view.msg_seq_num().unwrap_or(0));
    let orig_cl_ord_id_hash = view
        .get_str(41)
        .map(|s| fnv1a_64(s.as_bytes()))
        .unwrap_or(0);
    let side = match view.get_str(54) {
        Some("2") => SIDE_SELL,
        _ => SIDE_BUY,
    };
    let qty = view.get_u64(38).unwrap_or(0);
    let price_ticks = view.get_u64(44).unwrap_or(0) as i64;
    let algo_id_hash = view
        .get_str(1001)
        .map(|s| fnv1a_64(s.as_bytes()))
        .unwrap_or(0);
    let flags = if view.get_bool(43) == Some(true) { 0x08 } else { 0 };

    Some(NormalizedOrderEvent {
        cl_ord_id_hash,
        orig_cl_ord_id_hash,
        price_ticks,
        qty,
        algo_id_hash,
        ingress_tsc,
        account_slot,
        symbol_slot,
        pod_slot,
        side,
        action,
        protocol_id: PROTO_FIX44,
        flags,
        _pad: [0; 6],
    })
}
