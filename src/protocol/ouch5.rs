//! Phase D2: Zero-Copy Nasdaq OUCH 5.0 Binary Order Entry Codec (Big-Endian, 0 heap allocations).

use crate::protocol::{
    fnv1a_64, NormalizedOrderEvent, ACTION_CANCEL, ACTION_NEW, ACTION_REPLACE, PROTO_OUCH5,
    SIDE_BUY, SIDE_SELL,
};

pub const OUCH5_ENTER_ORDER_TYPE: u8 = b'O';
pub const OUCH5_REPLACE_ORDER_TYPE: u8 = b'U';
pub const OUCH5_CANCEL_ORDER_TYPE: u8 = b'X';

/// Nasdaq OUCH 5.0 Enter Order fixed core (Big-Endian, 32 bytes).
#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct Ouch5EnterOrderLayout {
    pub msg_type: u8,      // 0: 'O'
    pub user_ref_num: u32, // 1..5 (BE)
    pub side: u8,          // 5: 'B' or 'S'
    pub qty: u32,          // 6..10 (BE)
    pub symbol: [u8; 8],   // 10..18 (space-padded ASCII)
    pub price: u64,        // 18..26 (BE fixed-point 1e-4)
    pub tif: u32,          // 26..30 (BE)
    pub flags: u16,        // 30..32 (BE)
}

const _: () = assert!(std::mem::size_of::<Ouch5EnterOrderLayout>() == 32);

/// Nasdaq OUCH 5.0 Replace Order fixed core (Big-Endian, 25 bytes).
#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct Ouch5ReplaceOrderLayout {
    pub msg_type: u8,          // 0: 'U'
    pub orig_user_ref: u32,    // 1..5 (BE)
    pub repl_user_ref: u32,    // 5..9 (BE)
    pub qty: u32,              // 9..13 (BE)
    pub price: u64,            // 13..21 (BE)
    pub tif: u32,              // 21..25 (BE)
}

const _: () = assert!(std::mem::size_of::<Ouch5ReplaceOrderLayout>() == 25);

/// Nasdaq OUCH 5.0 Cancel Order fixed core (Big-Endian, 9 bytes).
#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct Ouch5CancelOrderLayout {
    pub msg_type: u8,      // 0: 'X'
    pub user_ref_num: u32, // 1..5 (BE)
    pub qty: u32,          // 5..9 (BE)
}

const _: () = assert!(std::mem::size_of::<Ouch5CancelOrderLayout>() == 9);

/// Encode OUCH 5.0 Enter Order directly into stack `[u8; 32]` (Big-Endian).
#[inline(always)]
pub fn encode_ouch5_enter(
    user_ref_num: u32,
    is_buy: bool,
    qty: u32,
    symbol: &[u8],
    price: u64,
    out: &mut [u8; 32],
) -> usize {
    out[0] = OUCH5_ENTER_ORDER_TYPE;
    out[1..5].copy_from_slice(&user_ref_num.to_be_bytes());
    out[5] = if is_buy { b'B' } else { b'S' };
    out[6..10].copy_from_slice(&qty.to_be_bytes());
    out[10..18].fill(b' ');
    let slen = symbol.len().min(8);
    out[10..10 + slen].copy_from_slice(&symbol[..slen]);
    out[18..26].copy_from_slice(&price.to_be_bytes());
    out[26..30].copy_from_slice(&0u32.to_be_bytes());
    out[30..32].copy_from_slice(&0u16.to_be_bytes());
    32
}

/// Encode OUCH 5.0 Replace Order directly into stack `[u8; 25]` (Big-Endian).
#[inline(always)]
pub fn encode_ouch5_replace(
    orig_user_ref: u32,
    repl_user_ref: u32,
    qty: u32,
    price: u64,
    out: &mut [u8; 25],
) -> usize {
    out[0] = OUCH5_REPLACE_ORDER_TYPE;
    out[1..5].copy_from_slice(&orig_user_ref.to_be_bytes());
    out[5..9].copy_from_slice(&repl_user_ref.to_be_bytes());
    out[9..13].copy_from_slice(&qty.to_be_bytes());
    out[13..21].copy_from_slice(&price.to_be_bytes());
    out[21..25].copy_from_slice(&0u32.to_be_bytes());
    25
}

/// Zero-copy Nasdaq OUCH 5.0 decoder -> 64-byte `NormalizedOrderEvent` (`< 5 ns`, 0 allocs).
#[inline(always)]
pub fn decode_ouch5_zero_copy(
    raw: &[u8],
    account_slot: u16,
    pod_slot: u16,
    ingress_tsc: u64,
) -> Option<NormalizedOrderEvent> {
    if raw.is_empty() {
        return None;
    }
    match raw[0] {
        OUCH5_ENTER_ORDER_TYPE if raw.len() >= 32 => {
            let user_ref = u32::from_be_bytes([raw[1], raw[2], raw[3], raw[4]]) as u64;
            let side = if raw[5] == b'S' { SIDE_SELL } else { SIDE_BUY };
            let qty = u32::from_be_bytes([raw[6], raw[7], raw[8], raw[9]]) as u64;
            let sym_hash = fnv1a_64(&raw[10..18]);
            let price = u64::from_be_bytes([
                raw[18], raw[19], raw[20], raw[21], raw[22], raw[23], raw[24], raw[25],
            ]) as i64;
            Some(NormalizedOrderEvent {
                cl_ord_id_hash: user_ref,
                orig_cl_ord_id_hash: 0,
                price_ticks: price,
                qty,
                algo_id_hash: 0,
                ingress_tsc,
                account_slot,
                symbol_slot: (sym_hash & 0x03FF) as u16,
                pod_slot,
                side,
                action: ACTION_NEW,
                protocol_id: PROTO_OUCH5,
                flags: 0,
                _pad: [0; 6],
            })
        }
        OUCH5_REPLACE_ORDER_TYPE if raw.len() >= 25 => {
            let orig_ref = u32::from_be_bytes([raw[1], raw[2], raw[3], raw[4]]) as u64;
            let repl_ref = u32::from_be_bytes([raw[5], raw[6], raw[7], raw[8]]) as u64;
            let qty = u32::from_be_bytes([raw[9], raw[10], raw[11], raw[12]]) as u64;
            let price = u64::from_be_bytes([
                raw[13], raw[14], raw[15], raw[16], raw[17], raw[18], raw[19], raw[20],
            ]) as i64;
            Some(NormalizedOrderEvent {
                cl_ord_id_hash: repl_ref,
                orig_cl_ord_id_hash: orig_ref,
                price_ticks: price,
                qty,
                algo_id_hash: 0,
                ingress_tsc,
                account_slot,
                symbol_slot: 0,
                pod_slot,
                side: SIDE_BUY,
                action: ACTION_REPLACE,
                protocol_id: PROTO_OUCH5,
                flags: 0,
                _pad: [0; 6],
            })
        }
        OUCH5_CANCEL_ORDER_TYPE if raw.len() >= 9 => {
            let user_ref = u32::from_be_bytes([raw[1], raw[2], raw[3], raw[4]]) as u64;
            let qty = u32::from_be_bytes([raw[5], raw[6], raw[7], raw[8]]) as u64;
            Some(NormalizedOrderEvent {
                cl_ord_id_hash: user_ref,
                orig_cl_ord_id_hash: user_ref,
                price_ticks: 0,
                qty,
                algo_id_hash: 0,
                ingress_tsc,
                account_slot,
                symbol_slot: 0,
                pod_slot,
                side: SIDE_BUY,
                action: ACTION_CANCEL,
                protocol_id: PROTO_OUCH5,
                flags: 0,
                _pad: [0; 6],
            })
        }
        _ => None,
    }
}
