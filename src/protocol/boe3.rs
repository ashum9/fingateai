//! Phase D2: Zero-Copy Cboe BOE3 Binary Order Entry Codec (Little-Endian native, 0 heap allocations).

use crate::protocol::{
    fnv1a_64, NormalizedOrderEvent, ACTION_CANCEL, ACTION_NEW, ACTION_REPLACE, PROTO_BOE3,
    SIDE_BUY, SIDE_SELL,
};

pub const BOE3_START_OF_MSG: u16 = 0xBABA;
pub const BOE3_MSG_NEW_ORDER: u16 = 0x0401;
pub const BOE3_MSG_MODIFY_ORDER: u16 = 0x0402;
pub const BOE3_MSG_CANCEL_ORDER: u16 = 0x0403;

/// Cboe BOE3 16-byte fixed Little-Endian header.
#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct Boe3Header {
    pub start_of_msg: u16,    // 0..2  (0xBABA)
    pub message_length: u16,  // 2..4  (LE)
    pub message_type: u16,    // 4..6  (LE)
    pub matching_unit: u8,    // 6
    pub reserved: u8,         // 7
    pub sequence_number: u64, // 8..16 (LE)
}

const _: () = assert!(std::mem::size_of::<Boe3Header>() == 16);

/// Cboe BOE3 New Order fixed layout (56 bytes total, Little-Endian).
#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct Boe3NewOrderFrame {
    pub header: Boe3Header,       // 0..16
    pub cl_ord_id: [u8; 16],      // 16..32
    pub side: u8,                 // 32 (1=Buy, 2=Sell)
    pub _pad: [u8; 3],            // 33..36
    pub qty: u32,                 // 36..40 (LE)
    pub symbol: [u8; 8],          // 40..48
    pub price: i64,               // 48..56 (LE fixed-point)
}

const _: () = assert!(std::mem::size_of::<Boe3NewOrderFrame>() == 56);

/// Encode a Cboe BOE3 New Order directly into a 56-byte stack array (0 allocs).
#[inline(always)]
pub fn encode_boe3_new_order(
    seq: u64,
    cl_ord_id: &[u8],
    is_buy: bool,
    qty: u32,
    symbol: &[u8],
    price: i64,
    out: &mut [u8; 56],
) -> usize {
    out.fill(0);
    out[0..2].copy_from_slice(&BOE3_START_OF_MSG.to_le_bytes());
    out[2..4].copy_from_slice(&56u16.to_le_bytes());
    out[4..6].copy_from_slice(&BOE3_MSG_NEW_ORDER.to_le_bytes());
    out[8..16].copy_from_slice(&seq.to_le_bytes());
    let cid_len = cl_ord_id.len().min(16);
    out[16..16 + cid_len].copy_from_slice(&cl_ord_id[..cid_len]);
    out[32] = if is_buy { SIDE_BUY } else { SIDE_SELL };
    out[36..40].copy_from_slice(&qty.to_le_bytes());
    let sym_len = symbol.len().min(8);
    out[40..40 + sym_len].copy_from_slice(&symbol[..sym_len]);
    out[48..56].copy_from_slice(&price.to_le_bytes());
    56
}

/// Zero-copy Cboe BOE3 decoder -> 64-byte `NormalizedOrderEvent` (`< 5 ns`, 0 allocs).
#[inline(always)]
pub fn decode_boe3_zero_copy(
    raw: &[u8],
    account_slot: u16,
    pod_slot: u16,
    ingress_tsc: u64,
) -> Option<NormalizedOrderEvent> {
    if raw.len() < 16 {
        return None;
    }
    let start = u16::from_le_bytes([raw[0], raw[1]]);
    if start != BOE3_START_OF_MSG {
        return None;
    }
    let msg_type = u16::from_le_bytes([raw[4], raw[5]]);
    match msg_type {
        BOE3_MSG_NEW_ORDER if raw.len() >= 56 => {
            let cid_hash = fnv1a_64(&raw[16..32]);
            let side = if raw[32] == SIDE_SELL { SIDE_SELL } else { SIDE_BUY };
            let qty = u32::from_le_bytes([raw[36], raw[37], raw[38], raw[39]]) as u64;
            let sym_hash = fnv1a_64(&raw[40..48]);
            let price = i64::from_le_bytes([
                raw[48], raw[49], raw[50], raw[51], raw[52], raw[53], raw[54], raw[55],
            ]);
            Some(NormalizedOrderEvent {
                cl_ord_id_hash: cid_hash,
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
                protocol_id: PROTO_BOE3,
                flags: 0,
                _pad: [0; 6],
            })
        }
        BOE3_MSG_MODIFY_ORDER if raw.len() >= 56 => {
            let cid_hash = fnv1a_64(&raw[16..32]);
            let orig_hash = fnv1a_64(&raw[40..48]);
            let qty = u32::from_le_bytes([raw[36], raw[37], raw[38], raw[39]]) as u64;
            let price = i64::from_le_bytes([
                raw[48], raw[49], raw[50], raw[51], raw[52], raw[53], raw[54], raw[55],
            ]);
            Some(NormalizedOrderEvent {
                cl_ord_id_hash: cid_hash,
                orig_cl_ord_id_hash: orig_hash,
                price_ticks: price,
                qty,
                algo_id_hash: 0,
                ingress_tsc,
                account_slot,
                symbol_slot: 0,
                pod_slot,
                side: SIDE_BUY,
                action: ACTION_REPLACE,
                protocol_id: PROTO_BOE3,
                flags: 0,
                _pad: [0; 6],
            })
        }
        BOE3_MSG_CANCEL_ORDER if raw.len() >= 32 => {
            let cid_hash = fnv1a_64(&raw[16..32]);
            Some(NormalizedOrderEvent {
                cl_ord_id_hash: cid_hash,
                orig_cl_ord_id_hash: cid_hash,
                price_ticks: 0,
                qty: 0,
                algo_id_hash: 0,
                ingress_tsc,
                account_slot,
                symbol_slot: 0,
                pod_slot,
                side: SIDE_BUY,
                action: ACTION_CANCEL,
                protocol_id: PROTO_BOE3,
                flags: 0,
                _pad: [0; 6],
            })
        }
        _ => None,
    }
}
