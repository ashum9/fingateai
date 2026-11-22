//! Phase D2: Zero-Copy CME iLink 3 SBE Binary Order Entry Codec (Templates 514/515/516, 0 allocs).

use crate::fix::wire::SbeWireView;
use crate::protocol::{
    NormalizedOrderEvent, ACTION_CANCEL, ACTION_NEW, ACTION_REPLACE, PROTO_SBE_ILINK3, SIDE_BUY,
    SIDE_SELL,
};

pub const ILINK3_TEMPLATE_NEW_ORDER: u16 = 514;
pub const ILINK3_TEMPLATE_CANCEL_REPLACE: u16 = 515;
pub const ILINK3_TEMPLATE_CANCEL: u16 = 516;
pub const ILINK3_SCHEMA_ID: u16 = 8;

/// Encode a 40-byte CME iLink 3 SBE NewOrderSingle (Template 514) into a stack buffer.
/// Body layout (32 bytes): `price(8B i64) | qty(4B u32) | security_id(4B u32) | side(1B) | pad(7B) | party_order_id(8B u64)`.
#[inline(always)]
pub fn encode_ilink3_new_order(
    party_order_id: u64,
    security_id: u32,
    is_buy: bool,
    qty: u32,
    price: i64,
    out: &mut [u8; 40],
) -> usize {
    out[0..2].copy_from_slice(&32u16.to_le_bytes()); // block_length
    out[2..4].copy_from_slice(&ILINK3_TEMPLATE_NEW_ORDER.to_le_bytes());
    out[4..6].copy_from_slice(&ILINK3_SCHEMA_ID.to_le_bytes());
    out[6..8].copy_from_slice(&9u16.to_le_bytes()); // version
    out[8..16].copy_from_slice(&price.to_le_bytes());
    out[16..20].copy_from_slice(&qty.to_le_bytes());
    out[20..24].copy_from_slice(&security_id.to_le_bytes());
    out[24] = if is_buy { SIDE_BUY } else { SIDE_SELL };
    out[25..32].fill(0);
    out[32..40].copy_from_slice(&party_order_id.to_le_bytes());
    40
}

/// Zero-copy CME iLink 3 SBE decoder -> 64-byte `NormalizedOrderEvent` (`< 5 ns`, 0 allocs).
#[inline(always)]
pub fn decode_ilink3_zero_copy(
    raw: &[u8],
    account_slot: u16,
    pod_slot: u16,
    ingress_tsc: u64,
) -> Option<NormalizedOrderEvent> {
    let view = SbeWireView::parse(raw)?;
    if view.body.len() < 32 {
        return None;
    }
    let price = view.read_i64_le(0)?;
    let qty = u32::from_le_bytes([view.body[8], view.body[9], view.body[10], view.body[11]]) as u64;
    let security_id =
        u32::from_le_bytes([view.body[12], view.body[13], view.body[14], view.body[15]]);
    let side = if view.body[16] == SIDE_SELL { SIDE_SELL } else { SIDE_BUY };
    let party_order_id = view.read_u64_le(24)?;

    let action = match view.template_id {
        ILINK3_TEMPLATE_NEW_ORDER => ACTION_NEW,
        ILINK3_TEMPLATE_CANCEL_REPLACE => ACTION_REPLACE,
        ILINK3_TEMPLATE_CANCEL => ACTION_CANCEL,
        _ => return None,
    };

    Some(NormalizedOrderEvent {
        cl_ord_id_hash: party_order_id,
        orig_cl_ord_id_hash: if action == ACTION_NEW { 0 } else { party_order_id },
        price_ticks: price,
        qty,
        algo_id_hash: 0,
        ingress_tsc,
        account_slot,
        symbol_slot: (security_id & 0x03FF) as u16,
        pod_slot,
        side,
        action,
        protocol_id: PROTO_SBE_ILINK3,
        flags: 0,
        _pad: [0; 6],
    })
}
