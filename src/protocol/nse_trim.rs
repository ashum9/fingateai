//! Phase D2: Zero-Copy NSE India Trimmed NNF (`TRIM`) Binary Protocol Codec (SEBI 13-Digit AlgoID).

use crate::protocol::{
    NormalizedOrderEvent, ACTION_CANCEL, ACTION_NEW, ACTION_REPLACE, PROTO_NSE_TRIM, SIDE_BUY,
    SIDE_SELL,
};

pub const NSE_TRIM_TX_NEW_ORDER: u16 = 20000;
pub const NSE_TRIM_TX_MODIFY_ORDER: u16 = 20040;
pub const NSE_TRIM_TX_CANCEL_ORDER: u16 = 20070;

/// NSE Trimmed NNF Order Entry fixed binary layout (48 bytes, Big-Endian network byte order).
#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct NseTrimOrderFrame {
    pub transaction_code: u16, // 0..2  (20000=New, 20040=Modify, 20070=Cancel)
    pub body_len: u16,         // 2..4
    pub token_number: u32,     // 4..8  (NSE F&O / CM instrument token)
    pub buy_sell: u16,         // 8..10 (1=Buy, 2=Sell)
    pub pad: u16,              // 10..12
    pub volume: u32,           // 12..16
    pub price_paise: i64,      // 16..24 (Price in paise)
    pub order_number: u64,     // 24..32
    pub nnf_algo_id: u64,      // 32..40 (13-digit SEBI NNF / Algo ID encoded in u64)
    pub orig_order_num: u64,   // 40..48
}

const _: () = assert!(std::mem::size_of::<NseTrimOrderFrame>() == 48);

/// Encode NSE Trimmed NNF Order Entry into stack `[u8; 48]` (Big-Endian, 0 allocs).
#[inline(always)]
pub fn encode_nse_trim_order(
    tx_code: u16,
    token_number: u32,
    is_buy: bool,
    volume: u32,
    price_paise: i64,
    order_number: u64,
    nnf_algo_id: u64,
    orig_order_num: u64,
    out: &mut [u8; 48],
) -> usize {
    out[0..2].copy_from_slice(&tx_code.to_be_bytes());
    out[2..4].copy_from_slice(&48u16.to_be_bytes());
    out[4..8].copy_from_slice(&token_number.to_be_bytes());
    out[8..10].copy_from_slice(&(if is_buy { 1u16 } else { 2u16 }).to_be_bytes());
    out[10..12].copy_from_slice(&0u16.to_be_bytes());
    out[12..16].copy_from_slice(&volume.to_be_bytes());
    out[16..24].copy_from_slice(&price_paise.to_be_bytes());
    out[24..32].copy_from_slice(&order_number.to_be_bytes());
    out[32..40].copy_from_slice(&nnf_algo_id.to_be_bytes());
    out[40..48].copy_from_slice(&orig_order_num.to_be_bytes());
    48
}

/// Zero-copy NSE TRIM binary decoder -> 64-byte `NormalizedOrderEvent` (`< 5 ns`, 0 allocs).
#[inline(always)]
pub fn decode_nse_trim_zero_copy(
    raw: &[u8],
    account_slot: u16,
    pod_slot: u16,
    ingress_tsc: u64,
) -> Option<NormalizedOrderEvent> {
    if raw.len() < 48 {
        return None;
    }
    let tx_code = u16::from_be_bytes([raw[0], raw[1]]);
    let action = match tx_code {
        NSE_TRIM_TX_NEW_ORDER => ACTION_NEW,
        NSE_TRIM_TX_MODIFY_ORDER => ACTION_REPLACE,
        NSE_TRIM_TX_CANCEL_ORDER => ACTION_CANCEL,
        _ => return None,
    };
    let token = u32::from_be_bytes([raw[4], raw[5], raw[6], raw[7]]);
    let side_raw = u16::from_be_bytes([raw[8], raw[9]]);
    let side = if side_raw == 2 { SIDE_SELL } else { SIDE_BUY };
    let qty = u32::from_be_bytes([raw[12], raw[13], raw[14], raw[15]]) as u64;
    let price_paise = i64::from_be_bytes([
        raw[16], raw[17], raw[18], raw[19], raw[20], raw[21], raw[22], raw[23],
    ]);
    let order_num = u64::from_be_bytes([
        raw[24], raw[25], raw[26], raw[27], raw[28], raw[29], raw[30], raw[31],
    ]);
    let nnf_algo_id = u64::from_be_bytes([
        raw[32], raw[33], raw[34], raw[35], raw[36], raw[37], raw[38], raw[39],
    ]);
    let orig_order_num = u64::from_be_bytes([
        raw[40], raw[41], raw[42], raw[43], raw[44], raw[45], raw[46], raw[47],
    ]);

    Some(NormalizedOrderEvent {
        cl_ord_id_hash: order_num,
        orig_cl_ord_id_hash: orig_order_num,
        price_ticks: price_paise,
        qty,
        algo_id_hash: nnf_algo_id,
        ingress_tsc,
        account_slot,
        symbol_slot: (token & 0x03FF) as u16,
        pod_slot,
        side,
        action,
        protocol_id: PROTO_NSE_TRIM,
        flags: 0,
        _pad: [0; 6],
    })
}
