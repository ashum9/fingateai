//! Phase D2: Zero-Allocation Byte-Slice JSON Order Scanner (`fingate::protocol::fast_json`).
//!
//! Extracts flat REST/WebSocket/MCP trading JSON orders directly into a 64-byte
//! `NormalizedOrderEvent` without allocating `serde_json::Value` AST maps or `String`s.

use crate::protocol::{
    fnv1a_64, NormalizedOrderEvent, ACTION_CANCEL, ACTION_NEW, ACTION_REPLACE, PROTO_FAST_JSON,
    SIDE_BUY, SIDE_SELL,
};

/// Zero-allocation scanner over flat JSON order payload:
/// e.g. `{"cl_ord_id":"BOT-1","symbol":"BTCUSDT","side":"BUY","price":95000,"qty":5,"algo_id":"ALGO-1"}`
#[inline]
pub fn decode_fast_json_zero_copy(
    raw: &[u8],
    account_slot: u16,
    pod_slot: u16,
    ingress_tsc: u64,
) -> Option<NormalizedOrderEvent> {
    let mut ev = NormalizedOrderEvent {
        cl_ord_id_hash: 0,
        orig_cl_ord_id_hash: 0,
        price_ticks: 0,
        qty: 0,
        algo_id_hash: 0,
        ingress_tsc,
        account_slot,
        symbol_slot: 1,
        pod_slot,
        side: SIDE_BUY,
        action: ACTION_NEW,
        protocol_id: PROTO_FAST_JSON,
        flags: 0,
        _pad: [0; 6],
    };

    let len = raw.len();
    let mut i = 0usize;
    let mut saw_qty_or_cancel = false;

    while i < len {
        // Find next quoted key `"..."`
        while i < len && raw[i] != b'"' {
            i += 1;
        }
        if i >= len {
            break;
        }
        let key_start = i + 1;
        i = key_start;
        while i < len && raw[i] != b'"' {
            i += 1;
        }
        if i >= len {
            break;
        }
        let key = &raw[key_start..i];
        i += 1;

        // Advance past ':' and whitespace
        while i < len && (raw[i] == b':' || raw[i] == b' ' || raw[i] == b'\t' || raw[i] == b'\n' || raw[i] == b'\r') {
            i += 1;
        }
        if i >= len {
            break;
        }

        // Parse string or numeric value zero-copy
        if raw[i] == b'"' {
            let val_start = i + 1;
            i = val_start;
            while i < len && raw[i] != b'"' {
                i += 1;
            }
            if i >= len {
                break;
            }
            let val = &raw[val_start..i];
            i += 1;

            match key {
                b"cl_ord_id" | b"clientOrderId" => ev.cl_ord_id_hash = fnv1a_64(val),
                b"orig_cl_ord_id" => ev.orig_cl_ord_id_hash = fnv1a_64(val),
                b"symbol" => ev.symbol_slot = (fnv1a_64(val) & 0x03FF) as u16,
                b"algo_id" => ev.algo_id_hash = fnv1a_64(val),
                b"side" => {
                    ev.side = if val == b"SELL" || val == b"sell" || val == b"2" {
                        SIDE_SELL
                    } else {
                        SIDE_BUY
                    };
                }
                b"action" => {
                    ev.action = match val {
                        b"REPLACE" | b"replace" | b"AMEND" => ACTION_REPLACE,
                        b"CANCEL" | b"cancel" => {
                            saw_qty_or_cancel = true;
                            ACTION_CANCEL
                        }
                        _ => ACTION_NEW,
                    };
                }
                _ => {}
            }
        } else {
            let num_start = i;
            let neg = raw[i] == b'-';
            if neg {
                i += 1;
            }
            let mut acc: u64 = 0;
            while i < len && raw[i].is_ascii_digit() {
                acc = acc.wrapping_mul(10).wrapping_add((raw[i] - b'0') as u64);
                i += 1;
            }
            // Skip any trailing decimal fraction / non-delimiter
            while i < len && raw[i] != b',' && raw[i] != b'}' {
                i += 1;
            }
            if i > num_start {
                match key {
                    b"price" => ev.price_ticks = if neg { -(acc as i64) } else { acc as i64 },
                    b"qty" | b"quantity" => {
                        ev.qty = acc;
                        saw_qty_or_cancel = true;
                    }
                    b"symbol_id" => ev.symbol_slot = acc as u16,
                    _ => {}
                }
            }
        }
    }

    if ev.cl_ord_id_hash == 0 || !saw_qty_or_cancel {
        return None;
    }
    Some(ev)
}
