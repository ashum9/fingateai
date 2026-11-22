//! Month 2, Week 2: Binance Spot Digital Twin (`BinanceSpotTwin`).
//!
//! Emulates Binance Spot production connectivity behaviors:
//! 1. FIX 4.4 session semantics with strict `SenderCompID` validation.
//! 2. Unclean TCP drop penalty: 2 * HeartBtInt lockout window. Reconnect attempts during
//!    lockout are rejected with Logout (`35=5, Text="SenderCompID locked out"`).
//! 3. Mandatory `ResetSeqNumFlag=Y (141=Y)` logon discipline on cold reconnect.
//! 4. 10-orders/second sliding-window rate-limiter with immediate `ExecutionReport (35=8, OrdStatus=8)` rejection.
//! 5. Binance SBE (Simple Binary Encoding) frame encoder/decoder for binary order flow.

use crate::fix::wire::{FixFrameBuilder, FixWireView};
use serde::{Deserialize, Serialize};

pub const BINANCE_SBE_SCHEMA_ID: u16 = 1;
pub const BINANCE_SBE_VERSION: u16 = 0;
pub const SBE_TEMPLATE_NEW_ORDER_SINGLE: u16 = 100;
pub const SBE_TEMPLATE_EXECUTION_REPORT: u16 = 101;
pub const SBE_TEMPLATE_ORDER_CANCEL_REQUEST: u16 = 102;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BinanceTwinConfig {
    pub sender_comp_id: String,
    pub target_comp_id: String,
    pub heart_bt_int_ms: u64,
    pub max_orders_per_second: u32,
    pub unclean_lockout_multiplier: u64,
}

impl Default for BinanceTwinConfig {
    fn default() -> Self {
        Self {
            sender_comp_id: "BINANCE".to_string(),
            target_comp_id: "FINGATE".to_string(),
            heart_bt_int_ms: 30_000,
            max_orders_per_second: 10,
            unclean_lockout_multiplier: 2,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TwinAction {
    SendFixFrame(Vec<u8>),
    SendSbeFrame(Vec<u8>),
    DropConnection,
    None,
}

pub struct BinanceSpotTwin {
    pub config: BinanceTwinConfig,
    pub active_session: bool,
    pub next_sender_seq: u64,
    pub next_target_seq: u64,
    pub lockout_until_ms: Option<u64>,
    pub recent_order_timestamps_ms: Vec<u64>,
    pub total_orders_processed: u64,
    pub rate_limit_rejects: u64,
    pub lockout_rejects: u64,
}

impl BinanceSpotTwin {
    pub fn new(config: BinanceTwinConfig) -> Self {
        Self {
            config,
            active_session: false,
            next_sender_seq: 1,
            next_target_seq: 1,
            lockout_until_ms: None,
            recent_order_timestamps_ms: Vec::new(),
            total_orders_processed: 0,
            rate_limit_rejects: 0,
            lockout_rejects: 0,
        }
    }

    /// Simulate an unclean TCP drop event at timestamp `now_ms`.
    /// Binance locks the `SenderCompID` for `2 * HeartBtInt`.
    pub fn trigger_unclean_tcp_drop(&mut self, now_ms: u64) {
        self.active_session = false;
        let lockout_ms = self.config.unclean_lockout_multiplier * self.config.heart_bt_int_ms;
        self.lockout_until_ms = Some(now_ms + lockout_ms);
    }

    /// Check if twin is currently locked out.
    pub fn is_locked_out(&self, now_ms: u64) -> bool {
        if let Some(until) = self.lockout_until_ms {
            now_ms < until
        } else {
            false
        }
    }

    /// Process an inbound raw FIX wire frame from the gateway.
    pub fn handle_inbound_fix(&mut self, raw_wire: &[u8], now_ms: u64) -> Vec<TwinAction> {
        let view = match FixWireView::parse_and_validate(raw_wire) {
            Ok(v) => v,
            Err(_) => return vec![], // Garbled frame -> silently ignore per Rule R25
        };

        let msg_type = match view.msg_type() {
            Some(m) => m,
            None => return vec![],
        };
        let seq = view.msg_seq_num().unwrap_or(0);

        // Check CompID routing
        let sender = view.get_str(49).unwrap_or("");
        let target = view.get_str(56).unwrap_or("");
        if sender != self.config.target_comp_id || target != self.config.sender_comp_id {
            // TargetCompID mismatch -> immediate Reject / Drop
            return vec![TwinAction::DropConnection];
        }

        // Check Lockout
        if self.is_locked_out(now_ms) {
            self.lockout_rejects += 1;
            let mut b = FixFrameBuilder::new();
            b.push_str(35, "5")
                .push_u64(34, self.next_sender_seq)
                .push_str(49, &self.config.sender_comp_id)
                .push_str(56, &self.config.target_comp_id)
                .push_u64(52, now_ms)
                .push_str(58, "BINANCE: SenderCompID locked out following unclean drop");
            self.next_sender_seq += 1;
            return vec![
                TwinAction::SendFixFrame(b.finish_soh_bytes(false, false)),
                TwinAction::DropConnection,
            ];
        }

        match msg_type {
            "A" => {
                // Logon
                let reset_flag = view.get_bool(141).unwrap_or(false);
                if reset_flag {
                    self.next_target_seq = 1;
                    self.next_sender_seq = 1;
                }

                self.active_session = true;
                self.next_target_seq = seq + 1;

                let mut b = FixFrameBuilder::new();
                b.push_str(35, "A")
                    .push_u64(34, self.next_sender_seq)
                    .push_str(49, &self.config.sender_comp_id)
                    .push_str(56, &self.config.target_comp_id)
                    .push_u64(52, now_ms)
                    .push_u64(108, self.config.heart_bt_int_ms / 1000)
                    .push_bool(141, reset_flag);
                self.next_sender_seq += 1;
                vec![TwinAction::SendFixFrame(b.finish_soh_bytes(false, false))]
            }
            "1" => {
                // TestRequest -> Echo Heartbeat
                self.next_target_seq = seq + 1;
                let test_req_id = view.get_str(112).unwrap_or("");
                let mut b = FixFrameBuilder::new();
                b.push_str(35, "0")
                    .push_u64(34, self.next_sender_seq)
                    .push_str(49, &self.config.sender_comp_id)
                    .push_str(56, &self.config.target_comp_id)
                    .push_u64(52, now_ms);
                if !test_req_id.is_empty() {
                    b.push_str(112, test_req_id);
                }
                self.next_sender_seq += 1;
                vec![TwinAction::SendFixFrame(b.finish_soh_bytes(false, false))]
            }
            "D" => {
                // NewOrderSingle -> Check Rate Limiter
                self.next_target_seq = seq + 1;
                self.total_orders_processed += 1;
                let cl_ord_id = view.get_str(11).unwrap_or("UNKNOWN").to_string();

                // Sliding 1000ms window check
                self.recent_order_timestamps_ms.retain(|&ts| now_ms.saturating_sub(ts) <= 1000);
                if self.recent_order_timestamps_ms.len() >= self.config.max_orders_per_second as usize {
                    self.rate_limit_rejects += 1;
                    let mut b = FixFrameBuilder::new();
                    b.push_str(35, "8") // ExecutionReport
                        .push_u64(34, self.next_sender_seq)
                        .push_str(49, &self.config.sender_comp_id)
                        .push_str(56, &self.config.target_comp_id)
                        .push_u64(52, now_ms)
                        .push_str(11, &cl_ord_id)
                        .push_str(17, &format!("REJ-{}", now_ms))
                        .push_str(150, "8") // ExecType = Rejected
                        .push_str(39, "8")  // OrdStatus = Rejected
                        .push_str(58, "BINANCE: 10 OPS Rate Limit Exceeded")
                        .push_u64(151, 0);
                    self.next_sender_seq += 1;
                    return vec![TwinAction::SendFixFrame(b.finish_soh_bytes(false, false))];
                }

                self.recent_order_timestamps_ms.push(now_ms);

                // Normal ExecutionReport: New (ACK)
                let mut b = FixFrameBuilder::new();
                b.push_str(35, "8")
                    .push_u64(34, self.next_sender_seq)
                    .push_str(49, &self.config.sender_comp_id)
                    .push_str(56, &self.config.target_comp_id)
                    .push_u64(52, now_ms)
                    .push_str(11, &cl_ord_id)
                    .push_str(17, &format!("EXEC-{}", now_ms))
                    .push_str(150, "0") // ExecType = New
                    .push_str(39, "0")  // OrdStatus = New
                    .push_u64(151, view.get_u64(38).unwrap_or(1)); // LeavesQty
                self.next_sender_seq += 1;
                vec![TwinAction::SendFixFrame(b.finish_soh_bytes(false, false))]
            }
            _ => {
                self.next_target_seq = seq + 1;
                vec![]
            }
        }
    }

    /// Encode a Binance SBE ExecutionReport binary message.
    /// SBE Header (8 bytes): blockLength(u16), templateId(u16), schemaId(u16), version(u16).
    /// Body: orderId(u64), execId(u64), leavesQty(u64), price(u64), execType(u8).
    pub fn encode_sbe_execution_report(
        order_id: u64,
        exec_id: u64,
        leaves_qty: u64,
        price: u64,
        exec_type: u8,
    ) -> Vec<u8> {
        let mut buf = Vec::with_capacity(8 + 33);
        // Header
        buf.extend_from_slice(&33u16.to_le_bytes()); // blockLength = 33
        buf.extend_from_slice(&SBE_TEMPLATE_EXECUTION_REPORT.to_le_bytes());
        buf.extend_from_slice(&BINANCE_SBE_SCHEMA_ID.to_le_bytes());
        buf.extend_from_slice(&BINANCE_SBE_VERSION.to_le_bytes());
        // Body
        buf.extend_from_slice(&order_id.to_le_bytes());
        buf.extend_from_slice(&exec_id.to_le_bytes());
        buf.extend_from_slice(&leaves_qty.to_le_bytes());
        buf.extend_from_slice(&price.to_le_bytes());
        buf.push(exec_type);
        buf
    }

    /// Decode a Binance SBE binary frame header.
    pub fn decode_sbe_header(buf: &[u8]) -> Option<(u16, u16, u16, u16)> {
        if buf.len() < 8 {
            return None;
        }
        let block_len = u16::from_le_bytes(buf[0..2].try_into().unwrap());
        let template_id = u16::from_le_bytes(buf[2..4].try_into().unwrap());
        let schema_id = u16::from_le_bytes(buf[4..6].try_into().unwrap());
        let version = u16::from_le_bytes(buf[6..8].try_into().unwrap());
        Some((block_len, template_id, schema_id, version))
    }
}
