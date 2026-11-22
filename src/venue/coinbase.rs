//! Month 2, Week 2: Coinbase International Digital Twin (`CoinbaseTwin`).
//!
//! Emulates Coinbase FIX 5.0 SP2 (`FIXT.1.1`) institutional connectivity:
//! 1. `FIXT.1.1` transport header with `ApplVerID=9 (1128=9)` session negotiation.
//! 2. Dual-session architecture: Order Entry (`OE`) + Drop-Copy (`DC`) stream multiplexing.
//! 3. Exchange-level Cancel-on-Disconnect (COD): If silence exceeds `HeartBtInt + Grace`,
//!    all active working orders for the session are automatically cancelled.
//! 4. Drop-Copy sequence decoupling: Order Entry and Drop-Copy maintain separate,
//!    non-interfering sequence numbers.

use crate::fix::wire::{FixFrameBuilder, FixWireView};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoinbaseTwinConfig {
    pub sender_comp_id: String,
    pub target_comp_id: String,
    pub heart_bt_int_ms: u64,
    pub cod_grace_ms: u64,
}

impl Default for CoinbaseTwinConfig {
    fn default() -> Self {
        Self {
            sender_comp_id: "COINBASE".to_string(),
            target_comp_id: "FINGATE".to_string(),
            heart_bt_int_ms: 30_000,
            cod_grace_ms: 2_000,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoinbaseWorkingOrder {
    pub cl_ord_id: String,
    pub order_id: String,
    pub symbol: String,
    pub leaves_qty: u64,
    pub price: u64,
}

pub struct CoinbaseTwin {
    pub config: CoinbaseTwinConfig,
    pub oe_active: bool,
    pub oe_next_sender_seq: u64,
    pub oe_next_target_seq: u64,
    pub dc_active: bool,
    pub dc_next_sender_seq: u64,
    pub last_recv_time_ms: u64,
    pub working_orders: HashMap<String, CoinbaseWorkingOrder>,
    pub cod_triggered: bool,
    pub total_cod_cancels: u64,
}

impl CoinbaseTwin {
    pub fn new(config: CoinbaseTwinConfig) -> Self {
        Self {
            config,
            oe_active: false,
            oe_next_sender_seq: 1,
            oe_next_target_seq: 1,
            dc_active: false,
            dc_next_sender_seq: 1,
            last_recv_time_ms: 0,
            working_orders: HashMap::new(),
            cod_triggered: false,
            total_cod_cancels: 0,
        }
    }

    /// Process incoming FIX 5.0 SP2 message on the Order Entry (OE) connection.
    /// Returns (OE responses, Drop-Copy stream messages).
    pub fn handle_inbound_oe(&mut self, raw_wire: &[u8], now_ms: u64) -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
        let view = match FixWireView::parse_and_validate(raw_wire) {
            Ok(v) => v,
            Err(_) => return (vec![], vec![]),
        };

        let msg_type = match view.msg_type() {
            Some(m) => m,
            None => return (vec![], vec![]),
        };
        let seq = view.msg_seq_num().unwrap_or(0);

        self.last_recv_time_ms = now_ms;
        self.oe_next_target_seq = seq + 1;

        let mut oe_responses = Vec::new();
        let mut dc_messages = Vec::new();

        match msg_type {
            "A" => {
                // FIXT.1.1 Logon with ApplVerID=9
                self.oe_active = true;
                let mut b = FixFrameBuilder::new();
                b.push_str(35, "A")
                    .push_u64(34, self.oe_next_sender_seq)
                    .push_str(49, &self.config.sender_comp_id)
                    .push_str(56, &self.config.target_comp_id)
                    .push_u64(52, now_ms)
                    .push_u64(108, self.config.heart_bt_int_ms / 1000)
                    .push_str(1128, "9"); // ApplVerID = FIX50SP2
                self.oe_next_sender_seq += 1;
                oe_responses.push(b.finish_soh_bytes(false, false));
            }
            "D" => {
                // NewOrderSingle -> Acknowledge and replicate to Drop-Copy
                let cl_ord_id = view.get_str(11).unwrap_or("ORD-UNKNOWN").to_string();
                let order_id = format!("CB-{}", now_ms);
                let leaves_qty = view.get_u64(38).unwrap_or(1);
                let symbol = view.get_str(55).unwrap_or("BTC-USD").to_string();
                let price = view.get_u64(44).unwrap_or(0);

                self.working_orders.insert(
                    cl_ord_id.clone(),
                    CoinbaseWorkingOrder {
                        cl_ord_id: cl_ord_id.clone(),
                        order_id: order_id.clone(),
                        symbol: symbol.clone(),
                        leaves_qty,
                        price,
                    },
                );

                // 1. OE ExecutionReport
                let mut oe_rep = FixFrameBuilder::new();
                oe_rep
                    .push_str(35, "8")
                    .push_u64(34, self.oe_next_sender_seq)
                    .push_str(49, &self.config.sender_comp_id)
                    .push_str(56, &self.config.target_comp_id)
                    .push_u64(52, now_ms)
                    .push_str(11, &cl_ord_id)
                    .push_str(37, &order_id)
                    .push_str(17, &format!("EXEC-{}", now_ms))
                    .push_str(150, "0") // ExecType = New
                    .push_str(39, "0")  // OrdStatus = New
                    .push_str(55, &symbol)
                    .push_u64(151, leaves_qty)
                    .push_str(1128, "9");
                self.oe_next_sender_seq += 1;
                oe_responses.push(oe_rep.finish_soh_bytes(false, false));

                // 2. Drop-Copy ExecutionReport (separate sequence number)
                let mut dc_rep = FixFrameBuilder::new();
                dc_rep
                    .push_str(35, "8")
                    .push_u64(34, self.dc_next_sender_seq)
                    .push_str(49, &format!("{}-DROPCOPY", self.config.sender_comp_id))
                    .push_str(56, &self.config.target_comp_id)
                    .push_u64(52, now_ms)
                    .push_str(11, &cl_ord_id)
                    .push_str(37, &order_id)
                    .push_str(17, &format!("EXEC-DC-{}", now_ms))
                    .push_str(150, "0")
                    .push_str(39, "0")
                    .push_str(55, &symbol)
                    .push_u64(151, leaves_qty)
                    .push_str(1128, "9");
                self.dc_next_sender_seq += 1;
                dc_messages.push(dc_rep.finish_soh_bytes(false, false));
            }
            _ => {}
        }

        (oe_responses, dc_messages)
    }

    /// Check if Cancel-on-Disconnect (COD) should trigger due to silence timeout.
    pub fn check_cancel_on_disconnect(&mut self, now_ms: u64) -> Vec<Vec<u8>> {
        if !self.oe_active || self.working_orders.is_empty() {
            return vec![];
        }

        let timeout = self.config.heart_bt_int_ms + self.config.cod_grace_ms;
        if now_ms.saturating_sub(self.last_recv_time_ms) >= timeout {
            self.cod_triggered = true;
            self.oe_active = false;

            let mut cancel_reports = Vec::new();
            for (_, order) in self.working_orders.drain() {
                self.total_cod_cancels += 1;
                let mut b = FixFrameBuilder::new();
                b.push_str(35, "8") // ExecutionReport (Cancelled by COD)
                    .push_u64(34, self.dc_next_sender_seq)
                    .push_str(49, &self.config.sender_comp_id)
                    .push_str(56, &self.config.target_comp_id)
                    .push_u64(52, now_ms)
                    .push_str(11, &order.cl_ord_id)
                    .push_str(37, &order.order_id)
                    .push_str(17, &format!("COD-{}", now_ms))
                    .push_str(150, "4") // ExecType = Cancelled
                    .push_str(39, "4")  // OrdStatus = Cancelled
                    .push_str(58, "COINBASE: Cancel on Disconnect Triggered")
                    .push_u64(151, 0)
                    .push_str(1128, "9");
                self.dc_next_sender_seq += 1;
                cancel_reports.push(b.finish_soh_bytes(false, false));
            }
            cancel_reports
        } else {
            vec![]
        }
    }
}
