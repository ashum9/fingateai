//! Month 2, Week 3: NSE / BSE India SEBI Conformance Digital Twin (`NseIndiaTwin`).
//!
//! Emulates Indian Exchange (NSE/BSE) algo connectivity under the mandatory
//! **SEBI Algorithmic Trading Circular (`SEBI/HO/MIRSD/MIRSD-PoD/P/CIR/2025/132`)**:
//! 1. Mandatory `AlgoID (1001)` tag enforcement on every order. Unregistered or missing AlgoIDs
//!    trigger immediate regulatory rejection (`35=8, OrdStatus=8, Text="SEBI: Missing AlgoID"`).
//! 2. 10 Orders Per Second (OPS) rate-limit circuit breaker per AlgoID.
//! 3. Static IP session binding: Primary vs Secondary IP failover.
//! 4. Emergency Kill-Switch (`35=q` OrderMassCancelRequest) cancelling all orders for an AlgoID.

use crate::fix::wire::{FixFrameBuilder, FixWireView};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

pub const SEBI_ALGO_TAG: u32 = 1001;
pub const SEBI_MAX_OPS: usize = 10;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NseTwinConfig {
    pub broker_comp_id: String,
    pub exchange_comp_id: String,
    pub primary_ip: String,
    pub secondary_ip: String,
    pub registered_algo_ids: HashSet<String>,
}

impl Default for NseTwinConfig {
    fn default() -> Self {
        let mut algos = HashSet::new();
        algos.insert("ALGO-NIFTY-ARB-01".to_string());
        algos.insert("ALGO-BANKNIFTY-MOM-02".to_string());
        Self {
            broker_comp_id: "FINGATE_BROKER".to_string(),
            exchange_comp_id: "NSE_FO".to_string(),
            primary_ip: "10.20.1.10".to_string(),
            secondary_ip: "10.20.1.11".to_string(),
            registered_algo_ids: algos,
        }
    }
}

pub struct NseIndiaTwin {
    pub config: NseTwinConfig,
    pub active_ip: Option<String>,
    pub next_sender_seq: u64,
    pub next_target_seq: u64,
    pub algo_order_timestamps_ms: HashMap<String, Vec<u64>>,
    pub algo_working_orders: HashMap<String, Vec<String>>, // algo_id -> [cl_ord_id]
    pub sebi_algo_id_rejects: u64,
    pub sebi_rate_limit_trips: u64,
    pub kill_switch_cancels: u64,
}

impl NseIndiaTwin {
    pub fn new(config: NseTwinConfig) -> Self {
        Self {
            config,
            active_ip: None,
            next_sender_seq: 1,
            next_target_seq: 1,
            algo_order_timestamps_ms: HashMap::new(),
            algo_working_orders: HashMap::new(),
            sebi_algo_id_rejects: 0,
            sebi_rate_limit_trips: 0,
            kill_switch_cancels: 0,
        }
    }

    /// Authenticate incoming TCP connection IP against SEBI static IP whitelist.
    pub fn connect_ip(&mut self, ip: &str) -> bool {
        if ip == self.config.primary_ip || ip == self.config.secondary_ip {
            self.active_ip = Some(ip.to_string());
            true
        } else {
            self.active_ip = None;
            false
        }
    }

    /// Process incoming FIX 4.4 / SEBI order flow frame.
    pub fn handle_inbound(&mut self, raw_wire: &[u8], now_ms: u64) -> Vec<Vec<u8>> {
        let view = match FixWireView::parse_and_validate(raw_wire) {
            Ok(v) => v,
            Err(_) => return vec![],
        };

        let msg_type = match view.msg_type() {
            Some(m) => m,
            None => return vec![],
        };
        let seq = view.msg_seq_num().unwrap_or(0);
        self.next_target_seq = seq + 1;

        match msg_type {
            "A" => {
                // Logon
                let mut b = FixFrameBuilder::new();
                b.push_str(35, "A")
                    .push_u64(34, self.next_sender_seq)
                    .push_str(49, &self.config.exchange_comp_id)
                    .push_str(56, &self.config.broker_comp_id)
                    .push_u64(52, now_ms)
                    .push_u64(108, 30);
                self.next_sender_seq += 1;
                vec![b.finish_soh_bytes(false, false)]
            }
            "D" => {
                // NewOrderSingle -> Enforce SEBI Circular 2025/132
                let cl_ord_id = view.get_str(11).unwrap_or("ORD-UNKNOWN").to_string();
                let algo_id_opt = view.get_str(SEBI_ALGO_TAG);

                // 1. Mandatory AlgoID Check
                let algo_id = match algo_id_opt {
                    Some(id) if self.config.registered_algo_ids.contains(id) => id.to_string(),
                    Some(unregistered) => {
                        self.sebi_algo_id_rejects += 1;
                        let mut b = FixFrameBuilder::new();
                        b.push_str(35, "8")
                            .push_u64(34, self.next_sender_seq)
                            .push_str(49, &self.config.exchange_comp_id)
                            .push_str(56, &self.config.broker_comp_id)
                            .push_u64(52, now_ms)
                            .push_str(11, &cl_ord_id)
                            .push_str(17, &format!("SEBI-REJ-{}", now_ms))
                            .push_str(150, "8")
                            .push_str(39, "8")
                            .push_str(58, &format!("SEBI: Unregistered AlgoID '{}'", unregistered));
                        self.next_sender_seq += 1;
                        return vec![b.finish_soh_bytes(false, false)];
                    }
                    None => {
                        self.sebi_algo_id_rejects += 1;
                        let mut b = FixFrameBuilder::new();
                        b.push_str(35, "8")
                            .push_u64(34, self.next_sender_seq)
                            .push_str(49, &self.config.exchange_comp_id)
                            .push_str(56, &self.config.broker_comp_id)
                            .push_u64(52, now_ms)
                            .push_str(11, &cl_ord_id)
                            .push_str(17, &format!("SEBI-REJ-{}", now_ms))
                            .push_str(150, "8")
                            .push_str(39, "8")
                            .push_str(58, "SEBI: Missing mandatory Tag 1001 (AlgoID)");
                        self.next_sender_seq += 1;
                        return vec![b.finish_soh_bytes(false, false)];
                    }
                };

                // 2. 10-OPS Rate Limit Circuit Breaker per AlgoID
                let timestamps = self.algo_order_timestamps_ms.entry(algo_id.clone()).or_default();
                timestamps.retain(|&ts| now_ms.saturating_sub(ts) <= 1000);

                if timestamps.len() >= SEBI_MAX_OPS {
                    self.sebi_rate_limit_trips += 1;
                    let mut b = FixFrameBuilder::new();
                    b.push_str(35, "8")
                        .push_u64(34, self.next_sender_seq)
                        .push_str(49, &self.config.exchange_comp_id)
                        .push_str(56, &self.config.broker_comp_id)
                        .push_u64(52, now_ms)
                        .push_str(11, &cl_ord_id)
                        .push_str(17, &format!("SEBI-RATE-{}", now_ms))
                        .push_str(150, "8")
                        .push_str(39, "8")
                        .push_str(58, &format!("SEBI: 10 OPS Rate Limit Breached for AlgoID {}", algo_id));
                    self.next_sender_seq += 1;
                    return vec![b.finish_soh_bytes(false, false)];
                }

                timestamps.push(now_ms);
                self.algo_working_orders.entry(algo_id.clone()).or_default().push(cl_ord_id.clone());

                // Order Accepted
                let mut b = FixFrameBuilder::new();
                b.push_str(35, "8")
                    .push_u64(34, self.next_sender_seq)
                    .push_str(49, &self.config.exchange_comp_id)
                    .push_str(56, &self.config.broker_comp_id)
                    .push_u64(52, now_ms)
                    .push_str(11, &cl_ord_id)
                    .push_str(17, &format!("NSE-{}", now_ms))
                    .push_str(150, "0")
                    .push_str(39, "0")
                    .push_u64(151, view.get_u64(38).unwrap_or(1))
                    .push_str(SEBI_ALGO_TAG, &algo_id);
                self.next_sender_seq += 1;
                vec![b.finish_soh_bytes(false, false)]
            }
            "q" => {
                // OrderMassCancelRequest (Kill Switch)
                let algo_id_opt = view.get_str(SEBI_ALGO_TAG);
                let mut cancels = Vec::new();

                if let Some(algo_id) = algo_id_opt {
                    if let Some(orders) = self.algo_working_orders.remove(algo_id) {
                        for ord_id in orders {
                            self.kill_switch_cancels += 1;
                            let mut b = FixFrameBuilder::new();
                            b.push_str(35, "8")
                                .push_u64(34, self.next_sender_seq)
                                .push_str(49, &self.config.exchange_comp_id)
                                .push_str(56, &self.config.broker_comp_id)
                                .push_u64(52, now_ms)
                                .push_str(11, &ord_id)
                                .push_str(17, &format!("NSE-CXL-{}", now_ms))
                                .push_str(150, "4")
                                .push_str(39, "4")
                                .push_u64(151, 0)
                                .push_str(58, "SEBI: Cancelled by Algo Emergency Kill Switch");
                            self.next_sender_seq += 1;
                            cancels.push(b.finish_soh_bytes(false, false));
                        }
                    }
                }
                cancels
            }
            _ => vec![],
        }
    }
}
