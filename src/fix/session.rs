//! Month 1, Week 2: Native Rust FIX 4.4 + FinGate Session Shield State Machine (`Fix44SessionEngine`).
//!
//! Implements all 25 formal FIX 4.4 and FinGate Session Shield rules (`R1`..`R25`),
//! driven deterministically by `Arc<dyn Env>` (`RealEnv` or `SimEnv`).
//! Supports both structured trace execution (`step_event`) and zero-copy wire-frame
//! execution (`step_wire_frame` via `FixWireView`).

use crate::env::Env;
use crate::fix::wire::{FixFrameBuilder, FixWireView};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::sync::Arc;

#[inline]
pub fn is_admin_msg_type(msg_type: &str) -> bool {
    matches!(msg_type, "0" | "1" | "2" | "3" | "4" | "5" | "A")
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EngineConfig {
    #[serde(default = "default_hb_ms")]
    pub heart_bt_int_ms: u64,
    #[serde(default)]
    pub test_request_grace_ms: Option<u64>,
    #[serde(default)]
    pub send_redundant_resend_requests: bool,
    #[serde(default = "default_pod_grace_ms")]
    pub pod_grace_timeout_ms: u64,
    #[serde(default)]
    pub unclean_drop_lockout_multiplier: Option<u64>,
    #[serde(default = "default_max_clock_skew_ms")]
    pub max_clock_skew_ms: u64,
}

fn default_hb_ms() -> u64 {
    30_000
}
fn default_pod_grace_ms() -> u64 {
    5_000
}
fn default_max_clock_skew_ms() -> u64 {
    120_000
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WorkingOrder {
    pub cl_ord_id: String,
    pub pod_id: String,
    #[serde(default)]
    pub symbol: String,
    #[serde(default)]
    pub side: String,
    pub leaves_qty: i64,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OutboundFixMsg {
    pub msg_type: String,
    pub msg_seq_num: u64,
    pub poss_dup_flag: bool,
    pub send_time_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gap_fill_flag: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub new_seq_no: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub begin_seq_no: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end_seq_no: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cl_ord_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub orig_cl_ord_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub test_req_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ref_seq_num: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_reject_reason: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reset_seq_num_flag: Option<bool>,
}

impl OutboundFixMsg {
    pub fn new(msg_type: &str, send_time_ms: u64) -> Self {
        Self {
            msg_type: msg_type.to_string(),
            msg_seq_num: 0,
            poss_dup_flag: false,
            send_time_ms,
            gap_fill_flag: None,
            new_seq_no: None,
            begin_seq_no: None,
            end_seq_no: None,
            cl_ord_id: None,
            orig_cl_ord_id: None,
            test_req_id: None,
            ref_seq_num: None,
            session_reject_reason: None,
            reset_seq_num_flag: None,
        }
    }

    /// Encode this outbound message into a raw FIX 4.4 wire frame (`8=FIX.4.4\x019=...\x0110=...\x01`).
    pub fn to_wire_bytes(&self, sender: &str, target: &str) -> Vec<u8> {
        let mut b = FixFrameBuilder::new();
        b.push_str(35, &self.msg_type)
            .push_u64(34, self.msg_seq_num)
            .push_str(49, sender)
            .push_str(56, target)
            .push_u64(52, self.send_time_ms);
        if self.poss_dup_flag {
            b.push_bool(43, true);
            b.push_u64(122, self.send_time_ms);
        }
        if let Some(gf) = self.gap_fill_flag {
            b.push_bool(123, gf);
        }
        if let Some(ns) = self.new_seq_no {
            b.push_u64(36, ns);
        }
        if let Some(bs) = self.begin_seq_no {
            b.push_u64(7, bs);
        }
        if let Some(es) = self.end_seq_no {
            b.push_u64(16, es);
        }
        if let Some(ref cid) = self.cl_ord_id {
            b.push_str(11, cid);
        }
        if let Some(ref ocid) = self.orig_cl_ord_id {
            b.push_str(41, ocid);
        }
        if let Some(ref trid) = self.test_req_id {
            b.push_str(112, trid);
        }
        if let Some(rsn) = self.ref_seq_num {
            b.push_u64(45, rsn);
        }
        if let Some(srr) = self.session_reject_reason {
            b.push_u64(373, srr);
        }
        if let Some(rflag) = self.reset_seq_num_flag {
            b.push_bool(141, rflag);
        }
        b.finish_soh_bytes(false, false)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FinalSessionState {
    pub status: String,
    pub next_sender_seq_num: u64,
    pub next_target_seq_num: u64,
    pub disconnect_time_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SessionTraceResult {
    pub outbound_messages: Vec<OutboundFixMsg>,
    pub final_state: FinalSessionState,
}

/// Deterministic Rust FIX 4.4 + FinGate Session Shield state machine.
pub struct Fix44SessionEngine {
    pub env: Arc<dyn Env>,
    pub config: EngineConfig,
    pub status: String,
    pub next_sender_seq_num: u64,
    pub next_target_seq_num: u64,
    pub disconnect_time_ms: Option<u64>,
    pub outbound_store: BTreeMap<u64, Value>,
    pub last_sent_time_ms: u64,
    pub last_recv_time_ms: u64,
    pub test_request_pending_since_ms: Option<u64>,
    pub resend_request_active: bool,
    pub inbound_queue: BTreeMap<u64, Value>,
    pub working_orders: BTreeMap<String, WorkingOrder>,
    pub crashed_pods_deadline_ms: BTreeMap<String, u64>,
    pub lockout_until_ms: Option<u64>,
    pub emitted_messages: Vec<OutboundFixMsg>,
    pub garbled_frames_dropped: usize,
}

impl Fix44SessionEngine {
    /// Construct a `Fix44SessionEngine` from a `SessionBench` JSON task specification and `Env`.
    pub fn from_task_json(task_spec: &Value, env: Arc<dyn Env>) -> anyhow::Result<Self> {
        let config: EngineConfig = serde_json::from_value(task_spec["engine_config"].clone())?;
        let init = &task_spec["initial_store"];

        let status = init
            .get("status")
            .and_then(|v| v.as_str())
            .unwrap_or("ACTIVE")
            .to_string();
        let next_sender_seq_num = init["next_sender_seq_num"].as_u64().unwrap_or(1);
        let next_target_seq_num = init["next_target_seq_num"].as_u64().unwrap_or(1);
        let disconnect_time_ms = init.get("disconnect_time_ms").and_then(|v| v.as_u64());

        let mut outbound_store = BTreeMap::new();
        if let Some(arr) = init.get("outbound_messages_store").and_then(|v| v.as_array()) {
            for item in arr {
                if let Some(seq) = item.get("msg_seq_num").and_then(|v| v.as_u64()) {
                    outbound_store.insert(seq, item.clone());
                }
            }
        }

        let last_sent_time_ms = init
            .get("last_sent_time_ms")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let last_recv_time_ms = init
            .get("last_recv_time_ms")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let test_request_pending_since_ms = init
            .get("test_request_pending_since_ms")
            .and_then(|v| v.as_u64());
        let resend_request_active = init
            .get("resend_request_active")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let lockout_until_ms = init.get("lockout_until_ms").and_then(|v| v.as_u64());

        let mut working_orders = BTreeMap::new();
        if let Some(arr) = init.get("working_orders").and_then(|v| v.as_array()) {
            for item in arr {
                let wo: WorkingOrder = serde_json::from_value(item.clone())?;
                working_orders.insert(wo.cl_ord_id.clone(), wo);
            }
        }

        Ok(Self {
            env,
            config,
            status,
            next_sender_seq_num,
            next_target_seq_num,
            disconnect_time_ms,
            outbound_store,
            last_sent_time_ms,
            last_recv_time_ms,
            test_request_pending_since_ms,
            resend_request_active,
            inbound_queue: BTreeMap::new(),
            working_orders,
            crashed_pods_deadline_ms: BTreeMap::new(),
            lockout_until_ms,
            emitted_messages: Vec::new(),
            garbled_frames_dropped: 0,
        })
    }

    fn emit(&mut self, mut msg: OutboundFixMsg, advance_seq: bool) {
        if advance_seq {
            let seq = self.next_sender_seq_num;
            self.next_sender_seq_num += 1;
            msg.msg_seq_num = seq;
            msg.poss_dup_flag = false;
            self.outbound_store
                .insert(seq, serde_json::to_value(&msg).unwrap_or(Value::Null));
        }
        self.last_sent_time_ms = msg.send_time_ms;
        self.emitted_messages.push(msg);
    }

    /// Execute FIX 4.4 `ResendRequest (35=2)` replay over `[begin_seq, end_seq]`.
    /// Implements R1, R2 (Contiguous Admin Gap-Fill Coalescing), and R13 (`16=0` -> max stored).
    fn execute_resend_range(&mut self, begin_seq: u64, end_seq: u64, now_ms: u64) {
        let max_stored = self.next_sender_seq_num.saturating_sub(1);
        let actual_end = if end_seq == 0 {
            max_stored
        } else {
            end_seq.min(max_stored)
        };
        let mut seq = begin_seq;

        while seq <= actual_end {
            let mtype = self
                .outbound_store
                .get(&seq)
                .and_then(|v| v.get("msg_type"))
                .and_then(|v| v.as_str())
                .unwrap_or("0")
                .to_string();

            if is_admin_msg_type(&mtype) {
                let gap_start = seq;
                while seq <= actual_end {
                    let next_type = self
                        .outbound_store
                        .get(&seq)
                        .and_then(|v| v.get("msg_type"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("0");
                    if is_admin_msg_type(next_type) {
                        seq += 1;
                    } else {
                        break;
                    }
                }
                let mut gf = OutboundFixMsg::new("4", now_ms);
                gf.msg_seq_num = gap_start;
                gf.poss_dup_flag = true;
                gf.gap_fill_flag = Some(true);
                gf.new_seq_no = Some(seq);
                self.emit(gf, false);
            } else {
                let cl_ord_id = self
                    .outbound_store
                    .get(&seq)
                    .and_then(|v| v.get("cl_ord_id"))
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                let mut resent = OutboundFixMsg::new(&mtype, now_ms);
                resent.msg_seq_num = seq;
                resent.poss_dup_flag = true;
                resent.cl_ord_id = cl_ord_id;
                self.emit(resent, false);
                seq += 1;
            }
        }
    }

    fn drain_inbound_queue(&mut self, now_ms: u64) {
        while let Some(queued) = self.inbound_queue.remove(&self.next_target_seq_num) {
            let q_type = queued
                .get("msg_type")
                .and_then(|v| v.as_str())
                .unwrap_or("0");
            let gap_fill = queued
                .get("gap_fill_flag")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);

            if q_type == "4" && gap_fill {
                if let Some(new_seq) = queued.get("new_seq_no").and_then(|v| v.as_u64()) {
                    self.next_target_seq_num = new_seq;
                }
            } else {
                self.next_target_seq_num += 1;
                if q_type == "2" {
                    let b = queued
                        .get("begin_seq_no")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(1);
                    let e = queued
                        .get("end_seq_no")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0);
                    self.execute_resend_range(b, e, now_ms);
                }
            }
        }
        if self.inbound_queue.is_empty() && self.status == "RESENDING" {
            self.status = "ACTIVE".to_string();
            self.resend_request_active = false;
        }
    }

    /// Process a single raw wire byte slice (`8=FIX.4.4\x019=...\x0110=...\x01`).
    /// Implements Rule R25 / Invariant I1: Garbled frames are silently dropped without
    /// incrementing `NextTargetMsgSeqNum`.
    pub fn step_wire_bytes(&mut self, raw_wire: &[u8], now_ms: u64) {
        let view = match FixWireView::parse_and_validate(raw_wire) {
            Ok(v) => v,
            Err(_) => {
                self.garbled_frames_dropped += 1;
                return;
            }
        };

        let msg_type = match view.msg_type() {
            Some(m) => m,
            None => {
                self.garbled_frames_dropped += 1;
                return;
            }
        };
        let seq_num = match view.msg_seq_num() {
            Some(s) => s,
            None => {
                self.garbled_frames_dropped += 1;
                return;
            }
        };

        let mut ev = json!({
            "event_type": "RECV_MSG",
            "timestamp_ms": now_ms,
            "msg_type": msg_type,
            "msg_seq_num": seq_num,
            "poss_dup_flag": view.get_bool(43).unwrap_or(false),
        });
        if let Some(orig) = view.get_u64(122) {
            ev["orig_sending_time_ms"] = json!(orig);
        }
        if let Some(gf) = view.get_bool(123) {
            ev["gap_fill_flag"] = json!(gf);
        }
        if let Some(ns) = view.get_u64(36) {
            ev["new_seq_no"] = json!(ns);
        }
        if let Some(bs) = view.get_u64(7) {
            ev["begin_seq_no"] = json!(bs);
        }
        if let Some(es) = view.get_u64(16) {
            ev["end_seq_no"] = json!(es);
        }
        if let Some(trid) = view.get_str(112) {
            ev["test_req_id"] = json!(trid);
        }
        if let Some(cid) = view.get_str(11) {
            ev["cl_ord_id"] = json!(cid);
        }
        if let Some(lqty) = view.get_u64(151) {
            ev["leaves_qty"] = json!(lqty);
        }
        self.step_event(&ev);
    }

    /// Process a single timestamped trace event.
    pub fn step_event(&mut self, event: &Value) {
        let ev_type = event
            .get("event_type")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let now_ms = event
            .get("timestamp_ms")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);

        match ev_type {
            "CLOCK_TICK" => self.handle_clock_tick(now_ms),
            "POD_CRASH" => {
                if let Some(pod_id) = event.get("pod_id").and_then(|v| v.as_str()) {
                    self.crashed_pods_deadline_ms
                        .insert(pod_id.to_string(), now_ms + self.config.pod_grace_timeout_ms);
                }
            }
            "POD_RECONNECT" => {
                if let Some(pod_id) = event.get("pod_id").and_then(|v| v.as_str()) {
                    self.crashed_pods_deadline_ms.remove(pod_id);
                }
            }
            "TCP_DROP" => {
                let clean = event.get("clean").and_then(|v| v.as_bool()).unwrap_or(false);
                self.disconnect_time_ms = Some(now_ms);
                if !clean {
                    if let Some(mult) = self.config.unclean_drop_lockout_multiplier {
                        self.lockout_until_ms = Some(now_ms + mult * self.config.heart_bt_int_ms);
                        self.status = "LOCKED_OUT".to_string();
                        return;
                    }
                }
                self.status = "DISCONNECTED".to_string();
            }
            "RECONNECT_ATTEMPT" => {
                if self.status == "LOCKED_OUT" {
                    if let Some(until) = self.lockout_until_ms {
                        if now_ms < until {
                            return;
                        }
                    }
                }
                let reset_flag = event
                    .get("reset_seq_num_flag")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                if reset_flag {
                    self.next_sender_seq_num = 1;
                    self.next_target_seq_num = 1;
                    self.inbound_queue.clear();
                    self.resend_request_active = false;
                }
                let mut logon = OutboundFixMsg::new("A", now_ms);
                logon.reset_seq_num_flag = Some(reset_flag);
                self.emit(logon, true);
            }
            "SEND_ORDER" => {
                if self.status == "ACTIVE" {
                    let mut nos = OutboundFixMsg::new("D", now_ms);
                    nos.cl_ord_id = event
                        .get("cl_ord_id")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());
                    self.emit(nos, true);
                }
            }
            "RECV_MSG" => self.handle_recv_msg(event, now_ms),
            _ => {}
        }
    }

    fn handle_clock_tick(&mut self, now_ms: u64) {
        let expired_pods: Vec<String> = self
            .crashed_pods_deadline_ms
            .iter()
            .filter(|(_, &deadline)| now_ms >= deadline)
            .map(|(pod_id, _)| pod_id.clone())
            .collect();

        for pod_id in expired_pods {
            self.crashed_pods_deadline_ms.remove(&pod_id);
            let order_ids: Vec<String> = self.working_orders.keys().cloned().collect();
            for cid in order_ids {
                let should_cancel = if let Some(wo) = self.working_orders.get_mut(&cid) {
                    if wo.pod_id == pod_id && wo.leaves_qty > 0 {
                        wo.leaves_qty = 0;
                        wo.status = "CANCELLING".to_string();
                        true
                    } else {
                        false
                    }
                } else {
                    false
                };
                if should_cancel {
                    let mut cancel = OutboundFixMsg::new("F", now_ms);
                    cancel.cl_ord_id = Some(format!("CANCEL-{}", cid));
                    cancel.orig_cl_ord_id = Some(cid);
                    self.emit(cancel, true);
                }
            }
        }

        if self.status != "ACTIVE" && self.status != "RESENDING" {
            return;
        }

        let hb_ms = self.config.heart_bt_int_ms;
        let grace_ms = self.config.test_request_grace_ms.unwrap_or(hb_ms);

        if let Some(pending_since) = self.test_request_pending_since_ms {
            if now_ms.saturating_sub(pending_since) >= grace_ms {
                self.status = "DISCONNECTED".to_string();
                self.disconnect_time_ms = Some(now_ms);
                return;
            }
        }

        if self.test_request_pending_since_ms.is_none()
            && now_ms.saturating_sub(self.last_recv_time_ms) >= hb_ms
        {
            self.test_request_pending_since_ms = Some(now_ms);
            let tr = OutboundFixMsg::new("1", now_ms);
            self.emit(tr, true);
            return;
        }

        if now_ms.saturating_sub(self.last_sent_time_ms) >= hb_ms {
            let hb = OutboundFixMsg::new("0", now_ms);
            self.emit(hb, true);
        }
    }

    fn handle_recv_msg(&mut self, msg: &Value, now_ms: u64) {
        let msg_type = msg.get("msg_type").and_then(|v| v.as_str()).unwrap_or("");
        if self.status == "DISCONNECTED" && msg_type != "A" {
            return;
        }

        // Rule R25 / Invariant I1: Garbled message check
        if msg.get("garbled").and_then(|v| v.as_bool()).unwrap_or(false) {
            self.garbled_frames_dropped += 1;
            return;
        }
        if let Some(raw_wire) = msg.get("raw_wire").and_then(|v| v.as_str()) {
            if !raw_wire.is_empty() && FixWireView::parse_and_validate(raw_wire.as_bytes()).is_err()
            {
                self.garbled_frames_dropped += 1;
                return;
            }
        }

        self.last_recv_time_ms = now_ms;
        self.test_request_pending_since_ms = None;

        let seq_num = msg.get("msg_seq_num").and_then(|v| v.as_u64()).unwrap_or(0);
        let poss_dup = msg
            .get("poss_dup_flag")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let gap_fill = msg
            .get("gap_fill_flag")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        // R12: SequenceReset-Reset (35=4, 123=N) bypasses sequence checks unconditionally
        if msg_type == "4" && !gap_fill {
            if let Some(new_seq) = msg.get("new_seq_no").and_then(|v| v.as_u64()) {
                self.next_target_seq_num = new_seq;
                self.inbound_queue.clear();
                self.resend_request_active = false;
                self.status = "ACTIVE".to_string();
            }
            return;
        }

        // R8 & R10: MsgSeqNum < NextTargetMsgSeqNum
        if seq_num < self.next_target_seq_num {
            if poss_dup {
                return;
            }
            let logout = OutboundFixMsg::new("5", now_ms);
            self.emit(logout, true);
            self.status = "DISCONNECTED".to_string();
            self.disconnect_time_ms = Some(now_ms);
            return;
        }

        // R9: PossDupFlag=Y missing required OrigSendingTime (122)
        let orig_time_opt = msg.get("orig_sending_time_ms").and_then(|v| v.as_u64());
        if poss_dup && orig_time_opt.is_none() {
            if seq_num == self.next_target_seq_num {
                self.next_target_seq_num += 1;
            }
            let mut rej = OutboundFixMsg::new("3", now_ms);
            rej.ref_seq_num = Some(seq_num);
            rej.session_reject_reason = Some(1);
            self.emit(rej, true);
            return;
        }

        // R6 & R7: Sequence gap (seq_num > NextTargetMsgSeqNum)
        if seq_num > self.next_target_seq_num {
            if msg_type == "A" && self.status == "DISCONNECTED" {
                let logon_ack = OutboundFixMsg::new("A", now_ms);
                self.emit(logon_ack, true);

                let mut rr = OutboundFixMsg::new("2", now_ms);
                rr.begin_seq_no = Some(self.next_target_seq_num);
                rr.end_seq_no = Some(0);
                self.emit(rr, true);

                self.inbound_queue.insert(seq_num, msg.clone());
                self.status = "RESENDING".to_string();
                self.resend_request_active = true;
                return;
            }

            self.inbound_queue.insert(seq_num, msg.clone());
            if !self.resend_request_active || self.config.send_redundant_resend_requests {
                let mut rr = OutboundFixMsg::new("2", now_ms);
                rr.begin_seq_no = Some(self.next_target_seq_num);
                rr.end_seq_no = Some(0);
                self.emit(rr, true);
                self.resend_request_active = true;
                self.status = "RESENDING".to_string();
            }

            if msg_type == "2" {
                let b = msg.get("begin_seq_no").and_then(|v| v.as_u64()).unwrap_or(1);
                let e = msg.get("end_seq_no").and_then(|v| v.as_u64()).unwrap_or(0);
                self.execute_resend_range(b, e, now_ms);
                if let Some(queued_entry) = self.inbound_queue.get_mut(&seq_num) {
                    queued_entry["msg_type"] = json!("0");
                }
            }
            return;
        }

        // Exact sequence match: seq_num == self.next_target_seq_num
        if msg_type == "4" && gap_fill {
            let new_seq = msg.get("new_seq_no").and_then(|v| v.as_u64()).unwrap_or(0);
            if new_seq < self.next_target_seq_num {
                // R11: Attempt to lower sequence number via GapFill -> Session Reject (373=5)
                self.next_target_seq_num += 1;
                let mut rej = OutboundFixMsg::new("3", now_ms);
                rej.ref_seq_num = Some(seq_num);
                rej.session_reject_reason = Some(5);
                self.emit(rej, true);
                return;
            }
            self.next_target_seq_num = new_seq;
            self.drain_inbound_queue(now_ms);
            return;
        }

        self.next_target_seq_num += 1;

        match msg_type {
            "A" => {
                self.status = "ACTIVE".to_string();
                self.disconnect_time_ms = None;
            }
            "1" => {
                let mut hb = OutboundFixMsg::new("0", now_ms);
                hb.test_req_id = msg
                    .get("test_req_id")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                self.emit(hb, true);
            }
            "2" => {
                let b = msg.get("begin_seq_no").and_then(|v| v.as_u64()).unwrap_or(1);
                let e = msg.get("end_seq_no").and_then(|v| v.as_u64()).unwrap_or(0);
                self.execute_resend_range(b, e, now_ms);
            }
            "8" => {
                if let Some(cid) = msg.get("cl_ord_id").and_then(|v| v.as_str()) {
                    if let Some(wo) = self.working_orders.get_mut(cid) {
                        let lqty = msg.get("leaves_qty").and_then(|v| v.as_i64()).unwrap_or(0);
                        wo.leaves_qty = lqty;
                        if lqty == 0 {
                            wo.status = "FILLED".to_string();
                        }
                    }
                }
            }
            _ => {}
        }

        self.drain_inbound_queue(now_ms);
    }

    /// Run a complete list of JSON trace events and return the `SessionTraceResult`.
    pub fn run_trace(&mut self, events: &[Value]) -> SessionTraceResult {
        for ev in events {
            self.step_event(ev);
        }
        SessionTraceResult {
            outbound_messages: self.emitted_messages.clone(),
            final_state: FinalSessionState {
                status: self.status.clone(),
                next_sender_seq_num: self.next_sender_seq_num,
                next_target_seq_num: self.next_target_seq_num,
                disconnect_time_ms: self.disconnect_time_ms,
            },
        }
    }
}
