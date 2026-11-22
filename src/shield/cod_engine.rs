//! Month 4, Week 2: Production Stateful Cancel-on-Disconnect (COD) & Pod Grace Engine.
//!
//! Implements formal FinGate Session Shield rules R16–R20 & Invariant I7:
//! 1. Rule R16: Keep external exchange session ACTIVE when an internal strategy pod crashes.
//! 2. Rule R17: Start configurable `PodGraceTimeoutMs` window (e.g. 5,000 ms).
//! 3. Rule R18: Track incoming venue ExecutionReports during the grace window.
//! 4. Rule R19: If pod reconnects within grace window, cancel timer and flush missed fills.
//! 5. Rule R20 / Invariant I7: If grace window expires, emit synthetic `OrderCancelRequest (35=F)`
//!    ONLY for remaining open orders (`leaves_qty > 0`) belonging to that crashed pod.

use crate::shield::multiplexer::StrategyPodMultiplexer;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyntheticOrderCancel {
    pub cancel_cl_ord_id: String,
    pub orig_wire_cl_ord_id: String,
    pub pod_id: String,
    pub symbol: String,
    pub timestamp_ms: u64,
}

#[derive(Debug, Clone)]
pub struct BufferedExecutionReport {
    pub wire_cl_ord_id: String,
    pub original_cl_ord_id: String,
    pub fill_qty: u64,
    pub price: u64,
    pub leaves_qty: u64,
    pub timestamp_ms: u64,
}

pub struct CancelOnDisconnectEngine {
    pub pod_grace_timeout_ms: u64,
    pub crashed_pod_deadlines_ms: HashMap<String, u64>,
    pub buffered_pod_fills: HashMap<String, VecDeque<BufferedExecutionReport>>,
    pub total_synthetic_cancels_emitted: u64,
    pub total_grace_reconnects: u64,
}

impl CancelOnDisconnectEngine {
    pub fn new(pod_grace_timeout_ms: u64) -> Self {
        Self {
            pod_grace_timeout_ms,
            crashed_pod_deadlines_ms: HashMap::new(),
            buffered_pod_fills: HashMap::new(),
            total_synthetic_cancels_emitted: 0,
            total_grace_reconnects: 0,
        }
    }

    /// Event: Strategy pod crashed or disconnected at `now_ms`.
    /// Starts the grace timer; exchange FIX connection remains ACTIVE.
    pub fn on_pod_crash(&mut self, pod_id: &str, now_ms: u64) {
        let deadline = now_ms + self.pod_grace_timeout_ms;
        self.crashed_pod_deadlines_ms.insert(pod_id.to_string(), deadline);
        self.buffered_pod_fills.entry(pod_id.to_string()).or_default();
    }

    /// Event: Strategy pod reconnected at `now_ms`.
    /// If within grace window, cancels the deadline and returns all buffered fills.
    pub fn on_pod_reconnect(&mut self, pod_id: &str, now_ms: u64) -> Option<Vec<BufferedExecutionReport>> {
        if let Some(&deadline) = self.crashed_pod_deadlines_ms.get(pod_id) {
            if now_ms <= deadline {
                self.crashed_pod_deadlines_ms.remove(pod_id);
                self.total_grace_reconnects += 1;
                let fills = self.buffered_pod_fills.remove(pod_id).map(|q| q.into()).unwrap_or_default();
                return Some(fills);
            }
        }
        None
    }

    /// Event: Incoming execution report (`35=8`) arrived from exchange while pod may be offline.
    pub fn on_execution_report(
        &mut self,
        pod_id: &str,
        wire_cl_ord_id: &str,
        orig_cl_ord_id: &str,
        fill_qty: u64,
        price: u64,
        leaves_qty: u64,
        now_ms: u64,
    ) {
        if self.crashed_pod_deadlines_ms.contains_key(pod_id) {
            let buffer = self.buffered_pod_fills.entry(pod_id.to_string()).or_default();
            buffer.push_back(BufferedExecutionReport {
                wire_cl_ord_id: wire_cl_ord_id.to_string(),
                original_cl_ord_id: orig_cl_ord_id.to_string(),
                fill_qty,
                price,
                leaves_qty,
                timestamp_ms: now_ms,
            });
        }
    }

    /// Step clock: Checks if any pod grace timer has expired.
    /// Emits synthetic cancels ONLY for working orders (`leaves_qty > 0`) of expired pods.
    pub fn check_grace_expirations(
        &mut self,
        now_ms: u64,
        multiplexer: &mut StrategyPodMultiplexer,
    ) -> Vec<SyntheticOrderCancel> {
        let expired_pods: Vec<String> = self
            .crashed_pod_deadlines_ms
            .iter()
            .filter(|(_, &deadline)| now_ms >= deadline)
            .map(|(pod_id, _)| pod_id.clone())
            .collect();

        let mut cancels = Vec::new();

        for pod_id in expired_pods {
            self.crashed_pod_deadlines_ms.remove(&pod_id);
            self.buffered_pod_fills.remove(&pod_id);

            // Scan all active orders in router owned by THIS pod
            for (wire_id, order) in multiplexer.router.wire_to_pod.iter_mut() {
                if order.pod_id == pod_id && order.leaves_qty > 0 {
                    let cancel_id = format!("CXL-SYNTH-{}", wire_id);
                    cancels.push(SyntheticOrderCancel {
                        cancel_cl_ord_id: cancel_id,
                        orig_wire_cl_ord_id: wire_id.clone(),
                        pod_id: pod_id.clone(),
                        symbol: order.symbol.clone(),
                        timestamp_ms: now_ms,
                    });
                    order.leaves_qty = 0; // Mark cancelled
                    self.total_synthetic_cancels_emitted += 1;
                }
            }
        }

        cancels
    }

    pub fn is_pod_in_grace(&self, pod_id: &str) -> bool {
        self.crashed_pod_deadlines_ms.contains_key(pod_id)
    }
}
