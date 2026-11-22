//! FinGate Month 6: Production Control Plane & Inspection REST API (`fingate-admin`)
//!
//! Provides enterprise administrative endpoints for FinGate Session Shield:
//! - Health / Readiness probes (`/healthz`, `/readyz`)
//! - Live session & strategy pod inspection (`/api/v1/sessions`)
//! - Real-time pre-trade risk headroom & OTR telemetry (`/api/v1/risk/headroom`)
//! - Authenticated emergency kill-switch trip & reset (`/api/v1/killswitch/trip`, `/api/v1/killswitch/reset`)
//! - Reproducer export for post-mortem debugging (`/api/v1/reproducer/export`)

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use serde::{Deserialize, Serialize};

/// HTTP response structure for control plane handlers.
#[derive(Debug, Clone, PartialEq)]
pub struct HttpResponse {
    pub status_code: u16,
    pub content_type: &'static str,
    pub body: String,
}

impl HttpResponse {
    pub fn ok_json(json: String) -> Self {
        Self {
            status_code: 200,
            content_type: "application/json",
            body: json,
        }
    }

    pub fn ok_text(text: &str) -> Self {
        Self {
            status_code: 200,
            content_type: "text/plain",
            body: text.to_string(),
        }
    }

    pub fn service_unavailable(json: String) -> Self {
        Self {
            status_code: 503,
            content_type: "application/json",
            body: json,
        }
    }

    pub fn unauthorized(msg: &str) -> Self {
        Self {
            status_code: 401,
            content_type: "application/json",
            body: format!(r#"{{"error": "Unauthorized", "message": "{}"}}"#, msg),
        }
    }

    pub fn not_found() -> Self {
        Self {
            status_code: 404,
            content_type: "application/json",
            body: r#"{"error": "Not Found"}"#.to_string(),
        }
    }

    pub fn to_http1_wire(&self) -> Vec<u8> {
        let status_text = match self.status_code {
            200 => "OK",
            401 => "Unauthorized",
            404 => "Not Found",
            503 => "Service Unavailable",
            _ => "Status",
        };
        format!(
            "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nAccess-Control-Allow-Origin: *\r\nConnection: close\r\n\r\n{}",
            self.status_code,
            status_text,
            self.content_type,
            self.body.len(),
            self.body
        ).into_bytes()
    }
}

/// Control plane telemetry and state snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionInspectEntry {
    pub pod_id: u32,
    pub pod_name: String,
    pub client_comp_id: String,
    pub target_comp_id: String,
    pub inbound_seq: u64,
    pub outbound_seq: u64,
    pub active_orders: usize,
    pub is_healthy: bool,
    pub last_heartbeat_ago_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskHeadroomSnapshot {
    pub max_notional_single_order: f64,
    pub gross_daily_credit_limit: f64,
    pub utilized_daily_credit: f64,
    pub available_daily_credit: f64,
    pub mifid_otr_ratio: f64,
    pub mifid_otr_limit: f64,
    pub gcra_tokens_remaining: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReproducerTraceDump {
    pub dump_id: String,
    pub timestamp_utc: u64,
    pub reason: String,
    pub kill_switch_active: bool,
    pub last_wire_frames: Vec<String>,
    pub active_sessions: Vec<SessionInspectEntry>,
    pub risk_headroom: Option<RiskHeadroomSnapshot>,
}

/// Pipeline stage indices for Phase D8 lock-free per-stage latency telemetry.
pub const STAGE_INGRESS: usize = 0;
pub const STAGE_CODEC: usize = 1;
pub const STAGE_RISK_GREEKS: usize = 2;
pub const STAGE_ORDER_FSM: usize = 3;
pub const STAGE_WAL: usize = 4;
pub const STAGE_UPLINK: usize = 5;
pub const NUM_PIPELINE_STAGES: usize = 6;

pub const STAGE_NAMES: [&str; NUM_PIPELINE_STAGES] = [
    "Ingress (SHM/TCP)",
    "Codec Decode",
    "Risk + SIMD SPAN",
    "Order FSM (35=G)",
    "WAL Enqueue",
    "Venue Uplink",
];

const LATENCY_BUCKET_BOUNDS_NS: [u64; 24] = [
    10, 20, 40, 80, 120, 160, 250, 400, 650, 1_000, 2_000, 4_000, 8_000, 16_000, 32_000, 64_000,
    128_000, 256_000, 512_000, 1_000_000, 2_500_000, 5_000_000, 10_000_000, u64::MAX,
];

/// Wait-free per-stage atomic latency histogram (`0` locks, `0` heap allocs on `record`).
pub struct AtomicStageHistogram {
    buckets: [AtomicU64; 24],
    count: AtomicU64,
    sum_ns: AtomicU64,
    max_ns: AtomicU64,
}

impl Default for AtomicStageHistogram {
    fn default() -> Self {
        Self::new()
    }
}

impl AtomicStageHistogram {
    pub fn new() -> Self {
        Self {
            buckets: std::array::from_fn(|_| AtomicU64::new(0)),
            count: AtomicU64::new(0),
            sum_ns: AtomicU64::new(0),
            max_ns: AtomicU64::new(0),
        }
    }

    #[inline(always)]
    pub fn record(&self, latency_ns: u64) {
        let mut idx = LATENCY_BUCKET_BOUNDS_NS.len() - 1;
        for (i, &bound) in LATENCY_BUCKET_BOUNDS_NS.iter().enumerate() {
            if latency_ns <= bound {
                idx = i;
                break;
            }
        }
        self.buckets[idx].fetch_add(1, Ordering::Relaxed);
        self.count.fetch_add(1, Ordering::Relaxed);
        self.sum_ns.fetch_add(latency_ns, Ordering::Relaxed);
        let mut cur_max = self.max_ns.load(Ordering::Relaxed);
        while latency_ns > cur_max {
            match self.max_ns.compare_exchange_weak(
                cur_max,
                latency_ns,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(v) => cur_max = v,
            }
        }
    }

    pub fn snapshot(&self, stage: &str) -> StageLatencySnapshot {
        let count = self.count.load(Ordering::Relaxed);
        let sum = self.sum_ns.load(Ordering::Relaxed);
        let max_ns = self.max_ns.load(Ordering::Relaxed);
        let mut counts = [0u64; 24];
        for i in 0..24 {
            counts[i] = self.buckets[i].load(Ordering::Relaxed);
        }
        let quantile = |q: f64| -> u64 {
            if count == 0 {
                return 0;
            }
            let target = ((count as f64) * q).ceil().max(1.0) as u64;
            let mut acc = 0u64;
            for (i, &c) in counts.iter().enumerate() {
                acc += c;
                if acc >= target {
                    let b = LATENCY_BUCKET_BOUNDS_NS[i];
                    return if b == u64::MAX { max_ns } else { b.min(max_ns) };
                }
            }
            max_ns
        };
        StageLatencySnapshot {
            stage: stage.to_string(),
            samples: count,
            mean_ns: if count > 0 { sum / count } else { 0 },
            p50_ns: quantile(0.50),
            p99_ns: quantile(0.99),
            p99_9_ns: quantile(0.999),
            p99_99_ns: quantile(0.9999),
            max_ns,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StageLatencySnapshot {
    pub stage: String,
    pub samples: u64,
    pub mean_ns: u64,
    pub p50_ns: u64,
    pub p99_ns: u64,
    pub p99_9_ns: u64,
    pub p99_99_ns: u64,
    pub max_ns: u64,
}

/// Shared state backing the Enterprise Control Plane.
pub struct ControlPlaneState {
    pub auth_token: String,
    pub start_time: Instant,
    pub kill_switch_active: Arc<AtomicBool>,
    pub wal_synced_seq: Arc<AtomicU64>,
    pub venue_connections_active: Arc<AtomicU64>,
    pub drop_copy_drift_shares: Arc<AtomicU64>,
    /// Phase D5/D8: Current active VSR quorum fencing view epoch.
    pub vsr_view_epoch: Arc<AtomicU64>,
    /// Track I8: Live Singularity / Horizon telemetry atomics (`0` locks, `0` allocs on hot path).
    pub active_policy_id: Arc<AtomicU64>,
    pub hawkes_intensity_e4: Arc<AtomicU64>,
    pub vpin_e4: Arc<AtomicU64>,
    pub entropy_e4: Arc<AtomicU64>,
    pub lattice_orders_committed: Arc<AtomicU64>,
    pub merkle_roots_sealed: Arc<AtomicU64>,
    /// Phase D8: Lock-free per-stage pipeline latency histograms.
    pub stage_histograms: Arc<[AtomicStageHistogram; NUM_PIPELINE_STAGES]>,
    pub session_registry: parking_lot_stub::RwLock<HashMap<u32, SessionInspectEntry>>,
    pub last_reproducer: parking_lot_stub::RwLock<Option<ReproducerTraceDump>>,
    /// Latest risk snapshot pushed by the risk engine (None until first report).
    pub risk_headroom: parking_lot_stub::RwLock<Option<RiskHeadroomSnapshot>>,
    /// Bounded ring of the most recent wire frames, captured into reproducers.
    pub recent_frames: parking_lot_stub::RwLock<VecDeque<String>>,
}

/// Maximum number of recent wire frames retained for reproducer export.
pub const RECENT_FRAME_CAPACITY: usize = 256;

// Minimal portable RwLock helper to avoid external dependencies
mod parking_lot_stub {
    use std::sync::{RwLock as StdRwLock, RwLockReadGuard, RwLockWriteGuard};

    pub struct RwLock<T>(StdRwLock<T>);

    impl<T> RwLock<T> {
        pub fn new(val: T) -> Self {
            Self(StdRwLock::new(val))
        }

        pub fn read(&self) -> RwLockReadGuard<'_, T> {
            self.0.read().unwrap()
        }

        pub fn write(&self) -> RwLockWriteGuard<'_, T> {
            self.0.write().unwrap()
        }
    }
}

impl ControlPlaneState {
    pub fn new(auth_token: &str) -> Self {
        Self {
            auth_token: auth_token.to_string(),
            start_time: Instant::now(),
            kill_switch_active: Arc::new(AtomicBool::new(false)),
            wal_synced_seq: Arc::new(AtomicU64::new(1)),
            venue_connections_active: Arc::new(AtomicU64::new(1)),
            drop_copy_drift_shares: Arc::new(AtomicU64::new(0)),
            vsr_view_epoch: Arc::new(AtomicU64::new(1)),
            active_policy_id: Arc::new(AtomicU64::new(1)),
            hawkes_intensity_e4: Arc::new(AtomicU64::new(10_000)),
            vpin_e4: Arc::new(AtomicU64::new(0)),
            entropy_e4: Arc::new(AtomicU64::new(35_000)),
            lattice_orders_committed: Arc::new(AtomicU64::new(0)),
            merkle_roots_sealed: Arc::new(AtomicU64::new(0)),
            stage_histograms: Arc::new(std::array::from_fn(|_| AtomicStageHistogram::new())),
            session_registry: parking_lot_stub::RwLock::new(HashMap::new()),
            last_reproducer: parking_lot_stub::RwLock::new(None),
            risk_headroom: parking_lot_stub::RwLock::new(None),
            recent_frames: parking_lot_stub::RwLock::new(VecDeque::with_capacity(RECENT_FRAME_CAPACITY)),
        }
    }

    /// Phase D8: Wait-free hot-path latency sample recording (`0` locks, `0` allocs).
    #[inline(always)]
    pub fn record_stage_latency_ns(&self, stage_idx: usize, latency_ns: u64) {
        if stage_idx < NUM_PIPELINE_STAGES {
            self.stage_histograms[stage_idx].record(latency_ns);
        }
    }

    /// Publishes the latest risk snapshot (called by the risk engine owner thread).
    pub fn update_risk_headroom(&self, snapshot: RiskHeadroomSnapshot) {
        *self.risk_headroom.write() = Some(snapshot);
    }

    /// Records a wire frame into the bounded reproducer ring.
    pub fn record_wire_frame(&self, frame: &str) {
        let mut ring = self.recent_frames.write();
        if ring.len() == RECENT_FRAME_CAPACITY {
            ring.pop_front();
        }
        ring.push_back(frame.to_string());
    }

    /// Registers or updates a session entry for `/api/v1/sessions`.
    pub fn upsert_session(&self, entry: SessionInspectEntry) {
        self.session_registry.write().insert(entry.pod_id, entry);
    }

    /// Checks if the provided bearer authorization header matches.
    pub fn verify_auth(&self, auth_header: Option<&str>) -> bool {
        // An unconfigured (empty) token must never authenticate anything.
        if self.auth_token.is_empty() {
            return false;
        }
        match auth_header {
            Some(h) => {
                let token = h.strip_prefix("Bearer ").unwrap_or(h).trim();
                token == self.auth_token
            }
            None => false,
        }
    }

    /// Handles an incoming HTTP request.
    pub fn handle_request(
        &self,
        method: &str,
        path: &str,
        headers: &HashMap<String, String>,
        body: &str,
    ) -> HttpResponse {
        let auth_header = headers.get("authorization").map(|s| s.as_str());

        match (method, path) {
            ("GET", "/healthz") => {
                let uptime_s = self.start_time.elapsed().as_secs();
                let json = serde_json::json!({
                    "status": "UP",
                    "uptime_seconds": uptime_s,
                    "service": "FinGate Session Shield",
                    "version": "1.0.0"
                });
                HttpResponse::ok_json(json.to_string())
            }

            ("GET", "/readyz") => {
                let ks_active = self.kill_switch_active.load(Ordering::Relaxed);
                let wal_seq = self.wal_synced_seq.load(Ordering::Relaxed);
                let venues = self.venue_connections_active.load(Ordering::Relaxed);
                let drift = self.drop_copy_drift_shares.load(Ordering::Relaxed);

                let is_ready = !ks_active && wal_seq > 0 && venues > 0 && drift == 0;
                let payload = serde_json::json!({
                    "ready": is_ready,
                    "kill_switch_active": ks_active,
                    "wal_synced_seq": wal_seq,
                    "venues_connected": venues,
                    "drop_copy_drift_shares": drift
                });

                if is_ready {
                    HttpResponse::ok_json(payload.to_string())
                } else {
                    HttpResponse::service_unavailable(payload.to_string())
                }
            }

            ("GET", "/api/v1/sessions") => {
                let sessions: Vec<SessionInspectEntry> = self
                    .session_registry
                    .read()
                    .values()
                    .cloned()
                    .collect();
                let payload = serde_json::json!({
                    "total_sessions": sessions.len(),
                    "sessions": sessions
                });
                HttpResponse::ok_json(payload.to_string())
            }

            ("GET", "/api/v1/risk/headroom") => match &*self.risk_headroom.read() {
                Some(snap) => HttpResponse::ok_json(serde_json::to_string(snap).unwrap_or_default()),
                None => HttpResponse::service_unavailable(
                    r#"{"error": "risk engine has not reported a snapshot yet"}"#.to_string(),
                ),
            },

            ("POST", "/api/v1/killswitch/trip") => {
                if !self.verify_auth(auth_header) {
                    return HttpResponse::unauthorized("Valid admin Bearer token required to trip kill switch");
                }

                self.kill_switch_active.store(true, Ordering::SeqCst);
                let reason = if body.trim().is_empty() {
                    "Manual admin emergency trip via Control Plane".to_string()
                } else {
                    body.trim().to_string()
                };

                let now_utc = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();

                // Save reproducer snapshot
                let reproducer = ReproducerTraceDump {
                    dump_id: format!("ks-trip-{}", now_utc),
                    timestamp_utc: now_utc,
                    reason: reason.clone(),
                    kill_switch_active: true,
                    last_wire_frames: self.recent_frames.read().iter().cloned().collect(),
                    active_sessions: self.session_registry.read().values().cloned().collect(),
                    risk_headroom: self.risk_headroom.read().clone(),
                };
                *self.last_reproducer.write() = Some(reproducer);

                let payload = serde_json::json!({
                    "action": "EMERGENCY_KILL_SWITCH_TRIPPED",
                    "reason": reason,
                    "status": "HALTED",
                    "timestamp_utc": now_utc
                });
                HttpResponse::ok_json(payload.to_string())
            }

            ("POST", "/api/v1/killswitch/reset") => {
                if !self.verify_auth(auth_header) {
                    return HttpResponse::unauthorized("Valid admin Bearer token required to reset kill switch");
                }

                self.kill_switch_active.store(false, Ordering::SeqCst);
                self.drop_copy_drift_shares.store(0, Ordering::Relaxed);

                let payload = serde_json::json!({
                    "action": "EMERGENCY_KILL_SWITCH_RESET",
                    "status": "NORMAL_OPERATIONS",
                    "timestamp_utc": SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
                });
                HttpResponse::ok_json(payload.to_string())
            }

            ("GET", "/api/v1/telemetry/stages") => {
                let stages: Vec<StageLatencySnapshot> = (0..NUM_PIPELINE_STAGES)
                    .map(|i| self.stage_histograms[i].snapshot(STAGE_NAMES[i]))
                    .collect();
                let payload = serde_json::json!({
                    "vsr_view_epoch": self.vsr_view_epoch.load(Ordering::Relaxed),
                    "kill_switch_active": self.kill_switch_active.load(Ordering::Relaxed),
                    "wal_synced_seq": self.wal_synced_seq.load(Ordering::Relaxed),
                    "stages": stages
                });
                HttpResponse::ok_json(payload.to_string())
            }

            ("GET", "/api/v1/singularity/status") => {
                let payload = serde_json::json!({
                    "sha256_hw_accelerated": crate::attestation::sha256_hw_accelerated(),
                    "active_policy_id": self.active_policy_id.load(Ordering::Relaxed),
                    "hawkes_intensity_e4": self.hawkes_intensity_e4.load(Ordering::Relaxed),
                    "vpin_e4": self.vpin_e4.load(Ordering::Relaxed),
                    "entropy_e4": self.entropy_e4.load(Ordering::Relaxed),
                    "lattice_orders_committed": self.lattice_orders_committed.load(Ordering::Relaxed),
                    "merkle_roots_sealed": self.merkle_roots_sealed.load(Ordering::Relaxed),
                    "kill_switch_active": self.kill_switch_active.load(Ordering::Relaxed)
                });
                HttpResponse::ok_json(payload.to_string())
            }

            ("POST", "/api/v1/policy/compile") => {
                if !self.verify_auth(auth_header) {
                    return HttpResponse::unauthorized(
                        "Valid admin Bearer token required to hot-swap policy VM",
                    );
                }
                let next_id = self.active_policy_id.load(Ordering::Relaxed).wrapping_add(1);
                match crate::horizon::nano_policy_vm::compile_policy_dsl(next_id, body) {
                    Ok(prog) => {
                        self.active_policy_id.store(next_id, Ordering::Release);
                        let payload = serde_json::json!({
                            "status": "VERIFIED_AND_ACTIVATED",
                            "policy_id": next_id,
                            "instruction_count": prog.len,
                            "simd_prefilter_enabled": prog.simd_prefilter_enabled
                        });
                        HttpResponse::ok_json(payload.to_string())
                    }
                    Err(err) => HttpResponse {
                        status_code: 400,
                        content_type: "application/json",
                        body: serde_json::json!({
                            "status": "POLICY_VERIFICATION_REJECTED",
                            "error": err
                        })
                        .to_string(),
                    },
                }
            }

            ("GET", "/api/v1/reproducer/export") => {
                if !self.verify_auth(auth_header) {
                    return HttpResponse::unauthorized("Valid admin Bearer token required to export reproducer");
                }

                let reproducer_guard = self.last_reproducer.read();
                match &*reproducer_guard {
                    Some(rep) => {
                        let json = serde_json::to_string_pretty(rep).unwrap_or_default();
                        HttpResponse::ok_json(json)
                    }
                    None => {
                        HttpResponse::ok_json(r#"{"status": "No incidents recorded"}"#.to_string())
                    }
                }
            }

            _ => HttpResponse::not_found(),
        }
    }
}
