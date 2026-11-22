//! Production Async Multi-Client HTTP/1.1 + SSE Live Stream + MCP JSON-RPC 2.0 Server (`src/server/mod.rs`).
//!
//! Zero extra crate dependencies (built directly on `tokio::net::TcpListener` + `tokio::sync::broadcast`):
//! - Concurrent non-blocking multi-client connections with exact `Content-Length` framing.
//! - Real-time Server-Sent Events (`GET /api/stream`) broadcasting snapshots on every order/tick/disarm.
//! - Complete Model Context Protocol (`POST /mcp`, JSON-RPC 2.0) exposing FinGate AI as a live safety
//!   tool server for external AI agents (Claude, Gemini, Cursor, custom LangGraph/CrewAI bots).
//! - Prometheus metrics (`/metrics`), Kubernetes probes (`/healthz`, `/readyz`), and full REST API.

use std::sync::{Arc, Mutex};

use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::broadcast;

use crate::ai::FinGateAiEngine;

pub struct AppServerState {
    pub engine: Mutex<FinGateAiEngine>,
    pub sse_tx: broadcast::Sender<String>,
    pub ui_html: &'static str,
}

impl AppServerState {
    pub fn new(ui_html: &'static str) -> Arc<Self> {
        let (sse_tx, _) = broadcast::channel(64);
        Arc::new(Self {
            engine: Mutex::new(FinGateAiEngine::new()),
            sse_tx,
            ui_html,
        })
    }

    pub fn broadcast_snapshot(&self, snap_json: &str) {
        let _ = self.sse_tx.send(snap_json.to_string());
    }
}

pub async fn run_http_server(addr: &str, ui_html: &'static str) -> std::io::Result<()> {
    let listener = TcpListener::bind(addr).await?;
    let state = AppServerState::new(ui_html);

    println!("==========================================================================================");
    println!("  FinGate AI — Production NSE Co-Pilot & 12-Stage Singularity Rust Firewall");
    println!("  Web Command Center  : http://{}", addr);
    println!("  Live SSE Stream     : http://{}/api/stream", addr);
    println!("  MCP JSON-RPC 2.0    : http://{}/mcp", addr);
    println!("  Prometheus Metrics  : http://{}/metrics", addr);
    println!("  (100% Historical NSE Replay & Paper Trading Only • Zero Real Money • 0 Heap Hot-Path)");
    println!("==========================================================================================");

    loop {
        let (stream, _) = listener.accept().await?;
        let st = Arc::clone(&state);
        tokio::spawn(async move {
            let _ = handle_connection(stream, st).await;
        });
    }
}

/// Read a full HTTP/1.1 request (headers + exact `Content-Length` body across split TCP segments).
async fn read_http_request(stream: &mut TcpStream) -> std::io::Result<Option<(String, String, String)>> {
    let mut buf = Vec::with_capacity(4096);
    let mut tmp = [0u8; 4096];
    let header_end;
    loop {
        let n = stream.read(&mut tmp).await?;
        if n == 0 {
            return Ok(None);
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            header_end = pos + 4;
            break;
        }
        if buf.len() > 65_536 {
            return Ok(None);
        }
    }

    let hdr_str = String::from_utf8_lossy(&buf[..header_end]).to_string();
    let mut content_len = 0usize;
    for line in hdr_str.lines().skip(1) {
        if let Some((k, v)) = line.split_once(':') {
            if k.trim().eq_ignore_ascii_case("content-length") {
                content_len = v.trim().parse::<usize>().unwrap_or(0).min(1_048_576);
            }
        }
    }

    while buf.len() < header_end + content_len {
        let n = stream.read(&mut tmp).await?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&tmp[..n]);
    }

    let first_line = hdr_str.lines().next().unwrap_or("");
    let mut parts = first_line.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let raw_target = parts.next().unwrap_or("").to_string();
    let body = String::from_utf8_lossy(&buf[header_end..(header_end + content_len).min(buf.len())])
        .to_string();
    Ok(Some((method, raw_target, body)))
}

async fn write_http(
    stream: &mut TcpStream,
    status: &str,
    content_type: &str,
    body: &[u8],
) -> std::io::Result<()> {
    let header = format!(
        "HTTP/1.1 {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nAccess-Control-Allow-Origin: *\r\nAccess-Control-Allow-Methods: GET, POST, OPTIONS\r\nAccess-Control-Allow-Headers: Content-Type, Authorization\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n",
        status,
        content_type,
        body.len()
    );
    stream.write_all(header.as_bytes()).await?;
    stream.write_all(body).await?;
    stream.flush().await
}

async fn handle_connection(mut stream: TcpStream, state: Arc<AppServerState>) -> std::io::Result<()> {
    let Some((method, raw_target, body)) = read_http_request(&mut stream).await? else {
        return Ok(());
    };
    let path = raw_target.split('?').next().unwrap_or(&raw_target);

    if method == "OPTIONS" {
        return write_http(&mut stream, "204 No Content", "text/plain", b"").await;
    }

    if method == "GET" && (path == "/" || path == "/index.html") {
        return write_http(
            &mut stream,
            "200 OK",
            "text/html; charset=utf-8",
            state.ui_html.as_bytes(),
        )
        .await;
    }

    // Live Server-Sent Events Stream (`GET /api/stream`)
    if method == "GET" && path == "/api/stream" {
        let sse_hdr = "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\nConnection: keep-alive\r\nAccess-Control-Allow-Origin: *\r\n\r\n";
        stream.write_all(sse_hdr.as_bytes()).await?;
        let initial = {
            let eng = state.engine.lock().unwrap();
            serde_json::to_string(&eng.snapshot()).unwrap_or_else(|_| "{}".to_string())
        };
        stream
            .write_all(format!("event: state\ndata: {}\n\n", initial).as_bytes())
            .await?;
        stream.flush().await?;

        let mut rx = state.sse_tx.subscribe();
        loop {
            tokio::select! {
                msg = rx.recv() => {
                    match msg {
                        Ok(data) => {
                            if stream.write_all(format!("event: state\ndata: {}\n\n", data).as_bytes()).await.is_err() {
                                break;
                            }
                            let _ = stream.flush().await;
                        }
                        Err(broadcast::error::RecvError::Lagged(_)) => continue,
                        Err(_) => break,
                    }
                }
                _ = tokio::time::sleep(std::time::Duration::from_secs(15)) => {
                    if stream.write_all(b": keepalive\n\n").await.is_err() {
                        break;
                    }
                    let _ = stream.flush().await;
                }
            }
        }
        return Ok(());
    }

    let (status, ctype, resp_body) = dispatch_api(&state, &method, path, &raw_target, &body);
    write_http(&mut stream, status, ctype, resp_body.as_bytes()).await
}

/// Pure synchronous API/MCP router (directly unit-testable without sockets too!).
pub fn dispatch_api(
    state: &AppServerState,
    method: &str,
    path: &str,
    raw_target: &str,
    body: &str,
) -> (&'static str, &'static str, String) {
    match (method, path) {
        ("GET", "/healthz") => (
            "200 OK",
            "application/json",
            json!({
                "status": "UP",
                "service": "FinGate AI Production Singularity Engine",
                "version": "2.0.0-singularity",
                "hw_sha256_active": crate::attestation::sha256_hw_accelerated()
            })
            .to_string(),
        ),

        ("GET", "/readyz") => {
            let eng = state.engine.lock().unwrap();
            let ks = eng
                .quorum_guard
                .kill_switch_active
                .load(std::sync::atomic::Ordering::Acquire);
            let status = if ks { "503 Service Unavailable" } else { "200 OK" };
            (
                status,
                "application/json",
                json!({
                    "ready": !ks,
                    "kill_switch_active": ks,
                    "orders_approved": eng.approved_count,
                    "orders_blocked": eng.blocked_count
                })
                .to_string(),
            )
        }

        ("GET", "/metrics") => {
            let snap = state.engine.lock().unwrap().snapshot();
            let mut m = String::new();
            m.push_str("# HELP fingate_orders_approved_total Total paper orders approved by all 12 FinGate stages\n");
            m.push_str(&format!("fingate_orders_approved_total {}\n", snap.approved_count));
            m.push_str("# HELP fingate_orders_blocked_total Total unsafe/toxic orders blocked by FinGate Firewall\n");
            m.push_str(&format!("fingate_orders_blocked_total {}\n", snap.blocked_count));
            m.push_str(&format!("fingate_protected_equity_inr {}\n", snap.protected_equity_inr));
            m.push_str(&format!("fingate_unguarded_equity_inr {}\n", snap.unguarded_equity_inr));
            m.push_str(&format!("fingate_capital_saved_inr {}\n", snap.total_capital_saved_inr));
            m.push_str(&format!("fingate_hawkes_intensity_e4 {}\n", snap.hawkes_intensity_e4));
            m.push_str(&format!("fingate_vpin_toxicity_e4 {}\n", snap.vpin_toxicity_e4));
            m.push_str(&format!("fingate_shannon_entropy_e4 {}\n", snap.shannon_entropy_e4));
            m.push_str(&format!(
                "fingate_kill_switch_active {}\n",
                if snap.kill_switch_active { 1 } else { 0 }
            ));
            m.push_str(&format!(
                "fingate_hw_sha256_active {}\n",
                if snap.hw_sha256_active { 1 } else { 0 }
            ));
            ("200 OK", "text/plain; version=0.0.4", m)
        }

        ("GET", "/api/state") => {
            let json = serde_json::to_string(&state.engine.lock().unwrap().snapshot())
                .unwrap_or_else(|_| "{}".to_string());
            ("200 OK", "application/json", json)
        }

        ("POST", "/api/step") => {
            let count = serde_json::from_str::<Value>(body)
                .ok()
                .and_then(|v| v.get("count").and_then(|c| c.as_u64()))
                .unwrap_or(1)
                .clamp(1, 24);
            let snap_json = {
                let mut eng = state.engine.lock().unwrap();
                for _ in 0..count {
                    eng.step_next_tick();
                }
                serde_json::to_string(&eng.snapshot()).unwrap_or_else(|_| "{}".to_string())
            };
            state.broadcast_snapshot(&snap_json);
            ("200 OK", "application/json", snap_json)
        }

        ("POST", "/api/backtest") => {
            let (report, snap_json) = {
                let mut eng = state.engine.lock().unwrap();
                let rep = eng.run_full_tape_backtest();
                let sj = serde_json::to_string(&eng.snapshot()).unwrap_or_else(|_| "{}".to_string());
                (rep, sj)
            };
            state.broadcast_snapshot(&snap_json);
            (
                "200 OK",
                "application/json",
                json!({ "backtest": report, "state": serde_json::from_str::<Value>(&snap_json).unwrap_or(Value::Null) }).to_string(),
            )
        }

        ("POST", "/api/order") => {
            let v = serde_json::from_str::<Value>(body).unwrap_or(Value::Null);
            let symbol = v.get("symbol").and_then(|x| x.as_str()).unwrap_or("NIFTY50");
            let side = v.get("side").and_then(|x| x.as_str()).unwrap_or("BUY");
            let qty = v.get("qty").and_then(|x| x.as_i64()).unwrap_or(10);
            let price = v.get("price_inr").and_then(|x| x.as_i64()).unwrap_or(24_200);
            let is_fno = v.get("is_fno").and_then(|x| x.as_bool()).unwrap_or(false);
            let (dec, snap_json) = {
                let mut eng = state.engine.lock().unwrap();
                let d = eng.submit_manual_order(symbol, side, qty, price, is_fno);
                let sj = serde_json::to_string(&eng.snapshot()).unwrap_or_else(|_| "{}".to_string());
                (d, sj)
            };
            state.broadcast_snapshot(&snap_json);
            (
                "200 OK",
                "application/json",
                json!({ "decision": dec, "state": serde_json::from_str::<Value>(&snap_json).unwrap_or(Value::Null) }).to_string(),
            )
        }

        ("POST", "/api/tape") => {
            let snap_json = {
                let mut eng = state.engine.lock().unwrap();
                if let Ok(v) = serde_json::from_str::<Value>(body) {
                    if let Some(id) = v.get("tape_id").and_then(|x| x.as_str()) {
                        eng.select_tape(id);
                    }
                }
                serde_json::to_string(&eng.snapshot()).unwrap_or_else(|_| "{}".to_string())
            };
            state.broadcast_snapshot(&snap_json);
            ("200 OK", "application/json", snap_json)
        }

        ("POST", "/api/policy") => {
            let snap_json = {
                let mut eng = state.engine.lock().unwrap();
                if let Ok(v) = serde_json::from_str::<Value>(body) {
                    if let Some(nl) = v.get("nl_text").and_then(|x| x.as_str()) {
                        eng.update_policy_from_nl(nl);
                    }
                }
                serde_json::to_string(&eng.snapshot()).unwrap_or_else(|_| "{}".to_string())
            };
            state.broadcast_snapshot(&snap_json);
            ("200 OK", "application/json", snap_json)
        }

        ("POST", "/api/chaos") => {
            let snap_json = {
                let mut eng = state.engine.lock().unwrap();
                if let Ok(v) = serde_json::from_str::<Value>(body) {
                    if let Some(k) = v.get("kind").and_then(|x| x.as_str()) {
                        eng.trigger_chaos_attack(k);
                    }
                }
                serde_json::to_string(&eng.snapshot()).unwrap_or_else(|_| "{}".to_string())
            };
            state.broadcast_snapshot(&snap_json);
            ("200 OK", "application/json", snap_json)
        }

        ("POST", "/api/killswitch") => {
            let snap_json = {
                let mut eng = state.engine.lock().unwrap();
                if let Ok(v) = serde_json::from_str::<Value>(body) {
                    let disarm = v.get("disarm").and_then(|x| x.as_bool()).unwrap_or(false);
                    eng.toggle_kill_switch(disarm);
                }
                serde_json::to_string(&eng.snapshot()).unwrap_or_else(|_| "{}".to_string())
            };
            state.broadcast_snapshot(&snap_json);
            ("200 OK", "application/json", snap_json)
        }

        ("POST", "/api/quorum/trip") => {
            let snap_json = {
                let mut eng = state.engine.lock().unwrap();
                eng.trip_kill_switch();
                serde_json::to_string(&eng.snapshot()).unwrap_or_else(|_| "{}".to_string())
            };
            state.broadcast_snapshot(&snap_json);
            ("200 OK", "application/json", snap_json)
        }

        ("POST", "/api/quorum/disarm") => {
            let v = serde_json::from_str::<Value>(body).unwrap_or(Value::Null);
            let ids: Vec<u64> = v
                .get("custodian_ids")
                .and_then(|a| a.as_array())
                .map(|arr| arr.iter().filter_map(|x| x.as_u64()).collect())
                .unwrap_or_default();
            let tamper = v.get("tamper_share").and_then(|x| x.as_bool()).unwrap_or(false);
            let (rep, snap_json) = {
                let mut eng = state.engine.lock().unwrap();
                let r = eng.disarm_with_custodians(&ids, tamper);
                let sj = serde_json::to_string(&eng.snapshot()).unwrap_or_else(|_| "{}".to_string());
                (r, sj)
            };
            state.broadcast_snapshot(&snap_json);
            (
                "200 OK",
                "application/json",
                json!({ "quorum": rep, "state": serde_json::from_str::<Value>(&snap_json).unwrap_or(Value::Null) }).to_string(),
            )
        }

        ("GET", "/api/proof/verify") => {
            let id = raw_target
                .split("id=")
                .nth(1)
                .and_then(|s| s.split('&').next())
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or(1);
            let eng = state.engine.lock().unwrap();
            match eng.verify_cryptographic_proof(id) {
                Some(rep) => ("200 OK", "application/json", serde_json::to_string(&rep).unwrap_or_default()),
                None => ("404 Not Found", "application/json", json!({"error": "decision id not found"}).to_string()),
            }
        }

        ("GET", "/api/flight-recorder") => {
            let eng = state.engine.lock().unwrap();
            let rows = eng.dump_flight_recorder(25);
            (
                "200 OK",
                "application/json",
                json!({
                    "total_recorded": eng.flight_recorder.total_recorded(),
                    "records": rows
                })
                .to_string(),
            )
        }

        ("POST", "/api/tax") => {
            let v = serde_json::from_str::<Value>(body).unwrap_or(Value::Null);
            let inc = v.get("annual_income_inr").and_then(|x| x.as_i64()).unwrap_or(1_500_000);
            let ded = v.get("deductions_80c_hra_inr").and_then(|x| x.as_i64()).unwrap_or(200_000);
            let snap_json = {
                let mut eng = state.engine.lock().unwrap();
                eng.update_tax_profile(inc, ded);
                serde_json::to_string(&eng.snapshot()).unwrap_or_else(|_| "{}".to_string())
            };
            state.broadcast_snapshot(&snap_json);
            ("200 OK", "application/json", snap_json)
        }

        ("POST", "/api/chat") => {
            let v = serde_json::from_str::<Value>(body).unwrap_or(Value::Null);
            let q = v.get("question").and_then(|x| x.as_str()).unwrap_or("Summarize my portfolio risk and taxes");
            let reply = state.engine.lock().unwrap().ask_financial_copilot(q);
            ("200 OK", "application/json", serde_json::to_string(&reply).unwrap_or_default())
        }

        ("POST", "/api/reset") => {
            let snap_json = {
                let mut eng = state.engine.lock().unwrap();
                *eng = FinGateAiEngine::new();
                serde_json::to_string(&eng.snapshot()).unwrap_or_else(|_| "{}".to_string())
            };
            state.broadcast_snapshot(&snap_json);
            ("200 OK", "application/json", snap_json)
        }

        // Model Context Protocol (MCP) JSON-RPC 2.0 Tool Server (`POST /mcp`)
        ("POST", "/mcp") => handle_mcp_jsonrpc(state, body),

        _ => (
            "404 Not Found",
            "application/json",
            json!({"error": "endpoint not found", "path": path}).to_string(),
        ),
    }
}

fn handle_mcp_jsonrpc(state: &AppServerState, body: &str) -> (&'static str, &'static str, String) {
    let req = serde_json::from_str::<Value>(body).unwrap_or(Value::Null);
    let id = req.get("id").cloned().unwrap_or(json!(1));
    let method = req.get("method").and_then(|m| m.as_str()).unwrap_or("");

    let result = match method {
        "initialize" => json!({
            "protocolVersion": "2024-11-05",
            "capabilities": { "tools": {} },
            "serverInfo": { "name": "fingate-ai-firewall", "version": "2.0.0" }
        }),
        "tools/list" => json!({
            "tools": [
                {
                    "name": "fingate_submit_paper_order",
                    "description": "Route a paper NSE order through FinGate's 12-stage nanosecond Rust & Silicon Firewall (SHM, Relativistic STP, Hawkes/VPIN, Entropy, NanoPolicyVm, SPAN, FPGA BAR0, OMS, Lattice, HW SHA-256 Merkle).",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "symbol": { "type": "string" },
                            "side": { "type": "string", "enum": ["BUY", "SELL"] },
                            "qty": { "type": "integer" },
                            "price_inr": { "type": "integer" },
                            "is_fno": { "type": "boolean" }
                        },
                        "required": ["symbol", "side", "qty", "price_inr"]
                    }
                },
                {
                    "name": "fingate_compile_policy",
                    "description": "Compile a plain-English risk rule or DSL into formally terminating NanoPolicyVm SIMD bytecode and dry-run across 60 historical NSE ticks.",
                    "inputSchema": {
                        "type": "object",
                        "properties": { "nl_text": { "type": "string" } },
                        "required": ["nl_text"]
                    }
                },
                {
                    "name": "fingate_ask_copilot",
                    "description": "Ask FinGate's grounded NSE financial, risk, and India tax co-pilot with live citations.",
                    "inputSchema": {
                        "type": "object",
                        "properties": { "question": { "type": "string" } },
                        "required": ["question"]
                    }
                },
                {
                    "name": "fingate_get_audit_status",
                    "description": "Fetch live portfolio equity, counterfactual capital saved, Hawkes/VPIN toxicity, Hardware SHA-256 Merkle root, and Post-Quantum Lattice audit state.",
                    "inputSchema": { "type": "object", "properties": {} }
                }
            ]
        }),
        "tools/call" => {
            let params = req.get("params").cloned().unwrap_or(Value::Null);
            let tool = params.get("name").and_then(|x| x.as_str()).unwrap_or("");
            let args = params.get("arguments").cloned().unwrap_or(Value::Null);
            let payload = match tool {
                "fingate_submit_paper_order" => {
                    let (dec, sj) = {
                        let mut eng = state.engine.lock().unwrap();
                        let d = eng.submit_manual_order(
                            args.get("symbol").and_then(|x| x.as_str()).unwrap_or("NIFTY50"),
                            args.get("side").and_then(|x| x.as_str()).unwrap_or("BUY"),
                            args.get("qty").and_then(|x| x.as_i64()).unwrap_or(1),
                            args.get("price_inr").and_then(|x| x.as_i64()).unwrap_or(24_200),
                            args.get("is_fno").and_then(|x| x.as_bool()).unwrap_or(false),
                        );
                        let sj = serde_json::to_string(&eng.snapshot()).unwrap_or_default();
                        (d, sj)
                    };
                    state.broadcast_snapshot(&sj);
                    serde_json::to_string_pretty(&dec).unwrap_or_default()
                }
                "fingate_compile_policy" => {
                    let (pol, sj) = {
                        let mut eng = state.engine.lock().unwrap();
                        eng.update_policy_from_nl(
                            args.get("nl_text").and_then(|x| x.as_str()).unwrap_or(""),
                        );
                        let p = eng.policy_summary.clone();
                        let sj = serde_json::to_string(&eng.snapshot()).unwrap_or_default();
                        (p, sj)
                    };
                    state.broadcast_snapshot(&sj);
                    serde_json::to_string_pretty(&pol).unwrap_or_default()
                }
                "fingate_ask_copilot" => {
                    let rep = state.engine.lock().unwrap().ask_financial_copilot(
                        args.get("question").and_then(|x| x.as_str()).unwrap_or(""),
                    );
                    serde_json::to_string_pretty(&rep).unwrap_or_default()
                }
                _ => {
                    let snap = state.engine.lock().unwrap().snapshot();
                    serde_json::to_string_pretty(&snap.crypto_audit).unwrap_or_default()
                }
            };
            json!({
                "content": [{ "type": "text", "text": payload }]
            })
        }
        _ => json!({ "error": format!("unknown MCP method '{}'", method) }),
    };

    (
        "200 OK",
        "application/json",
        json!({ "jsonrpc": "2.0", "id": id, "result": result }).to_string(),
    )
}
