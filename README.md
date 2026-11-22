# FinGate AI — Production NSE Market Co-Pilot & 12-Stage Singularity Rust Firewall

> **Safety & Compliance Notice:** 100% Historical/Curated NSE Market Event Tapes & Local Paper Trading Only (`₹5,00,000` virtual capital). Zero real-money execution, zero live broker credentials, zero external network dependencies required (optional `GEMINI_API_KEY` for live LLM narrative on top of the built-in grounded citation engine).

**FinGate AI** pairs an interactive Indian NSE retail & institutional market co-pilot with the full **FinGate Track A–I Singularity** nanosecond execution firewall (`src/singularity/`, `src/horizon/`, `src/frontier/`, `src/risk/`, `src/oms/`, `src/attestation/`, `src/ipc/`, `src/hw_sync/`, and 400 MHz SystemVerilog `hw/fpga_gatekeeper/gatekeeper.sv`).

Every order — whether replayed from the 5 × 12-tick NSE historical tapes, typed into the Paper Order Ticket, injected by the 4 adversarial Chaos Attack buttons, or submitted by an external AI agent over **MCP JSON-RPC 2.0 (`POST /mcp`)** — traverses all **12 real zero-allocation Rust & Silicon defense stages** before hitting the real mark-to-market paper ledger.

---

## 1. Quickstart (1 Command)

```bash
cd /Users/ashum9/projects/fingateAI
cargo run --release --bin fingate_ai
```

Then open **`http://127.0.0.1:8080`** in your browser.
- Override port: `PORT=9090 cargo run --release --bin fingate_ai`
- Optional live LLM co-pilot mode: `GEMINI_API_KEY=... cargo run --release --bin fingate_ai` (works 100% offline with built-in grounded citation engine when unset)

### Headless Certification & Benchmarks

```bash
# 1. Full 10-gate production self-test (60-tick NSE dry-run, Tape 2 backtest, 4 Chaos attacks,
#    2-of-5/tampered/3-of-5 Shamir proof, HW SHA-256 Merkle + PQ Lattice verifier, MCP API)
cargo run --release --offline --bin fingate_ai -- --self-test

# 2. Full Track I Singularity silicon & micro-architecture certifier (200k-order hot path)
cargo run --release --offline --bin fingate_singularity_gate

# 3. Complete offline test suite (unit tests + hackathon_ai_test + track_i_singularity_test + 34/34 zero-alloc hot paths)
cargo test --offline
```

---

## 2. Production 12-Stage Firewall Architecture

| Stage | Subsystem (`src/`) | What It Enforces Live |
| :--- | :--- | :--- |
| **1. SHM Ingress** | `FastStampedShmChannel` (`src/ipc/shm_channel.rs`) | 128-byte cache-line isolated Single-MESI sequence-stamped POSIX `MAP_SHARED` ring (`FGSHM002`). |
| **2. 1-of-5 Halt & 3-of-5 Shamir Disarm** | `ThresholdQuorumGuard` (`src/horizon/quorum_guard.rs`) | 1-of-5 instant kill switch (`SeqCst`); disarm requires 3-of-5 Lagrange interpolation over Mersenne $\mathbb{F}_{2^{61}-1}$ + constant-time HW HMAC-SHA256. |
| **3. Relativistic Causality** | `RelativisticRaceGuard` (`src/horizon/relativistic_guard.rs`) | Speed-of-light fiber transit check (`SG1 ↔ Mumbai NSE` physical floor) blocking spoofed/back-dated cross-venue packets. |
| **4. Toxic Flow & VPIN** | `HawkesToxicFlowShield` (`src/frontier/hawkes_shield.rs`) | Fixed-point Hawkes self-exciting point process + bucketed VPIN catching expiry-day HFT "Two-Patch" waterfalls. |
| **5. AI Hallucination Sentinel** | `OrderFlowEntropySentinel` (`src/horizon/entropy_sentinel.rs`) | Shannon entropy collapse detector auto-tripping the kill switch on stuck AI reconnect/martingale retry loops. |
| **6. Neuro-Symbolic Policy VM** | `NanoPolicyVm` (`src/frontier/policy_vm.rs`) | Compiles plain English or raw `REJECT ...` DSL into formally terminating SIMD bytecode + runs a **real 60-tick historical NSE dry-run**. |
| **7. Pre-Trade Risk & STP** | `PreTradeRiskEngine` (`src/risk/engine.rs`) | Credit limits, GCRA rate limiter, price collars, self-trade prevention, and O(1) slot reclamation. |
| **8. 16-Point SIMD SPAN** | `PortfolioGreeksEngine` (`src/risk/portfolio_greeks.rs`) | Live 16-scenario portfolio Delta/Gamma/Vega & worst-case SPAN tail-loss stress engine + 6-scenario Shadow Fork shockwaves. |
| **9. 400 MHz FPGA BAR0 Mirror** | `FpgaBar0Registers` + `FpgaEdgeGatekeeperModel` (`src/hw_sync/bar0.rs`, `hw/fpga_gatekeeper/gatekeeper.sv`) | Tear-free seqlock BAR0 risk registers mirroring the 4-cycle (`10 ns`) Alveo U50/U250 SystemVerilog gatekeeper. |
| **10. 64B Fibonacci OMS FSM** | `OrderLifecycleFsm` (`src/oms/fsm.rs`) | Single-cache-line Fibonacci-hashed order state machine with strict fill & slot reclamation. |
| **11. Post-Quantum Lattice Vault** | `ObliviousTelemetryVault` (`src/horizon/oblivious_vault.rs`) | Post-Quantum SIMD Ajtai-SIS Lattice homomorphic exposure commitment ($\mathbb{Z}_q^4$) + $\varepsilon$-differential privacy noise. |
| **12. HW SHA-256 Merkle + Flight Recorder + WAL** | `InlineMerkleProofEngine`, `BlackBoxFlightRecorder`, `AsyncGroupCommitWal` | Hardware `ARMv8 FEAT_SHA256` / `x86 SHA-NI` Merkle inclusion proofs, crash-surviving `MAP_SHARED` flight recorder, and async CRC32C WAL. |

---

## 3. Live Verified Numbers (Apple M4, `--release --offline`)

### A. Production `fingate_ai --self-test` (All 10 Gates Passed)
- **Hardware Acceleration:** `ARMv8-A FEAT_SHA256 Silicon` active; FPGA BAR0 `400 MHz / 4 cycles (10 ns)` synced dynamically on policy compile.
- **Real 60-Tick Historical NSE Dry-Run:** `25 µs` — caught **`10/10`** historical traps (`44` allowed, `16` blocked) across all 5 × 12-bar NSE tapes.
- **Tape 2 (`expiry_toxic_sweep`) Real MTM Backtest:** `193 µs` — Protected Equity **`₹4,99,945`** vs. Unguarded AI **`₹4,87,597`** → **`₹12,348`** real mark-to-market capital preserved (`6` approved, `6` blocked).
- **4 Distinct Chaos Injectors Blocked Live:**
  1. `fake_news` (₹1.21 Cr prompt-injected Nifty order) → Blocked by `NanoPolicyVm [PC#0 Code 101]` + auto-tripped 1-of-5 Kill Switch & FPGA BAR0 Kill Bit.
  2. `toxic_sweep` (Expiry-day Patch II dump) → Blocked by `Hawkes Self-Exciting Point Process + VPIN Cascade Shield`.
  3. `martingale_loop` (64 duplicate AI retries) → Blocked by `Shannon Entropy AI-Hallucination Sentinel` + auto-tripped Kill Switch.
  4. `ftl_spoof` (`0.2 ms` SG1 → Mumbai NSE spoof) → Blocked by `Relativistic Speed-of-Light Causality Guard`.
- **Interactive 3-of-5 Shamir $\mathbb{F}_{2^{61}-1}$ Disarm:** `2-of-5` DENIED, tampered 3rd share DENIED, valid `3-of-5` DISARMED in **`750 ns`**.
- **Cryptographic Proof Verifier:** HW SHA-256 Merkle inclusion VALID (`1,000 ns`) | Post-Quantum Ajtai-SIS Lattice aggregate VALID (`792 ns`).

### B. Track I Singularity Core (`fingate_singularity_gate`)
- **200,000-Order Full 12-Stage Hot Path:** `200,000/200,000` approved | **`p50 42 ns`** | **`p90 84 ns`** | **Mean `160.9 ns`** | `3,156` Merkle roots sealed | **`0` heap allocations (`34/34` zero-alloc checks passing)**.
- **SIMD Risk & Policy:** NEON `vmull` + Hillis-Steele Risk **`0.81 ns/order`** (`1.229B checks/sec` on 1 core) | SIMD `NanoPolicyVm` **`1.08 ns/order`** (`924.0M/s`).
- **128B Single-MESI SHM Cross-Thread:** **`33.7 ns`** one-way (`67.5 ns` RTT).
- **Post-Quantum Ajtai-SIS Lattice Commit:** **`8.03 ns/order`** (`124.5M/s`).

---

## 4. Production Server API (Async Multi-Client `tokio` HTTP/1.1 + SSE + MCP)

| Endpoint | Method | Purpose |
| :--- | :--- | :--- |
| `/` | `GET` | Single-screen Bloomberg-grade Interactive Web Command Center (`ui/index.html`) |
| `/api/stream` | `GET` | Real-time **Server-Sent Events (SSE)** live snapshot broadcast |
| `/mcp` | `POST` | **Model Context Protocol (JSON-RPC 2.0)** tool server (`fingate_submit_paper_order`, `fingate_compile_policy`, `fingate_ask_copilot`, `fingate_get_audit_status`) |
| `/metrics` | `GET` | Prometheus text exposition (`fingate_orders_approved_total`, equity, Hawkes/VPIN, entropy, kill switch) |
| `/healthz`, `/readyz` | `GET` | Kubernetes liveness & readiness probes (`503` when kill switch tripped) |
| `/api/state`, `/api/step`, `/api/backtest`, `/api/tape` | `GET`/`POST` | Historical 5 × 12-tick OHLCV NSE replay & real MTM counterfactual backtest |
| `/api/order`, `/api/policy`, `/api/chaos` | `POST` | Live manual order ticket, Plain-English/DSL compiler + 60-tick dry-run, 4 chaos injectors |
| `/api/quorum/trip`, `/api/quorum/disarm` | `POST` | Interactive 1-of-5 trip & 3-of-5 Shamir custodian disarm (supports tamper simulation) |
| `/api/proof/verify`, `/api/flight-recorder` | `GET` | On-demand HW SHA-256 Merkle + PQ Lattice verifier & crash-surviving `MAP_SHARED` event dump |
| `/api/tax`, `/api/chat`, `/api/reset` | `POST` | Dynamic India Tax/STT/STCG/LTCG calculator, grounded Financial Co-Pilot, clean reset |

---

## 5. Historical NSE Event Tapes (5 × 12 Bars = 60 Ticks)

1. **`rbi_mpc_shock`** — RBI Surprise Repo Cut & CRR Boost (`HDFCBANK` / `BANKNIFTY`)
2. **`expiry_toxic_sweep`** — Weekly Expiry-Day HFT "Two-Patch" Toxic Sweep (`NIFTY50`)
3. **`union_budget_tax`** — Union Budget Capex & STCG/LTCG Tax Shock (`RELIANCE` / `TCS`)
4. **`fake_news_attack`** — Adversarial Deepfake / Prompt-Injection Trap (`NIFTY50` / `BANKNIFTY`)
5. **`sip_portfolio_guide`** — Smart SIP, Crash-Hedge & Tax-Aware Investing (`NIFTYBEES` / `GOLDBEES`)
