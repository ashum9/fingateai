# FinGate AI (`fingateAI`)

**Neuro-Symbolic NSE Market Co-Pilot, Historical Event Backtester & 111-Nanosecond Rust Paper-Trading Firewall**

> **Theme:** AI for Finance  
> **Data & Safety Compliance:** 100% Historical NSE Market Tapes & Local Paper Trading (`₹5,00,000` virtual portfolio). Zero real money, zero live broker API keys, zero personal PII.

---

## 1. The Problem We Solve

Retail investors and algorithmic desks are rapidly adopting AI agents to analyze financial news, company filings, and NSE price action. However:
1. **SEBI Studies Show 9 out of 10 Traders Lose Money** to over-sizing, expiry-day HFT volatility sweeps, and hidden statutory friction (STT, GST, stamp duty, and short-term tax drag).
2. **Raw AI Agents Hallucinate Under Market Stress:** A single fake viral news headline, prompt injection, or WebSocket disconnect can cause an unguarded LLM trading bot to fire a catastrophic leveraged order and wipe out an account in seconds.

**FinGate AI** separates **Market Intelligence (AI)** from **Capital Survival (Deterministic Rust & Silicon)**:
* **The AI Co-Pilot** reads RBI monetary policy circulars, Union Budget announcements, company filings, and historical NSE tapes to propose paper trades, explain portfolio crash risk, and optimize Indian taxes.
* **The FinGate Rust & Silicon Firewall** sits between the AI and the paper exchange—verifying every trade in **single-digit to 111 nanoseconds** (`0 bytes` heap allocation) and blocking hallucinations, fake-news scams, and toxic flash crashes before a single rupee is lost.

---

## 2. One-Command Quickstart

### Start the Interactive 3-Column Web Command Center (`http://127.0.0.1:8080`)
```bash
cargo run --release --bin fingate_ai
```
Then open **[http://127.0.0.1:8080](http://127.0.0.1:8080)** in your browser.

### Run the Headless End-to-End Self-Test & Verification Suite
```bash
cargo run --release --bin fingate_ai -- --self-test
cargo test --test hackathon_ai_test
```

---

## 3. How the Single-Screen 3-Column Dashboard Works

```text
+---------------------------------------------------------------------------------------------------+
|  FINGATE AI — NSE Paper Portfolio: ₹5,00,000   |   Money Saved by Firewall: ₹4,85,000   | [KILL]  |
+-------------------------------+-----------------------------------+-------------------------------+
| 1. LEFT: NSE MARKET & NEWS    | 2. MIDDLE: AI BOT & YOUR RULES    | 3. RIGHT: FINGATE FIREWALL    |
|                               |                                   |                               |
| • 5 Historical NSE Tapes:     | • Plain-English Money Rules ->    | • Live Rust & Silicon Meters: |
|   1. RBI Surprise Rate Cut    |   Compiled to 4.7ns Loop-Free     |   - Hawkes Cascade Intensity  |
|   2. Expiry HFT Toxic Sweep   |   NanoPolicyVm Bytecode           |   - VPIN Flow Toxicity        |
|   3. Union Budget & Tax Shock |                                   |   - Shannon AI Entropy        |
|   4. Fake-News Prompt Scam    | • 3 Judge Chaos Attack Buttons:   |   - 3-of-5 Shamir Quorum      |
|   5. Smart SIP & Crash Hedge  |   [Inject Fake News Scam]         |   - Hardware SHA-256 Merkle   |
| • Live Price Chart & Filings  |   [Trigger Expiry Toxic Dump]     |   - Post-Quantum Lattice Vault|
| • 6-Shockwave Crash Simulator |   [Trigger AI Amnesia Loop]       | • 3-Sec AI Forensic Verdicts  |
|   (-10% to -30% 16-Pt SPAN)   | • India STT, GST & Tax Regime     |   & Exact "₹ Saved" Counter   |
+-------------------------------+-----------------------------------+-------------------------------+
```

---

## 4. Core Technical Innovations Inside `fingateAI`

| Subsystem | Innovation | Live Measured Spec | Source |
| :--- | :--- | :--- | :--- |
| **Plain-English → `NanoPolicyVm` Compiler** | Compiles natural-language user rules into a formally terminating (`<= 32` instructions, 8 registers, loop-free) bytecode VM with SIMD predicate lowering. | **`1.2 – 4.72 ns/order`** (`0 B` alloc) | [`src/horizon/nano_policy_vm.rs`](src/horizon/nano_policy_vm.rs) · [`src/ai/mod.rs`](src/ai/mod.rs) |
| **Hawkes Point-Process + VPIN Toxicity Shield** | Recursive exponential Hawkes self-excitation + 16-bucket VPIN order-flow toxicity (`0` floats) detecting expiry-day HFT dumps early. | **`2.85 ns/tick`** (`0 B` alloc) | [`src/horizon/hawkes_shield.rs`](src/horizon/hawkes_shield.rs) |
| **Shannon Entropy AI-Hallucination Sentinel** | 64-event sliding-window exact Shannon entropy (`TERM_E4_LUT`) catching stuck LLM retry loops and buy/sell oscillation. | **`2.90 ns/order`** (`0 B` alloc) | [`src/frontier/entropy_sentinel.rs`](src/frontier/entropy_sentinel.rs) |
| **16-Pt SIMD SPAN + 6-Shockwave Shadow Fork** | Evaluates portfolio Delta/Gamma/Vega and 16-scenario SPAN margin across 6 simultaneous flash-crash shockwaves (`-10%` to `-30%`). | **`5.70 ns/fork`** (`0 B` alloc) | [`src/frontier/shadow_fork.rs`](src/frontier/shadow_fork.rs) · [`src/risk/portfolio_greeks.rs`](src/risk/portfolio_greeks.rs) |
| **Asymmetric 1-of-5 Trip / 3-of-5 Shamir Disarm** | Instant 1-of-5 atomic kill switch (`0.78 ns`) paired with 3-of-5 Shamir Secret Sharing over Mersenne Prime $\mathbb{F}_{2^{61}-1}$ (Montgomery batch inversion + optimal 70-mul addition chain). | **`0.78 ns` trip / `136 ns` Shamir** | [`src/horizon/threshold_quorum.rs`](src/horizon/threshold_quorum.rs) |
| **Hardware Silicon SHA-256 Merkle + Post-Quantum Lattice Audit Vault** | `ARMv8 FEAT_SHA256` / `x86 SHA-NI` 64-leaf Merkle proofs + 4-lane SIMD Ajtai/Module-SIS Lattice additively homomorphic exposure commitments. | **`1.42 µs` 64-leaf Merkle seal** | [`src/attestation/mod.rs`](src/attestation/mod.rs) · [`src/horizon/oblivious_vault.rs`](src/horizon/oblivious_vault.rs) |
| **400 MHz 4-Cycle SystemVerilog FPGA Gatekeeper** | Synthesizable RTL pre-trade risk gatekeeper (`10.0 ns` @ 400 MHz) with C++17 10,000-vector bit-exact equivalence testbench. | **`4 cycles = 10.0 ns`** | [`hw/fpga_gatekeeper/gatekeeper.sv`](hw/fpga_gatekeeper/gatekeeper.sv) |
