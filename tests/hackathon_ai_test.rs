//! End-to-End Production Verification Suite for FinGate AI (`tests/hackathon_ai_test.rs`).
//!
//! Certifies the full 12-stage Singularity Rust Firewall + NSE Co-Pilot stack:
//! 1. 5 x 12-tick OHLCV + Microstructure historical NSE tapes (60 bars total) & real MTM PaperPortfolio.
//! 2. Natural-Language & Raw-DSL -> NanoPolicyVm Bytecode Compiler + Real 60-Tick Historical NSE Dry-Run.
//! 3. Full 12-bar counterfactual backtest proving real mark-to-market capital preservation.
//! 4. All 4 distinct adversarial chaos injectors (`fake_news`, `toxic_sweep`, `martingale_loop`, `ftl_spoof`).
//! 5. Interactive 3-of-5 Shamir Secret Sharing over Mersenne F_{2^61-1} (2-of-5 denied, tampered denied, 3-of-5 disarms).
//! 6. Live Hardware SHA-256 Merkle Inclusion + Post-Quantum Ajtai-SIS Lattice Proof Verification + BlackBox Flight Recorder.
//! 7. Manual paper order ticket, grounded AI Financial Co-Pilot, dynamic India Tax/STT engine, and REST/MCP/Prometheus server.

use traffic_gateway::ai::{
    compile_natural_language_policy, compile_natural_language_policy_with_dryrun, FinGateAiEngine,
};
use traffic_gateway::nse::{
    builtin_nse_tapes, compute_india_tax_and_costs, compute_india_tax_and_costs_custom,
    PaperPortfolio,
};
use traffic_gateway::server::{dispatch_api, AppServerState};

#[test]
fn test_nse_tapes_and_real_mtm_paper_portfolio() {
    let tapes = builtin_nse_tapes();
    assert_eq!(tapes.len(), 5);
    let total_ticks: usize = tapes.iter().map(|t| t.ticks.len()).sum();
    assert_eq!(total_ticks, 60, "expected 5 x 12 = 60 historical NSE bars");

    // Verify exact mark-to-market arithmetic & statutory fee deduction (zero fabricated P&L!)
    let mut pf = PaperPortfolio::new(500_000);
    let filled1 = pf.execute_fill("HDFCBANK", true, 10, 1_650, false, false);
    assert_eq!(filled1, 10);
    let fee1 = pf.total_fees_paid_inr;
    assert!(fee1 > 0);
    assert_eq!(pf.cash_available_inr, 500_000 - 16_500 - fee1);
    assert_eq!(pf.unrealized_pnl_inr(), 0);

    // Price rallies +₹50/sh -> real unrealized MTM = +₹500
    pf.mark_to_market("HDFCBANK", 1_700);
    assert_eq!(pf.unrealized_pnl_inr(), 500);
    assert_eq!(pf.total_equity_inr(), 500_000 - fee1 + 500);

    // Partial sell realizes exact half (+₹250 gross realized; equity reflects exact total fees)
    let filled2 = pf.execute_fill("HDFCBANK", false, 5, 1_700, false, false);
    assert_eq!(filled2, 5);
    assert_eq!(pf.realized_pnl_inr, 250);
    assert_eq!(pf.unrealized_pnl_inr(), 250);
    assert_eq!(pf.total_equity_inr(), 500_000 + 500 - pf.total_fees_paid_inr);
}

#[test]
fn test_nl_and_raw_dsl_compiler_with_60_tick_historical_dryrun() {
    let tapes = builtin_nse_tapes();

    // 1. Plain-English compilation + real 60-tick dry-run
    let (prog, summary) = compile_natural_language_policy_with_dryrun(
        7,
        "Max ₹28,000 per trade, max 90 quantity, block buys when Hawkes > 115000 and VPIN > 6800, halt if SPAN crash loss > ₹45,000",
        &tapes,
    );
    assert_eq!(prog.len, 4);
    assert_eq!(summary.max_notional_inr, 28_000);
    assert_eq!(summary.max_qty, 90);
    assert_eq!(summary.max_vpin_e4, 6_800);
    assert_eq!(summary.max_span_loss_inr, 45_000);
    assert_eq!(summary.dry_run_total_ticks, 60);
    assert!(
        summary.dry_run_traps_caught >= 8,
        "expected >= 8 historical traps caught across 60 NSE ticks, got {}",
        summary.dry_run_traps_caught
    );

    // 2. Backwards-compatible wrapper still compiles cleanly
    let (prog2, sum2) = compile_natural_language_policy(
        8,
        "IF NOTIONAL > 40000 THEN REJECT 101\nIF QTY > 120 THEN REJECT 104",
    );
    assert_eq!(prog2.len, 4);
    assert_eq!(sum2.max_notional_inr, 40_000);
    assert_eq!(sum2.max_qty, 120);
}

#[test]
fn test_production_12_stage_firewall_backtest_chaos_shamir_crypto_and_server() {
    let mut eng = FinGateAiEngine::new();
    let s0 = eng.snapshot();
    assert_eq!(s0.approved_count, 1);
    assert_eq!(s0.blocked_count, 0);
    assert_eq!(s0.fpga_bar0.clock_mhz, 400);
    assert_eq!(s0.fpga_bar0.pipeline_cycles, 4);
    assert!(s0.crypto_audit.lattice_sis_verified);

    // 1. Full 12-bar counterfactual backtest on Expiry-Day HFT Toxic Sweep
    eng.select_tape("expiry_toxic_sweep");
    let bt = eng.run_full_tape_backtest();
    assert_eq!(bt.ticks_replayed, 12);
    assert!(bt.blocked_trades >= 3);
    assert!(
        bt.protected_final_equity_inr > bt.unguarded_final_equity_inr,
        "protected equity {} must beat unguarded equity {}",
        bt.protected_final_equity_inr,
        bt.unguarded_final_equity_inr
    );

    // 2. Attack 1: Prompt-injected fake news (500 Nifty lots = ₹1.21 Crore) -> Blocked + Kill Switch tripped
    eng.trigger_chaos_attack("fake_news");
    let d1 = eng.snapshot().recent_decisions[0].clone();
    assert!(!d1.approved);
    assert!(d1.gate_triggered.contains("NanoPolicyVm"));
    assert!(eng.snapshot().kill_switch_active);

    // 3. Interactive 3-of-5 Shamir Secret Sharing over Mersenne F_{2^61-1}
    let fail_2of5 = eng.disarm_with_custodians(&[1, 2], false);
    assert!(!fail_2of5.success, "2-of-5 shares must NEVER disarm");
    assert!(eng.snapshot().kill_switch_active);

    let fail_tamper = eng.disarm_with_custodians(&[1, 3, 5], true);
    assert!(!fail_tamper.success, "tampered share must NEVER disarm");
    assert!(eng.snapshot().kill_switch_active);

    let ok_3of5 = eng.disarm_with_custodians(&[1, 3, 5], false);
    assert!(ok_3of5.success, "valid 3-of-5 shares must disarm");
    assert!(!eng.snapshot().kill_switch_active);

    // 4. Attack 2: Expiry-day HFT toxic sweep -> Blocked by Hawkes + VPIN shield
    eng.trigger_chaos_attack("toxic_sweep");
    let d2 = eng.snapshot().recent_decisions[0].clone();
    assert!(!d2.approved);
    assert!(
        d2.gate_triggered.contains("Hawkes") || d2.gate_triggered.contains("VPIN"),
        "expected Hawkes/VPIN block, got: {}",
        d2.gate_triggered
    );

    // 5. Attack 3: AI reconnect amnesia loop -> Blocked by Shannon Entropy Sentinel
    let _ = eng.disarm_with_custodians(&[1, 2, 4], false);
    eng.trigger_chaos_attack("martingale_loop");
    let d3 = eng.snapshot().recent_decisions[0].clone();
    assert!(!d3.approved);
    assert!(
        d3.gate_triggered.contains("Entropy"),
        "expected Entropy Sentinel block, got: {}",
        d3.gate_triggered
    );

    // 6. Attack 4: Relativistic Speed-of-Light Causality Violation (SG1 -> Mumbai NSE)
    let _ = eng.disarm_with_custodians(&[2, 3, 5], false);
    eng.trigger_chaos_attack("ftl_spoof");
    let d4 = eng.snapshot().recent_decisions[0].clone();
    assert!(!d4.approved);
    assert!(
        d4.gate_triggered.contains("Relativistic"),
        "expected Relativistic Causality block, got: {}",
        d4.gate_triggered
    );

    // 7. Live Hardware SHA-256 Merkle + Post-Quantum Ajtai-SIS Lattice Proof Verification
    let proof = eng
        .verify_cryptographic_proof(d4.id)
        .expect("stored proof for recent decision");
    assert!(proof.merkle_proof_valid);
    assert!(proof.lattice_sis_valid);

    // 8. Crash-surviving MAP_SHARED BlackBox Flight Recorder dump
    let bb = eng.dump_flight_recorder(8);
    assert!(eng.flight_recorder.total_recorded() >= 10);
    assert!(!bb.is_empty());

    // 9. Manual Paper Order Ticket (safe trade passes, oversized breaches NanoPolicyVm)
    let safe_ord = eng.submit_manual_order("NIFTYBEES", "BUY", 40, 265, false);
    assert!(safe_ord.approved);
    let risky_ord = eng.submit_manual_order("NIFTY50", "BUY", 50, 24_200, true);
    assert!(!risky_ord.approved);

    // 10. Grounded Financial Co-Pilot (zero-key deterministic citation mode)
    let copilot = eng.ask_financial_copilot("Explain my LTCG tax and how 3-of-5 Shamir works");
    assert!(!copilot.answer.is_empty());
    assert!(!copilot.citations.is_empty());

    // 11. Dynamic India Tax & Statutory Cost Calculator
    let tax_default = compute_india_tax_and_costs(500_000, 180_000, 5);
    assert_eq!(tax_default.brokerage_inr, 100);
    assert!(tax_default.stt_inr > 0);
    assert!(tax_default.stcg_20pct_tax_inr > tax_default.ltcg_12_5pct_tax_inr);
    assert!(tax_default.new_regime_tax_for_15l_income < tax_default.old_regime_tax_for_15l_income);

    let tax_custom = compute_india_tax_and_costs_custom(750_000, 250_000, 8, 2_400_000, 350_000);
    assert_eq!(tax_custom.annual_income_inr, 2_400_000);
    assert_eq!(tax_custom.deductions_80c_hra_inr, 350_000);
    assert!(tax_custom.new_regime_tax_for_15l_income > 0);

    // 12. Production REST, Prometheus /metrics, Kubernetes /healthz, and MCP JSON-RPC 2.0 Server
    let state = AppServerState::new("<html>ok</html>");
    let (st_h, _, body_h) = dispatch_api(&state, "GET", "/healthz", "/healthz", "");
    assert_eq!(st_h, "200 OK");
    assert!(body_h.contains("\"status\":\"UP\""));

    let (st_r, _, body_r) = dispatch_api(&state, "GET", "/readyz", "/readyz", "");
    assert_eq!(st_r, "200 OK");
    assert!(body_r.contains("\"ready\":true"));

    let (st_m, _, body_m) = dispatch_api(&state, "GET", "/metrics", "/metrics", "");
    assert_eq!(st_m, "200 OK");
    assert!(body_m.contains("fingate_orders_approved_total"));
    assert!(body_m.contains("fingate_protected_equity_inr"));

    let (st_mcp1, _, body_mcp1) = dispatch_api(
        &state,
        "POST",
        "/mcp",
        "/mcp",
        r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#,
    );
    assert_eq!(st_mcp1, "200 OK");
    assert!(body_mcp1.contains("fingate_submit_paper_order"));
    assert!(body_mcp1.contains("fingate_compile_policy"));
    assert!(body_mcp1.contains("fingate_ask_copilot"));
    assert!(body_mcp1.contains("fingate_get_audit_status"));

    let (st_mcp2, _, body_mcp2) = dispatch_api(
        &state,
        "POST",
        "/mcp",
        "/mcp",
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"fingate_submit_paper_order","arguments":{"symbol":"NIFTYBEES","side":"BUY","qty":20,"price_inr":265,"is_fno":false}}}"#,
    );
    assert_eq!(st_mcp2, "200 OK");
    assert!(body_mcp2.contains("approved") && body_mcp2.contains("true"));
}
