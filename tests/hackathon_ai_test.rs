//! End-to-End Hackathon Verification Suite for FinGate AI (`tests/hackathon_ai_test.rs`).

use traffic_gateway::ai::{compile_natural_language_policy, FinGateAiEngine};
use traffic_gateway::nse::{builtin_nse_tapes, compute_india_tax_and_costs};

#[test]
fn test_fingate_ai_nse_tapes_policy_compiler_chaos_and_india_tax() {
    // 1. Verify all 5 NSE historical tapes load cleanly
    let tapes = builtin_nse_tapes();
    assert_eq!(tapes.len(), 5);

    // 2. Verify Natural-Language -> NanoPolicyVm Bytecode Compiler
    let (prog, summary) = compile_natural_language_policy(
        7,
        "Max ₹28,000 per trade, max 90 quantity, block buys when Hawkes > 115000 and VPIN > 6800, halt if SPAN crash loss > ₹45,000",
    );
    assert_eq!(prog.len, 4);
    assert_eq!(summary.max_notional_inr, 28_000);
    assert_eq!(summary.max_qty, 90);
    assert_eq!(summary.max_vpin_e4, 6_800);
    assert_eq!(summary.max_span_loss_inr, 45_000);

    // 3. Verify End-to-End Engine: clean RBI trade passes, Chaos attacks are blocked in nanoseconds
    let mut eng = FinGateAiEngine::new();
    let s0 = eng.snapshot();
    assert_eq!(s0.approved_count, 1);
    assert_eq!(s0.blocked_count, 0);

    // Attack 1: Prompt-injected fake news (500 Nifty lots = ₹1.21 Crore) -> Blocked + Kill Switch tripped
    eng.trigger_chaos_attack("fake_news");
    let s1 = eng.snapshot();
    assert_eq!(s1.blocked_count, 1);
    assert!(!s1.recent_decisions[0].approved);
    assert!(s1.kill_switch_active);
    assert!(s1.total_capital_saved_inr >= 45_000);

    // Disarm via 3-of-5 Shamir Secret Sharing over Mersenne F_{2^61-1}
    eng.toggle_kill_switch(true);
    assert!(!eng.snapshot().kill_switch_active);

    // Attack 2: Expiry-day HFT toxic sweep -> Blocked by Hawkes + VPIN shield
    eng.trigger_chaos_attack("toxic_sweep");
    let s2 = eng.snapshot();
    assert_eq!(s2.blocked_count, 2);
    assert!(!s2.recent_decisions[0].approved);

    // Attack 3: AI reconnect amnesia loop -> Blocked by Shannon Entropy Sentinel
    eng.toggle_kill_switch(true);
    eng.trigger_chaos_attack("martingale_loop");
    let s3 = eng.snapshot();
    assert_eq!(s3.blocked_count, 3);
    assert!(!s3.recent_decisions[0].approved);

    // 4. Verify India STT, GST, Brokerage & STCG/LTCG/Regime Tax Engine
    let tax = compute_india_tax_and_costs(500_000, 180_000, 5);
    assert_eq!(tax.brokerage_inr, 100);
    assert!(tax.stt_inr > 0);
    assert!(tax.stcg_20pct_tax_inr > tax.ltcg_12_5pct_tax_inr);
    assert!(tax.new_regime_tax_for_15l_income < tax.old_regime_tax_for_15l_income);
}
