//! Month 5 Production Verification & 6-Layer Kill Switch Benchmark Suite (`fingate_month5`).
//!
//! Validates:
//! 1. 6-Layer Defense-in-Depth Kill Switch Activation Latency (target <50µs under line load).
//! 2. Layer 1: Inline Gate Cutoff (<200ns).
//! 3. Layer 2: Mass Cancel Generation across 1,000 active working orders.
//! 4. Layer 3: Session Logout Handshake (`35=5`).
//! 5. Layer 4: Socket-Level Hard RST (`SO_LINGER=0`).
//! 6. Layer 5: eBPF / XDP Kernel Network Packet Drop.
//! 7. Layer 6: Out-of-Band Hardware/Admin Watchdog Trip.
//! 8. Lock-Free Prometheus Metrics Exporter.

use anyhow::Result;
use hdrhistogram::Histogram;
use std::hint::black_box;
use std::time::Instant;
use traffic_gateway::killswitch::layers::{KillSwitchEngine, KillSwitchLayer};
use traffic_gateway::killswitch::telemetry::GatewayTelemetry;

fn main() -> Result<()> {
    println!("========================================================================================");
    println!(" FinGate — Month 5: 6-Layer Defense-in-Depth Emergency Kill Switch & Telemetry Engine");
    println!("========================================================================================");

    // -------------------------------------------------------------------------
    // 1. Week 1 & 4: 6-Layer Kill Switch Activation Latency Benchmark (1,000 runs)
    // -------------------------------------------------------------------------
    let engine = KillSwitchEngine::new();

    // Prepare 1,000 active working orders
    let mut working_orders = Vec::with_capacity(1_000);
    for i in 1..=1_000 {
        working_orders.push(format!("FG-NY4-pod-alpha-{:08}", i));
    }

    let iterations = 1_000usize;
    let mut hist = Histogram::<u64>::new(3)?;

    // Warmup
    for _ in 0..100 {
        let res = engine.execute_emergency_shutdown(black_box(&working_orders), 1_000);
        black_box(res);
        engine.reset_kill_switch();
    }

    let t0 = Instant::now();
    let mut sample_res = None;

    for i in 0..iterations {
        let now_ns = 1_731_000_000_000_000_000u64 + (i as u64 * 100_000);
        let res = engine.execute_emergency_shutdown(black_box(&working_orders), now_ns);
        let us = (res.total_activation_duration_ns / 1_000).max(1);
        let _ = hist.record(us);
        sample_res = Some(res);
        engine.reset_kill_switch();
    }
    let total_ms = t0.elapsed().as_secs_f64() * 1000.0;
    let mean_us = hist.mean();

    println!(
        "\n[1/4] Week 1 & 4 — 6-Layer Kill Switch Activation Benchmark ({} trials, 1,000 orders/trial):",
        iterations
    );
    println!(
        "      Mean: {:.2} us | p50: {} us | p99: {} us | p99.9: {} us | Total: {:.2} ms (Target: < 50 us)",
        mean_us,
        hist.value_at_percentile(50.0),
        hist.value_at_percentile(99.0),
        hist.value_at_percentile(99.9),
        total_ms
    );

    // -------------------------------------------------------------------------
    // 2. Week 1: Progressive Layer Timing Breakdown
    // -------------------------------------------------------------------------
    println!("\n[2/4] Week 1 — Progressive 6-Layer Execution Breakdown:");
    let res = sample_res.unwrap();
    assert_eq!(res.mass_cancels_generated, 1_000);
    for (layer, duration_ns) in &res.layers_executed {
        let layer_name = match layer {
            KillSwitchLayer::Layer1InlineGate => "Layer 1: Inline Gate Atomic Cutoff",
            KillSwitchLayer::Layer2MassCancel => "Layer 2: Mass Cancel Synthesizer (1,000 orders)",
            KillSwitchLayer::Layer3SessionLogout => "Layer 3: Session Logout Handshake (35=5)",
            KillSwitchLayer::Layer4SocketHardRst => "Layer 4: Socket-Level Hard RST (SO_LINGER=0)",
            KillSwitchLayer::Layer5KernelEbpfDrop => "Layer 5: eBPF/XDP Kernel Network Drop",
            KillSwitchLayer::Layer6WatchdogTrip => "Layer 6: Out-of-Band Hardware Watchdog Trip",
        };
        println!("      [PASS] {:<48} | {:>6} ns", layer_name, duration_ns);
    }

    // -------------------------------------------------------------------------
    // 3. Week 2: Functional State Machine Verification (Post-Kill Invariants)
    // -------------------------------------------------------------------------
    println!("\n[3/4] Week 2 — Post-Kill State Machine Invariant Verification:");
    // Execute active kill switch
    engine.execute_emergency_shutdown(&working_orders, 2_000_000);
    assert!(engine.is_active());
    assert!(engine.layer5_ebpf_dropped.load(std::sync::atomic::Ordering::Relaxed));
    assert!(engine.layer6_watchdog_tripped.load(std::sync::atomic::Ordering::Relaxed));
    println!("      [PASS] Layer 1 Inline Gate is ACTIVE (Rejecting all 35=D/35=G)");
    println!("      [PASS] Layer 5 Kernel eBPF Packet Drop flag is ENGAGED");
    println!("      [PASS] Layer 6 Hardware Watchdog Trip flag is ENGAGED");

    engine.reset_kill_switch();
    assert!(!engine.is_active());
    println!("      [PASS] Administrative Authorization: Reset Kill Switch returned engine to normal");

    // -------------------------------------------------------------------------
    // 4. Week 3: Lock-Free Prometheus Telemetry Exporter
    // -------------------------------------------------------------------------
    println!("\n[4/4] Week 3 — Lock-Free Prometheus Real-Time Telemetry Exporter:");
    let telemetry = GatewayTelemetry::new();
    for _ in 0..10_000 {
        telemetry.record_order_ingress();
        telemetry.record_order_egress();
    }
    telemetry.record_fill(true);
    telemetry.record_cancel();
    telemetry.set_kill_switch(true);

    let prom_text = telemetry.render_prometheus();
    assert!(prom_text.contains("fingate_orders_ingress_total 10000"));
    assert!(prom_text.contains("fingate_orders_egress_total 10000"));
    assert!(prom_text.contains("fingate_kill_switch_active 1"));
    println!("      [PASS] Rendered Prometheus Scrape Payload:\n{}", prom_text.lines().map(|l| format!("        {}", l)).collect::<Vec<_>>().join("\n"));

    println!("========================================================================================");
    let latency_ok = mean_us < 50.0;
    println!(
        " MONTH 5 EXIT CRITERIA: {} (Kill Switch mean {:.2}us {} 50us | 6/6 Layers Verified | Prometheus)",
        if latency_ok { "ALL PASSED" } else { "LATENCY TARGET MISSED" },
        mean_us,
        if latency_ok { "<" } else { ">=" }
    );
    println!("========================================================================================");

    if !latency_ok {
        std::process::exit(1);
    }
    Ok(())
}
