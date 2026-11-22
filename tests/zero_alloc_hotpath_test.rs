//! Phase D6: Hard Zero-Allocation Global Allocator Enforcement Gate (`tests/zero_alloc_hotpath_test.rs`).
//!
//! Installs a custom `#[global_allocator]` (`CountingAllocator`) and strictly proves
//! **`assert_eq!(bytes_allocated, 0)`** across EVERY single hot-path subsystem in FinGate:
//! 1. FIX 4.4 Wire Parse + Repeating Group Iter + `normalize_fix_view`
//! 2. CME iLink 3 SBE Binary Decode
//! 3. Nasdaq OUCH 5.0 Binary Encode + Decode
//! 4. Cboe BOE3 Binary Encode + Decode
//! 5. NSE India Trimmed NNF (`TRIM`) Binary Encode + Decode
//! 6. Zero-Alloc Byte-Slice JSON Order Scanner
//! 7. Dense 5-Check `PreTradeRiskEngine::check_order_slot`
//! 8. SIMD 16-Point SPAN + Portfolio Greeks + House Group Rollup (`PortfolioGreeksEngine`)
//! 9. In-Flight `35=G` + `PartialFill` `OrderLifecycleFsm`
//! 10. `FastClOrdIdRouter` outbound register + fill route
//! 11. `FastDropCopyReconciler::reconcile_wire_fast`
//! 12. 6-Layer `KillSwitchEngine::execute_emergency_shutdown_zero_alloc` (1,000 live orders!)
//! 13. PCIe FPGA BAR0 Seqlock `publish_limits` + 4-Cycle `FpgaEdgeGatekeeperModel`
//! 14. POSIX `MappedShmChannel` Pod <-> Gateway zero-copy round-trip

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

use traffic_gateway::attestation::{hmac_sha256, sha256};
use traffic_gateway::fix::wire::{FixFrameBuilder, FixWireView};
use traffic_gateway::hw_sync::bar0::{FpgaBar0Registers, FpgaEdgeGatekeeperModel};
use traffic_gateway::ipc::shm_channel::{
    FastStampedShmChannel, MappedShmChannel, ShmOrderVerdict, VERDICT_APPROVED,
};
use traffic_gateway::killswitch::layers::KillSwitchEngine;
use traffic_gateway::oms::order_fsm::OrderLifecycleFsm;
use traffic_gateway::protocol::boe3::{decode_boe3_zero_copy, encode_boe3_new_order};
use traffic_gateway::protocol::fast_json::decode_fast_json_zero_copy;
use traffic_gateway::protocol::nse_trim::{
    decode_nse_trim_zero_copy, encode_nse_trim_order, NSE_TRIM_TX_NEW_ORDER,
};
use traffic_gateway::protocol::ouch5::{decode_ouch5_zero_copy, encode_ouch5_enter};
use traffic_gateway::protocol::sbe_ilink3::{decode_ilink3_zero_copy, encode_ilink3_new_order};
use traffic_gateway::protocol::{normalize_fix_view, NormalizedOrderEvent, SIDE_BUY};
use traffic_gateway::reconcile::{FastDropCopyReconciler, FastReconcileOutcome, ReconcileConfig};
use traffic_gateway::risk::engine::{AccountRiskConfig, InstrumentRiskConfig, PreTradeRiskEngine};
use traffic_gateway::risk::portfolio_greeks::{
    ContractGreeks, PortfolioGreekLimits, PortfolioGreeksEngine, SpanRiskArray,
};
use traffic_gateway::frontier::entropy_sentinel::OrderFlowEntropySentinel;
use traffic_gateway::frontier::flight_recorder::{BlackBoxFlightRecorder, EVENT_RISK_PASS};
use traffic_gateway::frontier::merkle_proof::InlineMerkleProofEngine;
use traffic_gateway::frontier::shadow_fork::ShadowForkEngine;
use traffic_gateway::frontier::speculative_vault::SpeculativeOrderVault;
use traffic_gateway::frontier::superscalar_risk::{
    evaluate_risk_batch8_simd, BatchAccountState, BatchRiskLimits, SoaOrderBatch8,
};
use traffic_gateway::horizon::hawkes_shield::HawkesToxicFlowShield;
use traffic_gateway::horizon::nano_policy_vm::{compile_policy_dsl, PolicyEvalContext, PolicyVerdict};
use traffic_gateway::horizon::oblivious_vault::ObliviousTelemetryVault;
use traffic_gateway::horizon::relativistic_guard::{
    HybridLogicalClock, RelativisticRaceGuard, VENUE_CME_AURORA, VENUE_NASDAQ_NY4,
};
use traffic_gateway::horizon::threshold_quorum::{
    shamir_reconstruct_zero_alloc, ThresholdQuorumGuard,
};
use traffic_gateway::shield::multiplexer::FastClOrdIdRouter;
use traffic_gateway::shield::vsr_net::{VsrWireDatagram, VSR_MSG_PREPARE, VSR_WIRE_SIZE};
use traffic_gateway::singularity::UnifiedSingularityEngine;
use traffic_gateway::transport::userspace_net::UserspaceTcpConfig;
use traffic_gateway::transport::SimNicTransport;
use traffic_gateway::uplink::{KernelBypassVenueTwin, KernelBypassVenueUplink};
use traffic_gateway::wal::AsyncGroupCommitWal;

struct CountingAllocator;

static ALLOC_BYTES: AtomicUsize = AtomicUsize::new(0);
static ALLOC_CALLS: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOC_BYTES.fetch_add(layout.size(), Ordering::Relaxed);
        ALLOC_CALLS.fetch_add(1, Ordering::Relaxed);
        System.alloc(layout)
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        System.dealloc(ptr, layout)
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        ALLOC_BYTES.fetch_add(new_size, Ordering::Relaxed);
        ALLOC_CALLS.fetch_add(1, Ordering::Relaxed);
        System.realloc(ptr, layout, new_size)
    }
}

#[global_allocator]
static GLOBAL_ALLOC: CountingAllocator = CountingAllocator;

#[inline(never)]
fn assert_zero_alloc<F: FnOnce()>(stage: &str, f: F) {
    let b0 = ALLOC_BYTES.load(Ordering::SeqCst);
    let c0 = ALLOC_CALLS.load(Ordering::SeqCst);
    f();
    let b1 = ALLOC_BYTES.load(Ordering::SeqCst);
    let c1 = ALLOC_CALLS.load(Ordering::SeqCst);
    assert_eq!(
        b1 - b0,
        0,
        "HOT-PATH ALLOCATION VIOLATION in '{}': allocated {} bytes across {} calls!",
        stage,
        b1 - b0,
        c1 - c0
    );
    assert_eq!(
        c1 - c0,
        0,
        "HOT-PATH ALLOCATION CALL VIOLATION in '{}': {} alloc calls!",
        stage,
        c1 - c0
    );
}

/// Single test in this binary so no concurrent test thread introduces allocator noise.
#[test]
fn test_phase_d6_zero_heap_allocations_across_all_14_hot_paths() {
    // --- Cold-path setup (pre-allocates all slabs & test fixtures once) ---
    let mut fix_b = FixFrameBuilder::new();
    fix_b
        .push_str(35, "D")
        .push_u64(34, 42)
        .push_str(49, "POD01")
        .push_str(56, "FINGATE")
        .push_str(11, "ORD-ZA-001")
        .push_str(55, "BTC-USDT")
        .push_str(54, "1")
        .push_u64(38, 10)
        .push_u64(44, 95_000)
        .push_u64(453, 2)
        .push_str(448, "ALGO_DESK_1")
        .push_str(448, "CLEARING_7");
    let fix_wire = fix_b.finish_soh_bytes(false, false);

    let mut exec_b = FixFrameBuilder::new();
    exec_b
        .push_str(35, "8")
        .push_u64(34, 99)
        .push_str(17, "EX-ZA-9001")
        .push_str(37, "EXCH-9001")
        .push_str(11, "ORD-DC-001")
        .push_str(55, "AAPL")
        .push_str(54, "1")
        .push_str(150, "2")
        .push_str(39, "2")
        .push_u64(32, 100)
        .push_str(31, "185.50")
        .push_u64(14, 100)
        .push_u64(151, 0);
    let dc_wire = exec_b.finish_soh_bytes(false, false);

    let mut ilink_buf = [0u8; 40];
    encode_ilink3_new_order(12345, 7, true, 50, 95_000, &mut ilink_buf);

    let mut ouch_buf = [0u8; 32];
    let mut boe_buf = [0u8; 56];
    let mut trim_buf = [0u8; 48];
    let json_wire = br#"{"cl_ord_id":"AI-001","symbol":"NIFTY26NOV","side":"BUY","price":24500,"qty":75,"algo_id":"1234567890123"}"#;

    let mut risk = PreTradeRiskEngine::new();
    let acc_slot = risk.register_account(AccountRiskConfig {
        account_id: "ZA_ACC".to_string(),
        trading_group_id: 1,
        gross_credit_limit: 500_000_000,
        gcra_tau_ns: 10,
        gcra_burst_limit_ns: 100_000_000,
    });
    risk.register_instrument(
        1,
        InstrumentRiskConfig {
            max_order_qty: 10_000,
            max_order_notional: 50_000_000,
            price_collar_bps: 1000,
            reference_price: 95_000,
        },
    );

    let mut greeks = PortfolioGreeksEngine::new(4, 2, 4);
    let glim = PortfolioGreekLimits::default();
    greeks.configure_account(0, 0, glim);
    greeks.configure_house_group(0, glim);
    greeks.set_contract_greeks(
        1,
        ContractGreeks {
            delta_e4: 5_000,
            gamma_e4: 250,
            vega_e4: 600,
            theta_e4: -50,
            span: SpanRiskArray {
                scenarios: [-50, -40, -30, -20, -10, 0, 10, 20, -60, -45, -35, -25, 5, 15, 25, 35],
            },
        },
    );

    let mut fsm = OrderLifecycleFsm::with_capacity(256);
    let mut router = FastClOrdIdRouter::new("FG-ZA");
    let mut dc = FastDropCopyReconciler::new(&ReconcileConfig::default());

    let ks_engine = KillSwitchEngine::new();
    let ks_orders: Vec<String> = (0..1_000)
        .map(|i| format!("FG-ZA-P001-{:08}", i + 1))
        .collect();

    let bar0 = FpgaBar0Registers::new(1000, 100_000_000, 90_000, 100_000, 1000, 1000);
    let mut fpga = FpgaEdgeGatekeeperModel::new();

    let shm_path = std::env::temp_dir().join(format!(
        "fingate_za_shm_{}.shm",
        std::process::id()
    ));
    let shm_gw = MappedShmChannel::create(&shm_path, 0).expect("create SHM");
    let shm_pod = MappedShmChannel::attach(&shm_path).expect("attach SHM");
    let mut pod_ep = shm_pod.as_pod_endpoint();
    let mut gw_ep = shm_gw.as_gateway_endpoint();

    let (gw_nic, venue_nic) = SimNicTransport::pair();
    let kb_cfg = UserspaceTcpConfig {
        local_mac: [0x02, 0x00, 0x00, 0x00, 0x00, 0x01],
        remote_mac: [0x02, 0x00, 0x00, 0x00, 0x00, 0x02],
        local_ip: [10, 0, 0, 1],
        remote_ip: [10, 0, 0, 2],
        local_port: 41000,
        remote_port: 7001,
    };
    let mut kb_uplink = KernelBypassVenueUplink::new(gw_nic, kb_cfg);
    let mut kb_venue = KernelBypassVenueTwin::new(venue_nic, kb_cfg.swap_endpoints());

    let wal_za_path = std::env::temp_dir().join(format!("fingate_za_wal_{}.wal", std::process::id()));
    let _ = std::fs::remove_file(&wal_za_path);
    let mut async_wal = AsyncGroupCommitWal::open(&wal_za_path, false).expect("open async wal");

    let (mut spec_tx_nic, _spec_rx_nic) = SimNicTransport::pair();
    let mut spec_vault = SpeculativeOrderVault::new(4);
    spec_vault.arm_template(0, kb_cfg, 77, true, 58_000, 10, 100, 50_000, 70_000, 500_000_000);
    let mut sentinel = OrderFlowEntropySentinel::default();
    let mut merkle = InlineMerkleProofEngine::new(0xCAFE_BABE);
    let bbox_za_path = std::env::temp_dir().join(format!("fingate_za_bbox_{}.shm", std::process::id()));
    let mut bbox = BlackBoxFlightRecorder::create(&bbox_za_path).expect("create blackbox");
    let live_greek_state = *greeks.account_state(0).unwrap();

    let h1_prog = compile_policy_dsl(1, "REJECT 101 IF notional > 5000000 AND entropy < 8000\nREJECT 102 IF qty > 500").unwrap();
    let (h2_guard, h2_shares) = ThresholdQuorumGuard::provision(0x1A2B_3C4D_5E6F_7788, 3, 5, [0x42; 32]);
    let mut h3_hawkes = HawkesToxicFlowShield::default();
    let mut h4_rel = RelativisticRaceGuard::with_global_exchange_topology(20_000_000);
    let mut h5_obl = ObliviousTelemetryVault::new(0x1337_CAFE);

    let stamped_path =
        std::env::temp_dir().join(format!("fingate_za_stamped_{}.shm", std::process::id()));
    let stamped_gw = FastStampedShmChannel::create(&stamped_path, 0).expect("stamped shm create");
    let stamped_pod = FastStampedShmChannel::open(&stamped_path).expect("stamped shm open");
    let mut stamped_pod_ep = stamped_pod.pod_endpoint();
    let mut stamped_gw_ep = stamped_gw.gateway_endpoint();

    let sing_wal_path =
        std::env::temp_dir().join(format!("fingate_za_sing_wal_{}.wal", std::process::id()));
    let sing_bb_path =
        std::env::temp_dir().join(format!("fingate_za_sing_bb_{}.shm", std::process::id()));
    let _ = std::fs::remove_file(&sing_wal_path);
    let _ = std::fs::remove_file(&sing_bb_path);
    let (mut sing_engine, _sing_shares) = UnifiedSingularityEngine::initialize(
        &sing_wal_path,
        &sing_bb_path,
        0x1A2B_3C4D_5E6F_7788,
        "REJECT 101 IF notional > 5000000000\nREJECT 102 IF qty > 50000",
    )
    .expect("init singularity");

    // --- Hot-path ZERO-ALLOCATION proofs ---

    // 1. FIX 4.4 Parse + Repeating Group Iter + Normalization
    assert_zero_alloc("FIX 4.4 parse + repeating_group_iter + normalize", || {
        let view = FixWireView::parse_and_validate(&fix_wire).unwrap();
        let mut party_count = 0usize;
        for _p in view.repeating_group_iter(453, 448) {
            party_count += 1;
        }
        assert_eq!(party_count, 2);
        let ev = normalize_fix_view(&view, 0, 0, 1, 1000).unwrap();
        assert_eq!(ev.qty, 10);
    });

    // 2. CME iLink 3 SBE Binary Decode
    assert_zero_alloc("CME iLink 3 SBE decode", || {
        let ev = decode_ilink3_zero_copy(&ilink_buf, 0, 0, 1000).unwrap();
        assert_eq!(ev.qty, 50);
    });

    // 3. Nasdaq OUCH 5.0 Encode + Decode
    assert_zero_alloc("Nasdaq OUCH 5.0 encode + decode", || {
        encode_ouch5_enter(9001, true, 100, b"AAPL", 185_5000, &mut ouch_buf);
        let ev = decode_ouch5_zero_copy(&ouch_buf, 0, 0, 1000).unwrap();
        assert_eq!(ev.qty, 100);
    });

    // 4. Cboe BOE3 Encode + Decode
    assert_zero_alloc("Cboe BOE3 encode + decode", || {
        encode_boe3_new_order(1, b"BOE-ORD-1", true, 250, b"SPY", 580_0000, &mut boe_buf);
        let ev = decode_boe3_zero_copy(&boe_buf, 0, 0, 1000).unwrap();
        assert_eq!(ev.qty, 250);
    });

    // 5. NSE Trimmed NNF Encode + Decode
    assert_zero_alloc("NSE Trimmed NNF encode + decode", || {
        encode_nse_trim_order(
            NSE_TRIM_TX_NEW_ORDER,
            777,
            true,
            75,
            2_450_000,
            9001,
            1_234_567_890_123,
            0,
            &mut trim_buf,
        );
        let ev = decode_nse_trim_zero_copy(&trim_buf, 0, 0, 1000).unwrap();
        assert_eq!(ev.qty, 75);
        assert_eq!(ev.algo_id_hash, 1_234_567_890_123);
    });

    // 6. Zero-Alloc Byte-Slice JSON Order Scanner
    assert_zero_alloc("FastJSON zero-alloc order scan", || {
        let ev = decode_fast_json_zero_copy(json_wire, 0, 0, 1000).unwrap();
        assert_eq!(ev.qty, 75);
        assert_eq!(ev.price_ticks, 24500);
    });

    // 7. Dense 5-Check Pre-Trade Risk Engine
    assert_zero_alloc("PreTradeRiskEngine::check_order_slot", || {
        risk.check_order_slot(acc_slot, 0xAAAA_0001, 1, true, 95_000, 10, 5_000_000)
            .unwrap();
    });

    // 8. SIMD 16-Point SPAN + Portfolio Greeks + House Group Rollup
    assert_zero_alloc("PortfolioGreeksEngine::check_and_commit_order (SIMD SPAN)", || {
        greeks.check_and_commit_order(0, 1, true, 10).unwrap();
    });

    // 9. In-Flight 35=G + PartialFill OrderLifecycleFsm
    assert_zero_alloc("OrderLifecycleFsm 35=D -> 35=G -> PartialFill -> ReplaceAck -> Fill", || {
        fsm.submit_new(101, 0, 1, true, 100, 95_000).unwrap();
        fsm.request_replace(101, 102, 150, 95_100).unwrap();
        fsm.on_fill(101, 40).unwrap();
        fsm.on_replace_ack(102).unwrap();
        let tr = fsm.on_fill(102, 110).unwrap();
        assert_eq!(tr.leaves_qty, 0);
    });

    // 10. FastClOrdIdRouter outbound register + fill route
    assert_zero_alloc("FastClOrdIdRouter register + route fill", || {
        let wid = router.register_outbound_fast(1, 0xBEEF, 100, 95_000, true, 1000);
        let filled = router.route_inbound_fill_fast(wid.wire_seq, 100);
        assert!(filled.is_some());
    });

    // 11. FastDropCopyReconciler zero-alloc wire reconcile
    assert_zero_alloc("FastDropCopyReconciler register + fill + reconcile_wire_fast", || {
        assert!(dc.register_internal_order_fast(b"ORD-DC-001", b"AAPL", 1, 100, 1_855_000));
        assert!(dc.record_internal_fill_fast(b"ORD-DC-001", 100, 1_855_000));
        let view = FixWireView::parse_and_validate(&dc_wire).unwrap();
        let out = dc.reconcile_wire_fast(&view, 2_000_000);
        assert_eq!(out, FastReconcileOutcome::Matched { reconciled_qty: 100 });
    });

    // 12. 6-Layer Kill Switch over 1,000 live working orders (0 bytes allocated!)
    assert_zero_alloc("KillSwitchEngine::execute_emergency_shutdown_zero_alloc (1,000 orders)", || {
        let res = ks_engine.execute_emergency_shutdown_zero_alloc(&ks_orders, 1_000_000);
        assert_eq!(res.mass_cancels_generated, 1_000);
        assert!(res.final_state_active);
    });

    // 13. PCIe FPGA BAR0 Seqlock publish + 4-Cycle Edge Gatekeeper
    assert_zero_alloc("FpgaBar0Registers::publish_limits + evaluate_order", || {
        bar0.publish_limits(1000, 90_000_000, 90_000, 100_000, 1000, 1000);
        let (_v, cyc, _ns) = fpga.evaluate_order(&bar0, 10, 95_000);
        assert_eq!(cyc, 4);
    });

    // 14. POSIX MappedShmChannel zero-copy round-trip
    assert_zero_alloc("MappedShmChannel Pod <-> Gateway zero-copy round-trip", || {
        let ev = NormalizedOrderEvent {
            cl_ord_id_hash: 777,
            orig_cl_ord_id_hash: 0,
            price_ticks: 95_000,
            qty: 10,
            algo_id_hash: 0,
            ingress_tsc: 1000,
            account_slot: 0,
            symbol_slot: 1,
            pod_slot: 0,
            side: SIDE_BUY,
            action: 0,
            protocol_id: 1,
            flags: 0,
            _pad: [0; 6],
        };
        shm_pod.pod_try_submit(ev).unwrap();
        let got = shm_gw.gateway_try_poll_order().unwrap();
        assert_eq!(got.cl_ord_id_hash, 777);
        shm_gw
            .gateway_try_publish_verdict(ShmOrderVerdict {
                cl_ord_id_hash: got.cl_ord_id_hash,
                wire_seq: 1,
                leaves_qty: 0,
                cum_qty: 10,
                last_px: 95_000,
                egress_tsc: 1050,
                status: VERDICT_APPROVED,
                reject_code: 0,
                _pad: [0; 14],
            })
            .unwrap();
        let v = shm_pod.pod_try_poll_verdict().unwrap();
        assert_eq!(v.status, VERDICT_APPROVED);
    });

    // 15. Gap 2 (E2): Borrow-in-place SHM cached-cursor endpoints (0 bytes allocated!)
    assert_zero_alloc("ShmPodEndpoint / ShmGatewayEndpoint borrow-in-place round-trip", || {
        assert!(pod_ep.try_submit_in_place(|o| {
            o.cl_ord_id_hash = 888;
            o.qty = 5;
            o.price_ticks = 95_000;
        }));
        let h = gw_ep.try_poll_order_in_place(|o| o.cl_ord_id_hash).unwrap();
        assert_eq!(h, 888);
        assert!(gw_ep.try_publish_verdict_in_place(|v| {
            v.cl_ord_id_hash = h;
            v.status = VERDICT_APPROVED;
        }));
        let st = pod_ep.wait_verdict_in_place(|v| v.status);
        assert_eq!(st, VERDICT_APPROVED);
    });

    // 16. Gap 1 (E1): Kernel-Bypass L2/IPv4/TCP + CME iLink 3 SBE full venue round-trip (0 bytes!)
    assert_zero_alloc("KernelBypassVenueUplink + UserspaceTcpSession + VenueTwin", || {
        let ev = NormalizedOrderEvent {
            cl_ord_id_hash: 999,
            orig_cl_ord_id_hash: 0,
            price_ticks: 95_500,
            qty: 10,
            algo_id_hash: 0,
            ingress_tsc: 0,
            account_slot: 0,
            symbol_slot: 1,
            pod_slot: 0,
            side: SIDE_BUY,
            action: 0,
            protocol_id: 2,
            flags: 0,
            _pad: [0; 6],
        };
        assert_eq!(kb_uplink.send_order_zero_alloc(&ev).unwrap(), 94);
        assert_eq!(kb_venue.poll_and_match_once(), 1);
        let mut matched = false;
        kb_uplink.poll_exec_reports(4, |rep, _| {
            assert_eq!(rep.cl_ord_id_hash, 999);
            matched = true;
        });
        assert!(matched);
    });

    // 17. Gap 4 (E4): 65,536-slot In-Place AsyncGroupCommitWal hot-path enqueue (0 bytes!)
    assert_zero_alloc("AsyncGroupCommitWal::enqueue (65k ring in-place)", || {
        async_wal.enqueue(1, 10_000, 0, b"8=FIX.4.4\x0135=D\x0155=BTC\x01");
    });

    // 18. Gap 5 (E5): VSR binary UDP wire datagram encode + CRC32C decode (0 bytes!)
    assert_zero_alloc("VsrWireDatagram encode + CRC32C decode", || {
        let mut pkt = [0u8; VSR_WIRE_SIZE];
        let d = VsrWireDatagram {
            msg_type: VSR_MSG_PREPARE,
            sender_id: 0,
            payload_len: 4,
            view_number: 2,
            op_number: 1,
            payload: [0; 64],
            entry_crc: 123,
        };
        d.encode(&mut pkt);
        let dec = VsrWireDatagram::decode(&pkt).unwrap();
        assert_eq!(dec.view_number, 2);
    });

    // 19. Frontier G1: Speculative Order Vault trigger-to-wire with RFC 1624 incremental checksum (0 B!)
    assert_zero_alloc("Frontier G1: SpeculativeOrderVault::trigger_and_emit", || {
        assert_eq!(
            spec_vault.trigger_and_emit(0, 12345, 58_250, 15, &mut spec_tx_nic).unwrap(),
            94
        );
    });

    // 20. Frontier G2: SIMD 8-Way Super-Scalar Batch Risk + Prefix-Sum Credit & Delta (0 B!)
    assert_zero_alloc("Frontier G2: evaluate_risk_batch8_simd", || {
        let batch = SoaOrderBatch8 {
            prices: [58_200; 8],
            qtys: [10; 8],
            signed_deltas_e4: [5_000; 8],
        };
        let lim = BatchRiskLimits {
            max_order_qty: 100,
            max_order_notional: 50_000_000,
            collar_min: 50_000,
            collar_max: 70_000,
            max_abs_delta_e4: 50_000_000,
        };
        let mut st = BatchAccountState {
            remaining_credit: 50_000_000,
            net_delta_e4: 0,
        };
        let v = evaluate_risk_batch8_simd(&batch, &lim, &mut st);
        assert_eq!(v.approved_mask, 0xFF);
    });

    // 21. Frontier G3: Inline O(1) Shannon Entropy + Oscillation + Spoofing Sentinel (0 B!)
    assert_zero_alloc("Frontier G3: OrderFlowEntropySentinel::observe_order", || {
        let _ = sentinel.observe_order(58_200, 10, 1, false);
    });

    // 22. Frontier G4: Inline Proof-Carrying Order Commit + SHA-256 Merkle Seal + O(log N) Verify (0 B!)
    assert_zero_alloc("Frontier G4: InlineMerkleProofEngine commit + seal + verify", || {
        let (idx, _tag) = merkle.commit_order_inline(1000, 777, 58_200, 10, 10_000_000, -5_000, 0, 0xFF, 0);
        let root = merkle.seal_current_block();
        let leaf = *merkle.get_leaf(idx).unwrap();
        let proof = merkle.generate_inclusion_proof(idx).unwrap();
        assert!(InlineMerkleProofEngine::verify_inclusion_proof(&leaf, &proof, &root));
    });

    // 23. Frontier G5: Live Shadow-Fork 6-Shockwave Flash-Crash Counterfactual (0 B!)
    assert_zero_alloc("Frontier G5: ShadowForkEngine::evaluate_live_counterfactuals", || {
        let rep = ShadowForkEngine::evaluate_live_counterfactuals(&live_greek_state, 58_200, 500_000);
        assert!(rep.survives_all_shocks);
    });

    // 24. Frontier G6: Crash-Surviving MAP_SHARED 64B Black-Box Flight Recorder (0 B!)
    assert_zero_alloc("Frontier G6: BlackBoxFlightRecorder::record_fast", || {
        assert_eq!(
            bbox.record_fast(1000, 777, 58_200, 10, 0xCAFE, 38_000, -5_000, EVENT_RISK_PASS, 0, 0, 1),
            1
        );
    });

    // 25. Horizon H1: Formally Terminating NanoPolicyVm bytecode execution (0 B!)
    assert_zero_alloc("Horizon H1: VerifiedPolicyProgram::execute", || {
        let ctx = PolicyEvalContext {
            price: 58_200,
            qty: 10,
            notional: 582_000,
            net_delta_e4: 50_000,
            span_worst: -10_000,
            entropy_e4: 35_000,
            hawkes_e4: 15_000,
            vpin_e4: 1_000,
        };
        assert_eq!(h1_prog.execute(&ctx), PolicyVerdict::Allow);
    });

    // 26. Horizon H2: Asymmetric 1-of-N Trip + 3-of-5 Shamir F_(2^61-1) Reconstruct & Disarm (0 B!)
    assert_zero_alloc("Horizon H2: ThresholdQuorumGuard trip + 3-of-5 Shamir disarm", || {
        h2_guard.trip_emergency_halt_1_of_n();
        let sub = [h2_shares[0], h2_shares[2], h2_shares[4]];
        assert!(shamir_reconstruct_zero_alloc(&sub).is_some());
        assert_eq!(h2_guard.authorize_disarm_m_of_n(&sub, 1).unwrap(), 2);
    });

    // 27. Horizon H3: Inline Hawkes Self-Exciting Point Process + VPIN Shield (0 B!)
    assert_zero_alloc("Horizon H3: HawkesToxicFlowShield::observe_flow", || {
        let _ = h3_hawkes.observe_flow(1_000_000_000, true, 10);
    });

    // 28. Horizon H4: Relativistic Speed-of-Light Causality + HLC + Global STP (0 B!)
    assert_zero_alloc("Horizon H4: RelativisticRaceGuard::check_cross_venue_order", || {
        let _ = h4_rel.check_cross_venue_order(
            1,
            VENUE_NASDAQ_NY4,
            VENUE_CME_AURORA,
            1_000_000_000,
            1_005_000_000,
            HybridLogicalClock::pack(1_000_000, 1),
            true,
            58_200,
        );
    });

    // 29. Horizon H5: Oblivious Homomorphic Commit (F_2^61-1) + Inline epsilon-DP (0 B!)
    assert_zero_alloc("Horizon H5: ObliviousTelemetryVault commit + verify + DP", || {
        let c = h5_obl.commit_hidden_order(582_000);
        assert!(ObliviousTelemetryVault::verify_aggregate_audit(
            c,
            h5_obl.total_exposure_sum,
            h5_obl.total_blinding_sum,
        ));
        let _ = h5_obl.privatize_metric_dp(1_000_000, 1_000);
    });

    // 30. Track I1: Hardware Silicon SHA-256 + Streaming HMAC-SHA256 (0 B!)
    assert_zero_alloc("Singularity I1: HW SHA-256 + Streaming HMAC-SHA256", || {
        let h = sha256(&fix_wire);
        let mac = hmac_sha256(&h, &fix_wire);
        assert_ne!(mac, [0u8; 32]);
    });

    // 31. Track I3: Post-Quantum SIMD Ajtai-SIS Lattice Homomorphic Commitment + Verify (0 B!)
    assert_zero_alloc("Singularity I3: Post-Quantum Lattice Homomorphic Commit + SIS Verify", || {
        let lc = h5_obl.commit_hidden_order_lattice(582_000);
        assert!(ObliviousTelemetryVault::verify_lattice_aggregate_audit(
            lc,
            h5_obl.lattice_exposure_sum,
            h5_obl.lattice_blinding_sum,
            1u64 << 24,
        ));
    });

    // 32. Track I5: SWAR 8-Digit Fused Single-Pass FIX 4.4 Order Extractor (0 B!)
    assert_zero_alloc("Singularity I5: FixWireView::parse_order_fused_swar", || {
        let fast = FixWireView::parse_order_fused_swar(&fix_wire).unwrap();
        assert_eq!(fast.order_qty, 10);
    });

    // 33. Track I6: 128B Single-MESI Sequence-Stamped SHM Ring Round-Trip (0 B!)
    assert_zero_alloc("Singularity I6: FastStampedShmChannel 128B Single-MESI Round-Trip", || {
        assert!(stamped_pod_ep.try_publish_order_in_place(|o| {
            o.cl_ord_id_hash = 4242;
            o.qty = 25;
            o.price_ticks = 58_200;
        }));
        let h = stamped_gw_ep
            .try_poll_order_in_place(|o| o.cl_ord_id_hash)
            .unwrap();
        assert_eq!(h, 4242);
        assert!(stamped_gw_ep.try_publish_verdict_in_place(|v| {
            v.cl_ord_id_hash = h;
            v.status = VERDICT_APPROVED;
        }));
        let st = stamped_pod_ep.wait_verdict_in_place(|v| v.status);
        assert_eq!(st, VERDICT_APPROVED);
    });

    // 34. Track I8: Full 12-Stage UnifiedSingularityEngine End-to-End Inline Order (0 B!)
    assert_zero_alloc("Singularity I8: UnifiedSingularityEngine 12-Stage Inline Order", || {
        let ord = NormalizedOrderEvent {
            cl_ord_id_hash: 99_001,
            orig_cl_ord_id_hash: 0,
            price_ticks: 58_200,
            qty: 10,
            algo_id_hash: 1,
            ingress_tsc: 1_005_000_000,
            account_slot: 0,
            symbol_slot: 1,
            pod_slot: 0,
            side: SIDE_BUY,
            action: 0,
            protocol_id: 2,
            flags: 0,
            _pad: [0; 6],
        };
        let dec = sing_engine.process_order_inline(
            &ord,
            1_000_000_000,
            1_005_000_000,
            HybridLogicalClock::pack(1_000_000, 1),
            true,
        );
        assert!(dec.approved);
        sing_engine.on_order_completed_and_reclaim(99_001, 10, 0, 1, true);
    });

    let _ = sing_engine.wal.shutdown_and_sync();
    let _ = async_wal.shutdown_and_sync();
    let _ = std::fs::remove_file(&sing_wal_path);
    let _ = std::fs::remove_file(&sing_bb_path);
    let _ = std::fs::remove_file(&stamped_path);
    let _ = std::fs::remove_file(&wal_za_path);
    let _ = std::fs::remove_file(&bbox_za_path);
    let _ = std::fs::remove_file(&shm_path);
}
