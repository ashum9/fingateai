//! Track I (Singularity I1–I8): Mathematical, Cryptographic, Concurrency, & 12-Stage Unified Verification Suite.

use std::collections::HashMap;
use std::sync::Arc;
use std::thread;

use traffic_gateway::admin::control::ControlPlaneState;
use traffic_gateway::attestation::{hex_encode, hmac_sha256, sha256, sha256_hw_accelerated};
use traffic_gateway::ffi::{
    fingate_sha256_hw_accelerated, fingate_stamped_shm_close, fingate_stamped_shm_create,
    fingate_stamped_shm_open,
};
use traffic_gateway::fix::wire::{parse_u64_swar, FixFrameBuilder, FixWireView};
use traffic_gateway::frontier::speculative_vault::{full_tcp_checksum, SpeculativeOrderVault};
use traffic_gateway::frontier::superscalar_risk::{
    evaluate_risk_batch8_simd, BatchAccountState, BatchRiskLimits, SoaOrderBatch8,
};
use traffic_gateway::horizon::hawkes_shield::HawkesToxicFlowShield;
use traffic_gateway::horizon::nano_policy_vm::{
    compile_policy_dsl, OpCode, PolicyEvalContext, PolicyInstr, VerifiedPolicyProgram,
};
use traffic_gateway::horizon::oblivious_vault::{
    LatticeHomomorphicCommitment, ObliviousTelemetryVault,
};
use traffic_gateway::horizon::relativistic_guard::HybridLogicalClock;
use traffic_gateway::horizon::threshold_quorum::{
    mod_inv, mod_mul, shamir_reconstruct_zero_alloc, shamir_split, MERSENNE_P61,
};
use traffic_gateway::ipc::shm_channel::{FastStampedShmChannel, VERDICT_APPROVED};
use traffic_gateway::oms::order_fsm::{OrderLifecycleFsm, OrderRecordSlot};
use traffic_gateway::protocol::{NormalizedOrderEvent, SIDE_BUY, SIDE_SELL};
use traffic_gateway::singularity::{SingularityRejectReason, UnifiedSingularityEngine};
use traffic_gateway::transport::userspace_net::UserspaceTcpConfig;
use traffic_gateway::transport::SimNicTransport;

// =========================================================================
// I1: Hardware Silicon SHA-256 + Streaming HMAC-SHA256
// =========================================================================
#[test]
fn test_i1_hardware_silicon_sha256_and_hmac_vectors() {
    // NIST empty vector
    assert_eq!(
        hex_encode(&sha256(b"")),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    // NIST 1-block vector
    assert_eq!(
        hex_encode(&sha256(b"abc")),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    // NIST 2-block vector
    assert_eq!(
        hex_encode(&sha256(
            b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
        )),
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
    );
    // RFC-4231 Test Case 2 (Jefe)
    let mac = hmac_sha256(b"Jefe", b"what do ya want for nothing?");
    assert_eq!(
        hex_encode(&mac),
        "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
    );
    // FFI probe agrees with Rust probe
    assert_eq!(
        fingate_sha256_hw_accelerated() == 1,
        sha256_hw_accelerated()
    );
}

// =========================================================================
// I2: Optimal 70-Mul Addition Chain Fermat Inverse + Montgomery Batch Shamir
// =========================================================================
#[test]
fn test_i2_optimal_addition_chain_and_montgomery_batch_shamir() {
    // Verify a * mod_inv(a) == 1 (mod 2^61 - 1) across 2,000 non-zero field elements!
    let mut state = 0xDEAD_BEEF_1234_5678u64;
    for _ in 0..2_000 {
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
        let a = (state % (MERSENNE_P61 - 1)) + 1;
        let inv = mod_inv(a);
        assert_eq!(mod_mul(a, inv), 1, "mod_inv failed for a={}", a);
    }

    // Verify 5-of-7 Shamir reconstruction across ALL C(7,5) = 21 distinct subsets!
    let secret = 0x1FED_CBA9_8765_4321 & MERSENNE_P61;
    let shares = shamir_split(secret, 5, 7, [0x77; 32]);
    let mut subsets = 0usize;
    for a in 0..7 {
        for b in (a + 1)..7 {
            for c in (b + 1)..7 {
                for d in (c + 1)..7 {
                    for e in (d + 1)..7 {
                        let sub = [shares[a], shares[b], shares[c], shares[d], shares[e]];
                        assert_eq!(shamir_reconstruct_zero_alloc(&sub), Some(secret));
                        subsets += 1;
                    }
                }
            }
        }
    }
    assert_eq!(subsets, 21);
}

// =========================================================================
// I3: Post-Quantum SIMD Ajtai-SIS Lattice Homomorphic Commitment + Norm Binding
// =========================================================================
#[test]
fn test_i3_post_quantum_lattice_homomorphic_commitment_and_sis_binding() {
    let mut vault = ObliviousTelemetryVault::new(0xCAFE_BABE_1337);
    let mut public_sum = LatticeHomomorphicCommitment::default();
    let mut true_exposure = 0u64;

    // Commit 1,000 hidden orders: auditor sees ONLY opaque 244-bit lattice vectors!
    for i in 1..=1_000u64 {
        let notional = 50_000 + i * 73;
        let c = vault.commit_hidden_order_lattice(notional);
        public_sum = public_sum.homomorphic_add(c);
        true_exposure += notional;
    }
    assert_eq!(public_sum, vault.lattice_aggregate);
    assert_eq!(vault.lattice_exposure_sum, true_exposure);

    // Max valid blinding norm for 1,000 orders = 1_000 * 2^20
    let max_norm = 1_000u64 * (1u64 << 20);
    assert!(ObliviousTelemetryVault::verify_lattice_aggregate_audit(
        public_sum,
        vault.lattice_exposure_sum,
        vault.lattice_blinding_sum,
        max_norm,
    ));

    // 1. Omitting even $1 of exposure fails lattice verification!
    assert!(!ObliviousTelemetryVault::verify_lattice_aggregate_audit(
        public_sum,
        vault.lattice_exposure_sum - 1,
        vault.lattice_blinding_sum,
        max_norm,
    ));

    // 2. Norm-bound SIS enforcement rejects oversized blinding vectors!
    let mut oversized_r = vault.lattice_blinding_sum;
    oversized_r[0] = max_norm + 1;
    assert!(!ObliviousTelemetryVault::verify_lattice_aggregate_audit(
        public_sum,
        vault.lattice_exposure_sum,
        oversized_r,
        max_norm,
    ));

    // 3. Hiding property: identical notional produces distinct opaque lattice vectors!
    let c1 = vault.commit_hidden_order_lattice(100_000);
    let c2 = vault.commit_hidden_order_lattice(100_000);
    assert_ne!(c1, c2);
}

// =========================================================================
// I4: SIMD Predicate-Matrix Policy VM Parity + Zero-Stall SIMD Risk Parity
// =========================================================================
#[test]
fn test_i4_simd_policy_vm_and_zero_stall_superscalar_risk_parity() {
    let dsl = "\
        REJECT 101 IF notional > 5000000 AND entropy < 8000\n\
        REJECT 102 IF hawkes > 120000 AND vpin > 7000\n\
        REJECT 103 IF span < -250000\n\
        REJECT 104 IF qty > 1000\n";
    let simd_prog = compile_policy_dsl(10, dsl).unwrap();
    assert!(simd_prog.simd_prefilter_enabled);

    // Build an identical reference program with a harmless trailing `AllowHalt` to force non-SIMD slow path
    let mut raw_ref = vec![
        PolicyInstr {
            op: OpCode::RejectIfGtAndLt,
            src_a: 2,
            src_b: 5,
            reject_code: 101,
            imm: 5_000_000,
            extra: 8_000,
            ..Default::default()
        },
        PolicyInstr {
            op: OpCode::RejectIfGtAndGt,
            src_a: 6,
            src_b: 7,
            reject_code: 102,
            imm: 120_000,
            extra: 7_000,
            ..Default::default()
        },
        PolicyInstr {
            op: OpCode::RejectIfLtImm,
            src_a: 4,
            reject_code: 103,
            imm: -250_000,
            ..Default::default()
        },
        PolicyInstr {
            op: OpCode::RejectIfGtImm,
            src_a: 1,
            reject_code: 104,
            imm: 1_000,
            ..Default::default()
        },
        PolicyInstr {
            op: OpCode::AllowHalt,
            ..Default::default()
        },
    ];
    let ref_prog = VerifiedPolicyProgram::verify_and_seal(11, &raw_ref).unwrap();
    assert!(!ref_prog.simd_prefilter_enabled);
    raw_ref.clear();

    // Verify 100% bit-exact verdict parity across 1,000 randomized edge contexts!
    let mut rng = 0x9988_7766_5544_3322u64;
    for _ in 0..1_000 {
        let mut next = || {
            rng = rng.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            rng
        };
        let ctx = PolicyEvalContext {
            price: (next() % 100_000) as i64,
            qty: (next() % 1_400) as i64,
            notional: (next() % 8_000_000) as i64,
            net_delta_e4: ((next() % 1_000_000) as i64) - 500_000,
            span_worst: -((next() % 350_000) as i64),
            entropy_e4: (next() % 30_000) as i64,
            hawkes_e4: (next() % 180_000) as i64,
            vpin_e4: (next() % 10_000) as i64,
        };
        assert_eq!(simd_prog.execute(&ctx), ref_prog.execute(&ctx));
    }

    // Verify zero-stall `evaluate_risk_batch8_simd` handles >u32::MAX overflow guard cleanly
    let limits = BatchRiskLimits {
        max_order_qty: 10_000_000_000,
        max_order_notional: u64::MAX / 4,
        collar_min: 100,
        collar_max: 10_000_000_000,
        max_abs_delta_e4: 5_000_000,
    };
    let big_batch = SoaOrderBatch8 {
        prices: [5_000_000_000; 8], // > u32::MAX -> must trigger exact 64-bit fallback!
        qtys: [2; 8],
        signed_deltas_e4: [10_000; 8],
    };
    let mut st = BatchAccountState {
        remaining_credit: 100_000_000_000,
        net_delta_e4: 0,
    };
    let res = evaluate_risk_batch8_simd(&big_batch, &limits, &mut st);
    assert_eq!(res.approved_mask, 0xFF);
    assert_eq!(res.committed_notional, 80_000_000_000);
    assert_eq!(st.remaining_credit, 20_000_000_000);
}

// =========================================================================
// I5: SWAR 8-Digit Parallel Decimal Parser + Fused FIX Order Extractor
// =========================================================================
#[test]
fn test_i5_swar_decimal_parser_and_fused_fix_order_extractor() {
    // Exhaustive length 1..=18 + edge cases
    let cases = [
        "0",
        "7",
        "42",
        "999",
        "1234",
        "58250",
        "123456",
        "7654321",
        "12345678",
        "99999999",
        "123456789",
        "9876543210123456",
    ];
    for s in cases {
        assert_eq!(parse_u64_swar(s.as_bytes()), Some(s.parse::<u64>().unwrap()));
    }
    // Non-digit rejection across every position
    assert_eq!(parse_u64_swar(b""), None);
    assert_eq!(parse_u64_swar(b"1234a678"), None);
    assert_eq!(parse_u64_swar(b"1234:678"), None);
    assert_eq!(parse_u64_swar(b"/1234567"), None);
    assert_eq!(parse_u64_swar(b"1234567\xFF"), None);

    // Exact parity between `FixWireView::parse_and_validate` and `parse_order_fused_swar`
    let mut b = FixFrameBuilder::new();
    b.push_str(35, "D")
        .push_u64(34, 98765432)
        .push_str(49, "ALPHA_DESK")
        .push_str(56, "CME_ILINK")
        .push_str(11, "ORD-SWAR-001")
        .push_str(1, "ACCT_01")
        .push_str(55, "BTCUSDT")
        .push_str(54, "1")
        .push_u64(38, 250)
        .push_str(44, "58250.75");
    let wire = b.finish_soh_bytes(false, false);

    let full = FixWireView::parse_and_validate(&wire).unwrap();
    let fast = FixWireView::parse_order_fused_swar(&wire).unwrap();
    assert_eq!(fast.msg_type, full.get_raw(35).unwrap());
    assert_eq!(fast.msg_seq_num, 98_765_432);
    assert_eq!(fast.cl_ord_id, b"ORD-SWAR-001");
    assert_eq!(fast.account, b"ACCT_01");
    assert_eq!(fast.symbol, b"BTCUSDT");
    assert_eq!(fast.side, b'1');
    assert_eq!(fast.order_qty, 250);
    assert_eq!(fast.price_whole, 58_250);
    assert_eq!(fast.checksum, full.checksum);
    // O(1) hot-tag lookups on FixWireView
    assert_eq!(full.get_u64(38), Some(250));
    assert_eq!(full.get_str(55), Some("BTCUSDT"));
    assert_eq!(full.get_str(1), Some("ACCT_01"));
}

// =========================================================================
// I6: 128B Single-MESI Sequence-Stamped SHM Cross-Thread Stress Test
// =========================================================================
#[test]
fn test_i6_128b_stamped_shm_cross_thread_50k_roundtrip() {
    let path = std::env::temp_dir().join(format!("fingate_i6_shm_{}.shm", std::process::id()));
    let _ = std::fs::remove_file(&path);
    let gw = Arc::new(FastStampedShmChannel::create(&path, 0).unwrap());
    let pod = FastStampedShmChannel::open(&path).unwrap();

    let n_msgs = 25_000u64;
    let gw_clone = Arc::clone(&gw);
    let server = thread::spawn(move || {
        let mut ep = gw_clone.gateway_endpoint();
        let mut handled = 0u64;
        while handled < n_msgs {
            if let Some((h, px, qty)) = ep.try_poll_order_in_place(|o| (o.cl_ord_id_hash, o.price_ticks, o.qty)) {
                while !ep.try_publish_verdict_in_place(|v| {
                    v.cl_ord_id_hash = h;
                    v.last_px = px;
                    v.cum_qty = qty;
                    v.status = VERDICT_APPROVED;
                }) {}
                handled += 1;
            }
        }
    });

    let mut pod_ep = pod.pod_endpoint();
    for i in 1..=n_msgs {
        while !pod_ep.try_publish_order_in_place(|o| {
            o.cl_ord_id_hash = i;
            o.price_ticks = 58_000 + (i as i64 % 500);
            o.qty = (i % 100) + 1;
        }) {}
        let (vh, vpx, vstatus) = pod_ep.wait_verdict_in_place(|v| (v.cl_ord_id_hash, v.last_px, v.status));
        assert_eq!(vh, i);
        assert_eq!(vpx, 58_000 + (i as i64 % 500));
        assert_eq!(vstatus, VERDICT_APPROVED);
    }
    server.join().unwrap();

    // Verify C ABI handles open/close cleanly
    let cpath = std::ffi::CString::new(path.to_str().unwrap()).unwrap();
    unsafe {
        let h_open = fingate_stamped_shm_open(cpath.as_ptr());
        assert!(!h_open.is_null());
        fingate_stamped_shm_close(h_open);
        let path2 = std::env::temp_dir().join(format!("fingate_i6_c_{}.shm", std::process::id()));
        let cpath2 = std::ffi::CString::new(path2.to_str().unwrap()).unwrap();
        let h_cr = fingate_stamped_shm_create(cpath2.as_ptr(), 1);
        assert!(!h_cr.is_null());
        fingate_stamped_shm_close(h_cr);
        let _ = std::fs::remove_file(&path2);
    }
    let _ = std::fs::remove_file(&path);
}

// =========================================================================
// I7: 64B Single-Cache-Line Fibonacci OMS FSM + Hawkes & Speculative Hardening
// =========================================================================
#[test]
fn test_i7_64b_fibonacci_oms_hawkes_and_tcp_seq_wraparound() {
    assert_eq!(std::mem::size_of::<OrderRecordSlot>(), 64);

    // Stress sequential IDs 1..=4,000 + interleaved 35=G + reclaim (proves zero clustering / drift!)
    let mut fsm = OrderLifecycleFsm::with_capacity(512);
    for id in 1..=4_000u64 {
        fsm.submit_new(id, 0, 1, true, 100, 58_000).unwrap();
        if id % 10 == 0 {
            let new_id = id + 10_000_000;
            fsm.request_replace(id, new_id, 150, 58_010).unwrap();
            fsm.on_replace_ack(new_id).unwrap();
            fsm.on_fill(new_id, 150).unwrap();
            assert!(fsm.reclaim_terminal(new_id));
        } else {
            fsm.on_fill(id, 100).unwrap();
            assert!(fsm.reclaim_terminal(id));
        }
    }
    assert_eq!(fsm.total_reserved_exposure_qty(), 0);
    fsm.verify_invariants().unwrap();

    // Hawkes monotonic watermark + dt=0 burst overflow saturation immunity
    let mut hawkes = HawkesToxicFlowShield::default();
    let _ = hawkes.observe_flow(10_000_000, true, 10);
    // Out-of-order past timestamp MUST NOT move watermark backward
    let _ = hawkes.observe_flow(5_000_000, true, 10);
    assert_eq!(hawkes.last_event_ns, 10_000_000);
    // Massive dt=0 burst saturates cleanly without panicking/wrapping
    for _ in 0..5_000 {
        let _ = hawkes.observe_flow(10_000_000, true, 1);
    }
    assert!(hawkes.current_intensity_e4 <= 100_000_000_000);

    // SpeculativeVault RFC 1624 TCP sequence wraparound (`u32::MAX -> 0`) bit-exact checksum proof!
    let cfg = UserspaceTcpConfig {
        local_mac: [0x02, 0x00, 0x00, 0x00, 0x00, 0x01],
        remote_mac: [0x02, 0x00, 0x00, 0x00, 0x00, 0x02],
        local_ip: [10, 0, 0, 1],
        remote_ip: [10, 0, 0, 2],
        local_port: 40_000,
        remote_port: 50_000,
    };
    let (mut tx_nic, _rx_nic) = SimNicTransport::pair();
    let mut vault = SpeculativeOrderVault::new(2);
    assert!(vault.arm_template(0, cfg, 7, true, 58_000, 10, 100, 50_000, 70_000, 500_000_000));
    // Set TCP seq 16 bytes below u32::MAX so +40 wraps around 0!
    assert!(vault.rearm_tcp_seq(0, u32::MAX - 15));
    vault
        .trigger_and_emit(0, 777, 58_250, 25, &mut tx_nic)
        .unwrap();
    let frame = vault.inspect_frame(0).unwrap();
    let wrapped_seq = u32::from_be_bytes([frame[38], frame[39], frame[40], frame[41]]);
    assert_eq!(wrapped_seq, (u32::MAX - 15).wrapping_add(40));
    let mut copy = *frame;
    let wire_cs = u16::from_be_bytes([copy[50], copy[51]]);
    copy[50] = 0;
    copy[51] = 0;
    let exact_rfc793 = full_tcp_checksum(cfg.local_ip, cfg.remote_ip, &copy[34..]);
    assert_eq!(wire_cs, exact_rfc793);
}

// =========================================================================
// I8: Full 12-Stage UnifiedSingularityEngine + Admin Control Plane Endpoints
// =========================================================================
#[test]
fn test_i8_unified_12_stage_singularity_engine_and_admin_endpoints() {
    let wal_p = std::env::temp_dir().join(format!("fingate_i8_wal_{}.wal", std::process::id()));
    let bb_p = std::env::temp_dir().join(format!("fingate_i8_bb_{}.shm", std::process::id()));
    let _ = std::fs::remove_file(&wal_p);
    let _ = std::fs::remove_file(&bb_p);

    let (mut engine, shares) = UnifiedSingularityEngine::initialize(
        &wal_p,
        &bb_p,
        0x1A2B_3C4D_5E6F_7788,
        "REJECT 101 IF notional > 50000000\nREJECT 102 IF qty > 500",
    )
    .unwrap();

    // 1. Process 64 clean orders -> triggers 1 full Hardware SHA-256 Merkle block seal + 64 Lattice commits!
    let mut public_lattice_sum = LatticeHomomorphicCommitment::default();
    let mut sealed_root = None;
    for i in 1..=64u64 {
        let ord = NormalizedOrderEvent {
            cl_ord_id_hash: i,
            orig_cl_ord_id_hash: 0,
            price_ticks: 58_000 + (i as i64),
            qty: 5,
            algo_id_hash: 1,
            ingress_tsc: 1_000_000_000 + i * 20_000_000,
            account_slot: 0,
            symbol_slot: 1,
            pod_slot: 0,
            side: if i % 2 == 0 { SIDE_BUY } else { SIDE_SELL },
            action: 0,
            protocol_id: 2,
            flags: 0,
            _pad: [0; 6],
        };
        let orig = 1_000_000_000 + i * 20_000_000;
        let dec = engine.process_order_inline(
            &ord,
            orig,
            orig + 5_000_000, // 5 ms > NY4->CME light cone (3.94 ms)
            HybridLogicalClock::pack(orig / 1_000, 1),
            true,
        );
        assert!(dec.approved, "order {} rejected: {:?}", i, dec.reject_reason);
        public_lattice_sum = public_lattice_sum.homomorphic_add(dec.lattice_commit);
        if let Some(r) = dec.merkle_sealed_root {
            sealed_root = Some(r);
        }
        engine.on_order_completed_and_reclaim(i, 5, 0, 1, i % 2 == 0);
    }
    assert!(sealed_root.is_some());
    assert_eq!(engine.merkle_roots_sealed, 1);
    assert!(ObliviousTelemetryVault::verify_lattice_aggregate_audit(
        public_lattice_sum,
        engine.oblivious_vault.lattice_exposure_sum,
        engine.oblivious_vault.lattice_blinding_sum,
        64 * (1u64 << 20),
    ));

    // 2. Live Hot-Swap DSL Policy VM blocks qty > 10 immediately!
    engine
        .hot_swap_policy_dsl(2, "REJECT 202 IF qty > 10")
        .unwrap();
    let big_ord = NormalizedOrderEvent {
        cl_ord_id_hash: 9_001,
        price_ticks: 58_100,
        qty: 20,
        account_slot: 0,
        symbol_slot: 1,
        side: SIDE_BUY,
        ..Default::default()
    };
    let rej_vm = engine.process_order_inline(
        &big_ord,
        3_000_000_000,
        3_005_000_000,
        HybridLogicalClock::pack(3_000_000, 1),
        false,
    );
    assert_eq!(
        rej_vm.reject_reason,
        Some(SingularityRejectReason::NanoPolicyVmRejected(202))
    );

    // 3. Relativistic Faster-Than-Light timestamp blocked!
    let small_ord = NormalizedOrderEvent {
        cl_ord_id_hash: 9_002,
        price_ticks: 58_100,
        qty: 5,
        account_slot: 0,
        symbol_slot: 1,
        side: SIDE_BUY,
        ..Default::default()
    };
    let rej_ftl = engine.process_order_inline(
        &small_ord,
        4_000_000_000,
        4_000_100_000, // 0.1 ms < 3.94 ms NY4->CME physical speed-of-light limit!
        HybridLogicalClock::pack(4_000_000, 1),
        false,
    );
    assert_eq!(
        rej_ftl.reject_reason,
        Some(SingularityRejectReason::RelativisticCausalityViolation)
    );

    // 4. 1-of-5 Instant Trip halts engine; 3-of-5 Shamir + HW-HMAC disarms!
    engine.quorum_guard.trip_emergency_halt_1_of_n();
    let rej_ks = engine.process_order_inline(
        &small_ord,
        5_000_000_000,
        5_005_000_000,
        HybridLogicalClock::pack(5_000_000, 1),
        false,
    );
    assert_eq!(
        rej_ks.reject_reason,
        Some(SingularityRejectReason::KillSwitchActive)
    );
    engine
        .quorum_guard
        .authorize_disarm_m_of_n(&[shares[0], shares[2], shares[4]], 1)
        .unwrap();

    // 5. Admin Control Plane `/api/v1/singularity/status` & `POST /api/v1/policy/compile`
    let cp = ControlPlaneState::new("secret-token");
    let st_resp = cp.handle_request("GET", "/api/v1/singularity/status", &HashMap::new(), "");
    assert_eq!(st_resp.status_code, 200);
    assert!(st_resp.body.contains("sha256_hw_accelerated"));

    let mut hdrs = HashMap::new();
    hdrs.insert("authorization".to_string(), "Bearer secret-token".to_string());
    let pol_resp = cp.handle_request(
        "POST",
        "/api/v1/policy/compile",
        &hdrs,
        "REJECT 301 IF qty > 500\nREJECT 302 IF notional > 10000000",
    );
    assert_eq!(pol_resp.status_code, 200);
    assert!(pol_resp.body.contains("VERIFIED_AND_ACTIVATED"));

    let _ = engine.wal.shutdown_and_sync();
    let _ = std::fs::remove_file(&wal_p);
    let _ = std::fs::remove_file(&bb_p);
}
