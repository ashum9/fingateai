//! Month 1, Week 3: Native Rust Procedural Seeded Chaos Generator & Live Loopback TCP Chaos Harness.
//!
//! Provides:
//! 1. `generate_chaos_scenario_rust(seed: u64)`: Synthesizes deterministic multi-fault FIX 4.4
//!    scenarios driven by `SimEnv` at >1,000 seeds/sec.
//! 2. `run_tcp_loopback_chaos_session(seed: u64)`: Spins up an actual Tokio TCP Exchange Chaos
//!    Twin on `127.0.0.1:0`, injects TCP packet fragmentation (half-frames across `write_all`),
//!    Nagle multi-frame coalescing, corrupted CheckSum frames (`F_WIRE_01`), and sequence gaps
//!    over a live socket, verifying full wire recovery.

use crate::env::{Env, SimEnv};
use crate::fix::invariants::verify_all_invariants;
use crate::fix::session::{Fix44SessionEngine, SessionTraceResult};
use crate::fix::wire::{FixFrameBuilder, FixTcpDefragmenter};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcpChaosSessionSummary {
    pub seed: u64,
    pub tcp_chunks_transmitted: usize,
    pub valid_frames_decoded: usize,
    pub garbled_frames_dropped: usize,
    pub outbound_responses_emitted: usize,
    pub final_status: String,
    pub next_sender_seq_num: u64,
    pub next_target_seq_num: u64,
    pub invariant_violations: Vec<String>,
}

/// Procedurally synthesize a deterministic multi-fault FIX 4.4 scenario and its verified reference
/// using `SimEnv::new(seed)` in native Rust.
pub fn generate_chaos_scenario_rust(seed: u64) -> anyhow::Result<(Value, SessionTraceResult)> {
    let sim = Arc::new(SimEnv::new(seed));

    let init_sender_seq = 6 + (sim.next_u64() % 12); // 6..17
    let init_target_seq = 4 + (sim.next_u64() % 10); // 4..13
    let hb_int_ms = match sim.next_u64() % 3 {
        0 => 15_000,
        1 => 30_000,
        _ => 60_000,
    };
    let grace_ms = 5_000u64;

    let mut outbound_store = Vec::new();
    let mut order_idx = 100u64;
    for seq in 1..init_sender_seq {
        let mtype = if seq == 1 {
            "A"
        } else {
            match sim.next_u64() % 5 {
                0 => "0",
                1 => "1",
                2 => "3",
                3 => "D",
                _ => "F",
            }
        };
        let mut item = json!({
            "msg_seq_num": seq,
            "msg_type": mtype,
            "send_time_ms": seq * 100,
        });
        if mtype == "D" || mtype == "F" {
            item["cl_ord_id"] = json!(format!("ORD-S{}-{}", seed, order_idx));
            order_idx += 1;
        }
        outbound_store.push(item);
    }

    let working_orders = json!([
        {
            "cl_ord_id": format!("SHIELD-{}-1", seed),
            "pod_id": "pod-alpha",
            "symbol": "BTC-USD",
            "side": "BUY",
            "leaves_qty": 5,
            "status": "WORKING"
        },
        {
            "cl_ord_id": format!("SHIELD-{}-2", seed),
            "pod_id": "pod-alpha",
            "symbol": "ETH-USD",
            "side": "SELL",
            "leaves_qty": 10,
            "status": "WORKING"
        }
    ]);

    let mut events = Vec::new();
    let mut now_ms = init_sender_seq * 100 + 500;
    let mut cur_target_seq = init_target_seq;

    // 1. Fault F_WIRE_01: Inject a garbled wire frame (corrupted CheckSum or BodyLength)
    {
        let corrupt_cs = (sim.next_u64() & 1) == 0;
        let mut b = FixFrameBuilder::new();
        b.push_str(35, "8")
            .push_u64(34, cur_target_seq)
            .push_str(49, "EXCHANGE")
            .push_str(56, "FINGATE")
            .push_u64(52, now_ms);
        let raw_wire = b.finish_pipe_string(corrupt_cs, !corrupt_cs);
        events.push(json!({
            "timestamp_ms": now_ms,
            "event_type": "RECV_MSG",
            "msg_type": "8",
            "msg_seq_num": cur_target_seq,
            "poss_dup_flag": false,
            "garbled": true,
            "raw_wire": raw_wire,
        }));
        now_ms += 100;
    }

    // 2. Fault F_SEQ_05: PossDupFlag=Y missing OrigSendingTime (122) -> SessionReject (35=3, 373=1)
    if (sim.next_u64() % 2) == 0 {
        events.push(json!({
            "timestamp_ms": now_ms,
            "event_type": "RECV_MSG",
            "msg_type": "8",
            "msg_seq_num": cur_target_seq,
            "poss_dup_flag": true,
            "orig_sending_time_ms": Value::Null,
        }));
        cur_target_seq += 1;
        now_ms += 120;
    }

    // 3. Fault F_SEQ_01: ResendRequest across interleaved Admin (0, 1, 3) & App (D, F) history
    {
        let begin_no = 2 + (sim.next_u64() % (init_sender_seq.saturating_sub(3).max(1)));
        let end_no = if (sim.next_u64() & 1) == 0 {
            0
        } else {
            init_sender_seq - 1
        };
        events.push(json!({
            "timestamp_ms": now_ms,
            "event_type": "RECV_MSG",
            "msg_type": "2",
            "msg_seq_num": cur_target_seq,
            "poss_dup_flag": false,
            "begin_seq_no": begin_no,
            "end_seq_no": end_no,
        }));
        cur_target_seq += 1;
        now_ms += 150;
    }

    // 4. Fault F_SEQ_02: Out-of-order SequenceReset-GapFill (35=4, 123=Y) arriving ahead of missing seq
    {
        let missing_seq = cur_target_seq;
        let future_gf_seq = cur_target_seq + 1;
        let jump_to = cur_target_seq + 4;

        events.push(json!({
            "timestamp_ms": now_ms,
            "event_type": "RECV_MSG",
            "msg_type": "4",
            "msg_seq_num": future_gf_seq,
            "poss_dup_flag": true,
            "orig_sending_time_ms": now_ms - 50,
            "gap_fill_flag": true,
            "new_seq_no": jump_to,
        }));
        now_ms += 100;

        events.push(json!({
            "timestamp_ms": now_ms,
            "event_type": "RECV_MSG",
            "msg_type": "8",
            "msg_seq_num": missing_seq,
            "poss_dup_flag": true,
            "orig_sending_time_ms": now_ms - 150,
            "cl_ord_id": format!("SHIELD-{}-1", seed),
            "leaves_qty": 0,
        }));
        cur_target_seq = jump_to;
        now_ms += 150;
    }

    // 5. Fault F_ORD_01: Pod crash + grace timeout expiration cancelling only remaining working order
    {
        events.push(json!({
            "timestamp_ms": now_ms,
            "event_type": "POD_CRASH",
            "pod_id": "pod-alpha",
        }));
        now_ms += grace_ms + 100;
        events.push(json!({
            "timestamp_ms": now_ms,
            "event_type": "CLOCK_TICK",
        }));
        let _ = cur_target_seq;
    }

    let task_spec = json!({
        "task_id": format!("CHAOS_RUST_{}", seed),
        "seed": seed,
        "engine_config": {
            "heart_bt_int_ms": hb_int_ms,
            "test_request_grace_ms": hb_int_ms,
            "send_redundant_resend_requests": false,
            "pod_grace_timeout_ms": grace_ms,
        },
        "initial_store": {
            "status": "ACTIVE",
            "next_sender_seq_num": init_sender_seq,
            "next_target_seq_num": init_target_seq,
            "last_sent_time_ms": init_sender_seq * 100,
            "last_recv_time_ms": init_sender_seq * 100,
            "outbound_messages_store": outbound_store,
            "working_orders": working_orders,
        },
        "inbound_event_trace": events,
    });

    let mut engine = Fix44SessionEngine::from_task_json(&task_spec, sim)?;
    let events_slice = task_spec["inbound_event_trace"].as_array().unwrap();
    let result = engine.run_trace(events_slice);

    let inv = verify_all_invariants(&task_spec, &result);
    if !inv.passed {
        anyhow::bail!(
            "Generated chaos seed {} violated invariants: {:?}",
            seed,
            inv.violations
        );
    }

    Ok((task_spec, result))
}

/// Run a live loopback TCP chaos session where an Exchange Chaos Twin sends split half-frames,
/// Nagle-coalesced multi-frames, a corrupted CheckSum frame (`F_WIRE_01`), and a `ResendRequest`
/// over a real OS TCP socket to `FixTcpDefragmenter` + `Fix44SessionEngine`.
pub async fn run_tcp_loopback_chaos_session(seed: u64) -> anyhow::Result<TcpChaosSessionSummary> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;

    // Build initial task spec for the receiving engine
    let (task_spec, _) = generate_chaos_scenario_rust(seed)?;
    let init_target_seq = task_spec["initial_store"]["next_target_seq_num"]
        .as_u64()
        .unwrap_or(5);

    // Spawn the Exchange Chaos Twin TCP sender
    let sender_handle = tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await?;
        let mut chunks_sent = 0usize;

        // Frame 1: TestRequest (35=1, seq=init_target_seq) split into TWO separate TCP writes (half-frame test!)
        let mut b1 = FixFrameBuilder::new();
        b1.push_str(35, "1")
            .push_u64(34, init_target_seq)
            .push_str(49, "EXCHANGE")
            .push_str(56, "FINGATE")
            .push_u64(52, 2000)
            .push_str(112, "PING-TCP-1");
        let f1 = b1.finish_soh_bytes(false, false);
        let split_at = f1.len() / 2;
        sock.write_all(&f1[..split_at]).await?;
        chunks_sent += 1;
        tokio::task::yield_now().await;
        sock.write_all(&f1[split_at..]).await?;
        chunks_sent += 1;

        // Frame 2 (GARBLED CheckSum `F_WIRE_01`) + Frame 3 (Valid ResendRequest `35=2`) coalesced in a SINGLE TCP write!
        let mut b2_garbled = FixFrameBuilder::new();
        b2_garbled
            .push_str(35, "0")
            .push_u64(34, init_target_seq + 1)
            .push_str(49, "EXCHANGE")
            .push_str(56, "FINGATE")
            .push_u64(52, 2100);
        let f2_garbled = b2_garbled.finish_soh_bytes(true, false); // Corrupted CheckSum!

        let mut b3_resend = FixFrameBuilder::new();
        b3_resend
            .push_str(35, "2")
            .push_u64(34, init_target_seq + 1) // Same seq_num because f2_garbled must NOT increment NextTargetMsgSeqNum!
            .push_str(49, "EXCHANGE")
            .push_str(56, "FINGATE")
            .push_u64(52, 2200)
            .push_u64(7, 2)
            .push_u64(16, 0);
        let f3_resend = b3_resend.finish_soh_bytes(false, false);

        let mut coalesced = Vec::with_capacity(f2_garbled.len() + f3_resend.len());
        coalesced.extend_from_slice(&f2_garbled);
        coalesced.extend_from_slice(&f3_resend);
        sock.write_all(&coalesced).await?;
        chunks_sent += 1;

        sock.shutdown().await?;
        Ok::<usize, anyhow::Error>(chunks_sent)
    });

    // Client connects to the Exchange Chaos Twin and feeds raw TCP reads into `FixTcpDefragmenter` + `Fix44SessionEngine`
    let mut client = TcpStream::connect(addr).await?;
    let sim = Arc::new(SimEnv::new(seed));
    let mut engine = Fix44SessionEngine::from_task_json(&task_spec, sim)?;
    let mut defrag = FixTcpDefragmenter::new();

    let mut read_buf = [0u8; 64];
    let mut now_ms = 2000u64;
    let mut valid_decoded = 0usize;

    loop {
        let n = client.read(&mut read_buf).await?;
        if n == 0 {
            break;
        }
        let frames = defrag.feed(&read_buf[..n]);
        for raw_frame in frames {
            let before_garbled = engine.garbled_frames_dropped;
            engine.step_wire_bytes(&raw_frame, now_ms);
            if engine.garbled_frames_dropped == before_garbled {
                valid_decoded += 1;
            }
            now_ms += 100;
        }
    }

    let chunks_sent = sender_handle.await??;
    let trace_res = SessionTraceResult {
        outbound_messages: engine.emitted_messages.clone(),
        final_state: crate::fix::session::FinalSessionState {
            status: engine.status.clone(),
            next_sender_seq_num: engine.next_sender_seq_num,
            next_target_seq_num: engine.next_target_seq_num,
            disconnect_time_ms: engine.disconnect_time_ms,
        },
    };
    let inv = verify_all_invariants(&task_spec, &trace_res);

    Ok(TcpChaosSessionSummary {
        seed,
        tcp_chunks_transmitted: chunks_sent,
        valid_frames_decoded: valid_decoded,
        garbled_frames_dropped: engine.garbled_frames_dropped,
        outbound_responses_emitted: engine.emitted_messages.len(),
        final_status: engine.status,
        next_sender_seq_num: engine.next_sender_seq_num,
        next_target_seq_num: engine.next_target_seq_num,
        invariant_violations: inv.violations,
    })
}
