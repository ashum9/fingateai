//! Phase C9: NVIDIA BlueField-3 DPU Companion Vault & Autonomous Dead-Man Watchdog (`fingate::dpu`).
//!
//! Runs completely off the Host x86 trading CPU:
//! 1. Ingests 128-byte `DpuTelemetrySlot` frames from `DpuRingConsumer`, verifies `CRC32C`,
//!    and tracks the independent live working order ledger.
//! 2. Monitors `host_heartbeat_ns`: if the Host trading server panics (`SIGKILL` / hang)
//!    for longer than `dead_man_timeout_ns`, the DPU autonomously synthesizes byte-exact
//!    FIX `35=q` + individual `35=F` cancellation frames for every open order without host help!

pub mod dma_ring;

use crate::dpu::dma_ring::{
    DpuRingConsumer, DPU_VERDICT_APPROVED, DPU_VERDICT_CANCELLED, DPU_VERDICT_FILLED,
};
use crate::killswitch::layers::{build_mass_cancel_frame_into, build_single_cancel_frame_into};
use std::collections::HashMap;
use std::sync::atomic::Ordering;

/// Autonomous SmartNIC/DPU Companion Agent (off-host compliance vault + dead-man COD).
pub struct DpuCompanionAgent {
    consumer: DpuRingConsumer,
    pub dead_man_timeout_ns: u64,
    /// Independent DPU-side working order inventory: `cl_ord_id_hash -> wire_cl_ord_id`.
    pub open_working_orders: HashMap<u64, String>,
    /// Emitted autonomous FIX cancel frames upon Host dead-man failover.
    pub emitted_cancel_frames: Vec<Vec<u8>>,
}

impl DpuCompanionAgent {
    pub fn new(consumer: DpuRingConsumer, dead_man_timeout_ns: u64) -> Self {
        Self {
            consumer,
            dead_man_timeout_ns,
            open_working_orders: HashMap::with_capacity(4096),
            emitted_cancel_frames: Vec::new(),
        }
    }

    /// Poll pending DMA slots, verify CRC32C integrity, update working book, and inspect host heartbeat.
    /// Returns number of autonomous cancel frames emitted if dead-man watchdog fired.
    pub fn poll_once(&mut self, current_dpu_ns: u64) -> usize {
        // 1. Drain wait-free Host->DPU DMA ring
        while let Some(slot) = self.consumer.rx.try_pop() {
            if !slot.verify_crc() {
                self.consumer.ctrl.dpu_crc_errors.fetch_add(1, Ordering::Relaxed);
                continue;
            }
            self.consumer
                .ctrl
                .dpu_slots_verified
                .fetch_add(1, Ordering::Relaxed);

            match slot.verdict {
                DPU_VERDICT_APPROVED => {
                    self.open_working_orders
                        .insert(slot.cl_ord_id_hash, slot.wire_id_str().to_string());
                }
                DPU_VERDICT_FILLED | DPU_VERDICT_CANCELLED => {
                    self.open_working_orders.remove(&slot.cl_ord_id_hash);
                }
                _ => {}
            }
        }

        // 2. Check Host Dead-Man Watchdog (explicit crash or missed heartbeat window)
        if self.consumer.ctrl.dpu_dead_man_triggered.load(Ordering::Relaxed) {
            return 0;
        }
        let host_alive = self.consumer.ctrl.host_alive.load(Ordering::Acquire);
        let last_hb = self.consumer.ctrl.host_heartbeat_ns.load(Ordering::Acquire);
        let heartbeat_expired = current_dpu_ns.saturating_sub(last_hb) > self.dead_man_timeout_ns;

        if !host_alive || heartbeat_expired {
            self.trigger_autonomous_host_crash_cancels()
        } else {
            0
        }
    }

    /// Autonomously emit `35=q` + byte-exact `35=F` cancellations directly from DPU memory.
    fn trigger_autonomous_host_crash_cancels(&mut self) -> usize {
        self.consumer
            .ctrl
            .dpu_dead_man_triggered
            .store(true, Ordering::SeqCst);

        let mut emitted = 0usize;
        let mut buf = [0u8; 160];

        // 1. Emit global FIX 4.4 OrderMassCancelRequest (35=q)
        let mass_len = build_mass_cancel_frame_into("DPU-DEADMAN-KILL", &mut buf);
        self.emitted_cancel_frames.push(buf[..mass_len].to_vec());
        emitted += 1;

        // 2. Emit surgical FIX 4.4 OrderCancelRequest (35=F) for every open working order
        let mut active_wires: Vec<String> = self.open_working_orders.values().cloned().collect();
        active_wires.sort();
        for (idx, wire_id) in active_wires.iter().enumerate() {
            let flen = build_single_cancel_frame_into(idx, wire_id, &mut buf);
            self.emitted_cancel_frames.push(buf[..flen].to_vec());
            emitted += 1;
        }
        self.open_working_orders.clear();

        self.consumer
            .ctrl
            .dpu_autonomous_cancels_emitted
            .store(emitted as u64, Ordering::SeqCst);
        emitted
    }
}
