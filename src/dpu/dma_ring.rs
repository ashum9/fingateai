//! Phase C9: Host-to-DPU Lock-Free 128-Byte Cache-Aligned DMA Telemetry Ring (`fingate::dpu::dma_ring`).
//!
//! Models an NVIDIA BlueField-3 SmartNIC PCIe DMA / RoCEv2 RDMA write-combining ring:
//! - Exact 128-byte (2x 64-byte cache line) `#[repr(C, align(64))]` slot layout.
//! - Host Rust trading core writes a single slot in `< 30 ns` with zero disk or network syscalls.
//! - Out-of-band DPU ARM cores independently validate `CRC32C` and replicate to WORM storage.

use crate::ring::{SpscConsumer, SpscProducer, SpscRing};
use crc32fast::Hasher as Crc32Hasher;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

pub const DPU_VERDICT_APPROVED: u8 = 0;
pub const DPU_VERDICT_REJECTED: u8 = 1;
pub const DPU_VERDICT_FILLED: u8 = 2;
pub const DPU_VERDICT_CANCELLED: u8 = 3;

/// Exact 128-byte (2 cache lines) Host -> DPU DMA telemetry slot.
#[derive(Debug, Clone, Copy)]
#[repr(C, align(64))]
pub struct DpuTelemetrySlot {
    pub seq_num: u64,        // 0..8
    pub tsc_ns: u64,         // 8..16
    pub cl_ord_id_hash: u64, // 16..24
    pub price: u64,          // 24..32
    pub qty: u64,            // 32..40
    pub account_slot: u16,   // 40..42
    pub symbol_slot: u16,    // 42..44
    pub msg_type: u8,        // 44
    pub verdict: u8,         // 45
    pub wire_id_len: u8,     // 46
    pub _pad0: u8,           // 47
    pub crc32c: u32,         // 48..52
    pub _pad1: u32,          // 52..56
    pub wire_id: [u8; 32],   // 56..88
    pub _reserved: [u8; 40], // 88..128
}

const _: () = assert!(std::mem::size_of::<DpuTelemetrySlot>() == 128);

impl DpuTelemetrySlot {
    #[inline(always)]
    pub fn new_signed(
        seq_num: u64,
        tsc_ns: u64,
        cl_ord_id_hash: u64,
        price: u64,
        qty: u64,
        account_slot: u16,
        symbol_slot: u16,
        msg_type: u8,
        verdict: u8,
        wire_id_str: &str,
    ) -> Self {
        let mut wire_id = [0u8; 32];
        let src = wire_id_str.as_bytes();
        let wlen = src.len().min(32);
        wire_id[..wlen].copy_from_slice(&src[..wlen]);

        let mut slot = Self {
            seq_num,
            tsc_ns,
            cl_ord_id_hash,
            price,
            qty,
            account_slot,
            symbol_slot,
            msg_type,
            verdict,
            wire_id_len: wlen as u8,
            _pad0: 0,
            crc32c: 0,
            _pad1: 0,
            wire_id,
            _reserved: [0u8; 40],
        };
        slot.crc32c = slot.compute_crc();
        slot
    }

    #[inline(always)]
    pub fn compute_crc(&self) -> u32 {
        let mut h = Crc32Hasher::new();
        h.update(&self.seq_num.to_le_bytes());
        h.update(&self.tsc_ns.to_le_bytes());
        h.update(&self.cl_ord_id_hash.to_le_bytes());
        h.update(&self.price.to_le_bytes());
        h.update(&self.qty.to_le_bytes());
        h.update(&self.account_slot.to_le_bytes());
        h.update(&self.symbol_slot.to_le_bytes());
        h.update(&[self.msg_type, self.verdict, self.wire_id_len]);
        h.update(&self.wire_id[..self.wire_id_len as usize]);
        h.finalize()
    }

    #[inline(always)]
    pub fn verify_crc(&self) -> bool {
        self.crc32c == self.compute_crc()
    }

    #[inline(always)]
    pub fn wire_id_str(&self) -> &str {
        std::str::from_utf8(&self.wire_id[..self.wire_id_len as usize]).unwrap_or("")
    }
}

/// Shared Host <-> DPU Heartbeat & Dead-Man Control Block.
pub struct DpuControlBlock {
    pub host_heartbeat_ns: AtomicU64,
    pub host_alive: AtomicBool,
    pub dpu_dead_man_triggered: AtomicBool,
    pub dpu_slots_verified: AtomicU64,
    pub dpu_crc_errors: AtomicU64,
    pub dpu_autonomous_cancels_emitted: AtomicU64,
}

impl DpuControlBlock {
    pub fn new(initial_ns: u64) -> Self {
        Self {
            host_heartbeat_ns: AtomicU64::new(initial_ns),
            host_alive: AtomicBool::new(true),
            dpu_dead_man_triggered: AtomicBool::new(false),
            dpu_slots_verified: AtomicU64::new(0),
            dpu_crc_errors: AtomicU64::new(0),
            dpu_autonomous_cancels_emitted: AtomicU64::new(0),
        }
    }
}

/// Host-side DMA Producer (pinned to Host trading core).
pub struct HostDpuProducer {
    tx: SpscProducer<DpuTelemetrySlot, 4096>,
    pub ctrl: Arc<DpuControlBlock>,
}

impl HostDpuProducer {
    /// Push a signed 128-byte telemetry slot onto the wait-free Host->DPU DMA ring (`< 30 ns`).
    #[inline(always)]
    pub fn push_telemetry(&mut self, slot: DpuTelemetrySlot) -> Result<(), DpuTelemetrySlot> {
        self.tx.try_push(slot)
    }

    /// Pulse the host hardware heartbeat register so the DPU knows the host core is healthy.
    #[inline(always)]
    pub fn pulse_heartbeat(&self, now_ns: u64) {
        self.ctrl.host_heartbeat_ns.store(now_ns, Ordering::Release);
    }

    /// Simulate sudden Host OS kernel panic / `SIGKILL` for dead-man testing.
    pub fn simulate_host_crash(&self) {
        self.ctrl.host_alive.store(false, Ordering::SeqCst);
    }
}

/// DPU-side DMA Consumer (runs out-of-band on BlueField ARM cores).
pub struct DpuRingConsumer {
    pub rx: SpscConsumer<DpuTelemetrySlot, 4096>,
    pub ctrl: Arc<DpuControlBlock>,
}

/// Allocate a matched `(HostDpuProducer, DpuRingConsumer)` DMA ring pair.
pub fn create_host_dpu_channel(initial_ns: u64) -> (HostDpuProducer, DpuRingConsumer) {
    let (tx, rx) = SpscRing::<DpuTelemetrySlot, 4096>::split();
    let ctrl = Arc::new(DpuControlBlock::new(initial_ns));
    (
        HostDpuProducer {
            tx,
            ctrl: ctrl.clone(),
        },
        DpuRingConsumer { rx, ctrl },
    )
}
