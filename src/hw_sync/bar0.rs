//! Phase C10: 64-Byte Cache-Aligned PCIe `BAR0` Shadow Register ABI & 4-Cycle Silicon Gatekeeper Model.
//!
//! Synchronizes FinGate's pinned Host Rust stateful risk core with an inline FPGA/SmartNIC
//! edge gatekeeper (`hw/fpga_gatekeeper/gatekeeper.sv`) via an odd-even hardware **Seqlock**:
//! - Exact 64-byte (`1` PCIe TLP cache-line) `#[repr(C, align(64))]` binary layout matching `bar0_abi.h`.
//! - Host Rust updates limits or flips `global_kill_mask` Bit 0 in `< 20 ns`.
//! - FPGA silicon evaluates `KillBit`, `MaxQty`, `MaxNotional`, `PriceCollar`, and hardware `GCRA`
//!   in **4 clock cycles (`16 ns @ 250 MHz`)** before packets ever leave the PHY edge.

use std::sync::atomic::{fence, AtomicU32, AtomicU64, Ordering};

pub const BAR0_MAGIC_VER: u32 = 0x4647_4857; // "FGHW"

/// Exact 64-byte PCIe `BAR0` memory-mapped register block matching `hw/fpga_gatekeeper/bar0_abi.h`.
#[repr(C, align(64))]
pub struct FpgaBar0Registers {
    pub magic_ver: AtomicU32,             // 0..4   (0x4647_4857)
    pub global_kill_mask: AtomicU32,      // 4..8   (Bit 0 = hard 1-cycle TX drop)
    pub max_order_qty: AtomicU64,         // 8..16
    pub max_order_notional: AtomicU64,    // 16..24
    pub price_collar_min: AtomicU64,      // 24..32
    pub price_collar_max: AtomicU64,      // 32..40
    pub gcra_max_ops_window: AtomicU32,   // 40..44
    pub gcra_window_cycles: AtomicU32,    // 44..48
    pub epoch_seq: AtomicU64,             // 48..56 (Odd = host writing, Even = committed)
    pub telemetry_dropped_cnt: AtomicU64, // 56..64 (Written by FPGA silicon, read by Host)
}

const _: () = assert!(std::mem::size_of::<FpgaBar0Registers>() == 64);

/// Tear-free snapshot of `BAR0` shadow limits read by hardware or host diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bar0Snapshot {
    pub magic_ver: u32,
    pub global_kill_mask: u32,
    pub max_order_qty: u64,
    pub max_order_notional: u64,
    pub price_collar_min: u64,
    pub price_collar_max: u64,
    pub gcra_max_ops_window: u32,
    pub gcra_window_cycles: u32,
    pub epoch_seq: u64,
    pub telemetry_dropped_cnt: u64,
}

impl FpgaBar0Registers {
    pub fn new(
        max_order_qty: u64,
        max_order_notional: u64,
        price_collar_min: u64,
        price_collar_max: u64,
        gcra_max_ops_window: u32,
        gcra_window_cycles: u32,
    ) -> Self {
        Self {
            magic_ver: AtomicU32::new(BAR0_MAGIC_VER),
            global_kill_mask: AtomicU32::new(0),
            max_order_qty: AtomicU64::new(max_order_qty),
            max_order_notional: AtomicU64::new(max_order_notional),
            price_collar_min: AtomicU64::new(price_collar_min),
            price_collar_max: AtomicU64::new(price_collar_max),
            gcra_max_ops_window: AtomicU32::new(gcra_max_ops_window),
            gcra_window_cycles: AtomicU32::new(gcra_window_cycles),
            epoch_seq: AtomicU64::new(2), // Even = clean initial committed epoch
            telemetry_dropped_cnt: AtomicU64::new(0),
        }
    }

    /// Tear-free Host Rust seqlock publish to PCIe BAR0 registers (`< 20 ns`).
    #[inline]
    pub fn publish_limits(
        &self,
        max_order_qty: u64,
        max_order_notional: u64,
        price_collar_min: u64,
        price_collar_max: u64,
        gcra_max_ops_window: u32,
        gcra_window_cycles: u32,
    ) {
        // 1. Advance epoch to ODD (signals hardware reader that write is in progress)
        let prev = self.epoch_seq.load(Ordering::Relaxed);
        let odd = (prev & !1) + 1;
        self.epoch_seq.store(odd, Ordering::Release);
        fence(Ordering::SeqCst);

        // 2. Write shadow risk registers
        self.max_order_qty.store(max_order_qty, Ordering::Relaxed);
        self.max_order_notional.store(max_order_notional, Ordering::Relaxed);
        self.price_collar_min.store(price_collar_min, Ordering::Relaxed);
        self.price_collar_max.store(price_collar_max, Ordering::Relaxed);
        self.gcra_max_ops_window.store(gcra_max_ops_window, Ordering::Relaxed);
        self.gcra_window_cycles.store(gcra_window_cycles, Ordering::Relaxed);

        // 3. Commit EVEN epoch
        fence(Ordering::Release);
        self.epoch_seq.store(odd + 1, Ordering::Release);
    }

    /// 1-cycle emergency hardware kill switch trip (`Bit 0` -> `1`) bypassing seqlock wait.
    #[inline(always)]
    pub fn trip_silicon_kill_bit(&self) {
        self.global_kill_mask.fetch_or(1, Ordering::SeqCst);
    }

    /// Clear silicon kill switch bit (`Bit 0` -> `0`) upon authenticated admin reset.
    #[inline(always)]
    pub fn clear_silicon_kill_bit(&self) {
        self.global_kill_mask.fetch_and(!1, Ordering::SeqCst);
    }

    /// Tear-free seqlock snapshot read mirroring the FPGA RTL register latch.
    #[inline]
    pub fn read_snapshot(&self) -> Bar0Snapshot {
        loop {
            let s1 = self.epoch_seq.load(Ordering::Acquire);
            if (s1 & 1) != 0 {
                std::hint::spin_loop();
                continue;
            }
            let snap = Bar0Snapshot {
                magic_ver: self.magic_ver.load(Ordering::Relaxed),
                global_kill_mask: self.global_kill_mask.load(Ordering::Relaxed),
                max_order_qty: self.max_order_qty.load(Ordering::Relaxed),
                max_order_notional: self.max_order_notional.load(Ordering::Relaxed),
                price_collar_min: self.price_collar_min.load(Ordering::Relaxed),
                price_collar_max: self.price_collar_max.load(Ordering::Relaxed),
                gcra_max_ops_window: self.gcra_max_ops_window.load(Ordering::Relaxed),
                gcra_window_cycles: self.gcra_window_cycles.load(Ordering::Relaxed),
                epoch_seq: s1,
                telemetry_dropped_cnt: self.telemetry_dropped_cnt.load(Ordering::Relaxed),
            };
            fence(Ordering::Acquire);
            let s2 = self.epoch_seq.load(Ordering::Acquire);
            if s1 == s2 {
                return snap;
            }
        }
    }
}

/// Reason code returned by the 4-cycle FPGA edge gatekeeper (`hw/fpga_gatekeeper/gatekeeper.sv`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FpgaGateVerdict {
    Pass = 0,
    DropKillBit = 1,
    DropMaxQty = 2,
    DropPriceCollar = 3,
    DropMaxNotional = 4,
    DropGcraRate = 5,
}

/// Cycle-accurate behavioral twin of `hw/fpga_gatekeeper/gatekeeper.sv`
/// (`4` clock cycles: `16 ns @ 250 MHz` or `10 ns @ 400 MHz` Alveo UL3524/U50).
pub struct FpgaEdgeGatekeeperModel {
    pub clock_cycle: u64,
    pub window_start_cycle: u64,
    pub window_ops_count: u32,
    pub clock_period_ns: u64, // 4 ns => 250 MHz FPGA fabric (legacy field)
    pub clock_period_ps: u64, // 4000 ps = 250 MHz; 2500 ps = 400 MHz (Alveo UL3524/U50)
}

impl FpgaEdgeGatekeeperModel {
    pub const PIPELINE_LATENCY_CYCLES: u64 = 4;

    pub fn new() -> Self {
        Self {
            clock_cycle: 0,
            window_start_cycle: 0,
            window_ops_count: 0,
            clock_period_ns: 4,
            clock_period_ps: 4_000,
        }
    }

    /// Gap 5 (E5): 400 MHz AMD Alveo UL3524 / U50 target (`2.500 ns` period => `10.0 ns` total 4-cycle gate!).
    pub fn new_400mhz_alveo() -> Self {
        Self {
            clock_cycle: 0,
            window_start_cycle: 0,
            window_ops_count: 0,
            clock_period_ns: 2,
            clock_period_ps: 2_500,
        }
    }

    /// Evaluate an inbound SBE/order wire header against `BAR0` registers across 4 pipelined FPGA cycles.
    /// Returns `(FpgaGateVerdict, latency_cycles, latency_ns)`.
    #[inline]
    pub fn evaluate_order(
        &mut self,
        bar0: &FpgaBar0Registers,
        order_qty: u64,
        order_price: u64,
    ) -> (FpgaGateVerdict, u64, u64) {
        // Cycle 1: Latch BAR0 shadow registers & check Global Kill Mask Bit 0
        self.clock_cycle += 1;
        let snap = bar0.read_snapshot();
        let kill_hit = (snap.global_kill_mask & 1) != 0;

        // Cycle 2: Combinatorial Max Quantity & Price Collar comparison
        self.clock_cycle += 1;
        let qty_hit = order_qty > snap.max_order_qty;
        let collar_hit = (snap.price_collar_min > 0 && order_price < snap.price_collar_min)
            || (snap.price_collar_max > 0 && order_price > snap.price_collar_max);

        // Cycle 3: DSP48 64-bit Notional Multiply & Hardware GCRA Sliding Window Counter
        self.clock_cycle += 1;
        let notional = order_qty.saturating_mul(order_price);
        let notional_hit = notional > snap.max_order_notional;
        if snap.gcra_window_cycles > 0
            && self.clock_cycle.saturating_sub(self.window_start_cycle) >= snap.gcra_window_cycles as u64
        {
            self.window_start_cycle = self.clock_cycle;
            self.window_ops_count = 0;
        }
        let gcra_hit = snap.gcra_max_ops_window > 0 && self.window_ops_count >= snap.gcra_max_ops_window;

        // Cycle 4: AXI4-Stream `tvalid` output mux & hardware drop counter increment
        self.clock_cycle += 1;
        let verdict = if kill_hit {
            FpgaGateVerdict::DropKillBit
        } else if qty_hit {
            FpgaGateVerdict::DropMaxQty
        } else if collar_hit {
            FpgaGateVerdict::DropPriceCollar
        } else if notional_hit {
            FpgaGateVerdict::DropMaxNotional
        } else if gcra_hit {
            FpgaGateVerdict::DropGcraRate
        } else {
            self.window_ops_count += 1;
            FpgaGateVerdict::Pass
        };

        if verdict != FpgaGateVerdict::Pass {
            bar0.telemetry_dropped_cnt.fetch_add(1, Ordering::Relaxed);
        }

        let latency_cycles = Self::PIPELINE_LATENCY_CYCLES;
        let latency_ns = (latency_cycles * self.clock_period_ps) / 1_000;
        (verdict, latency_cycles, latency_ns)
    }
}
