// Phase C10: Canonical 64-Byte PCIe BAR0 Shadow Register ABI (Matches `src/hw_sync/bar0.rs`).
#pragma once

#include <cstddef>
#include <cstdint>

static constexpr uint32_t FINGATE_BAR0_MAGIC = 0x46474857u; // "FGHW"

struct alignas(64) FpgaBar0Registers {
    uint32_t magic_ver;              // 0..4
    uint32_t global_kill_mask;       // 4..8   (Bit 0 = hard 1-cycle TX drop)
    uint64_t max_order_qty;          // 8..16
    uint64_t max_order_notional;     // 16..24
    uint64_t price_collar_min;       // 24..32
    uint64_t price_collar_max;       // 32..40
    uint32_t gcra_max_ops_window;    // 40..44
    uint32_t gcra_window_cycles;     // 44..48
    uint64_t epoch_seq;              // 48..56 (Odd = writing, Even = committed seqlock)
    uint64_t telemetry_dropped_cnt;  // 56..64 (Incremented by FPGA silicon)
};

static_assert(sizeof(FpgaBar0Registers) == 64, "PCIe BAR0 block must fit in exactly 1 cache line (64B)");
static_assert(offsetof(FpgaBar0Registers, global_kill_mask) == 4, "global_kill_mask offset mismatch");
static_assert(offsetof(FpgaBar0Registers, max_order_qty) == 8, "max_order_qty offset mismatch");
static_assert(offsetof(FpgaBar0Registers, epoch_seq) == 48, "epoch_seq offset mismatch");
static_assert(offsetof(FpgaBar0Registers, telemetry_dropped_cnt) == 56, "telemetry_dropped_cnt offset mismatch");
