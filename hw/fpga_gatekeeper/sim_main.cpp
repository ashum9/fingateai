// Phase C10: C++ PCIe BAR0 ABI & Verilator Hardware-in-the-Loop Driver (`sim_main.cpp`).
//
// Builds standalone ABI verifier with any C++17 compiler:
//   c++ -std=c++17 hw/fpga_gatekeeper/sim_main.cpp -o target/fpga_abi_check && ./target/fpga_abi_check
// Or links with Verilator RTL model when `-DWITH_VERILATOR` is passed.

#include "bar0_abi.h"
#include <cassert>
#include <cstdio>

#ifdef WITH_VERILATOR
#include "Vfingate_edge_gatekeeper.h"
#include "verilated.h"
#endif

int main(int argc, char** argv) {
    (void)argc;
    (void)argv;

    // 1. Verify exact 64-byte PCIe BAR0 ABI matches Rust `src/hw_sync/bar0.rs`
    FpgaBar0Registers bar0{};
    bar0.magic_ver = FINGATE_BAR0_MAGIC;
    bar0.global_kill_mask = 0;
    bar0.max_order_qty = 1000;
    bar0.max_order_notional = 100000000ULL;
    bar0.price_collar_min = 90000;
    bar0.price_collar_max = 100000;
    bar0.gcra_max_ops_window = 10;
    bar0.gcra_window_cycles = 250000;
    bar0.epoch_seq = 2;
    bar0.telemetry_dropped_cnt = 0;

    assert(sizeof(bar0) == 64);
    assert(bar0.magic_ver == 0x46474857u);
    std::printf("[PASS] C++ PCIe BAR0 ABI verified: sizeof=%zu bytes, magic=0x%08X\n",
                sizeof(bar0), bar0.magic_ver);

#ifdef WITH_VERILATOR
    Verilated::commandArgs(argc, argv);
    auto* dut = new Vfingate_edge_gatekeeper;
    auto tick = [&]() {
        dut->clk = 0; dut->eval();
        dut->clk = 1; dut->eval();
    };

    dut->rst_n = 0;
    tick();
    dut->rst_n = 1;

    dut->bar0_global_kill_mask    = 0;
    dut->bar0_max_order_qty       = 1000;
    dut->bar0_max_order_notional  = 100000000ULL;
    dut->bar0_price_collar_min    = 90000;
    dut->bar0_price_collar_max    = 100000;
    dut->bar0_gcra_max_ops_window = 10;
    dut->bar0_gcra_window_cycles  = 1000;

    // Valid order -> passes after 4 clock cycles (16 ns @ 250 MHz)
    dut->axis_in_tvalid = 1;
    dut->axis_in_order_qty = 5;
    dut->axis_in_order_price = 95000;
    tick();
    dut->axis_in_tvalid = 0;
    tick(); tick(); tick();
    assert(dut->axis_out_tvalid == 1);
    assert(dut->axis_out_verdict == 0);

    // Flip Kill Bit 0 -> blocked in 4 clock cycles
    dut->bar0_global_kill_mask = 1;
    dut->axis_in_tvalid = 1;
    dut->axis_in_order_qty = 5;
    dut->axis_in_order_price = 95000;
    tick();
    dut->axis_in_tvalid = 0;
    tick(); tick(); tick();
    assert(dut->axis_out_tvalid == 0);
    assert(dut->axis_out_verdict == 1);
    assert(dut->bar0_telemetry_dropped_cnt == 1);
    std::printf("[PASS] Verilator SystemVerilog RTL verified: 4-cycle (16 ns) edge drop on KillBit\n");
    delete dut;
#endif

    return 0;
}
