// Phase C10: Synthesizable SystemVerilog 4-Cycle Stateless Edge Pre-Trade Gatekeeper (`gatekeeper.sv`).
//
// Target Silicon: AMD Alveo / Xilinx UltraScale+ @ 250 MHz (4 ns clock period => 16 ns total gate latency).
// Sits directly on the AXI4-Stream TX datapath ahead of the 10G/25G Ethernet MAC:
//   Stage 1: Latch BAR0 shadow registers + Global Kill Bit (Bit 0)
//   Stage 2: Max Quantity & Dynamic Price Collar check
//   Stage 3: DSP48 64-bit Notional multiply + Hardware GCRA Window Counter
//   Stage 4: AXI4-Stream `axis_out_tvalid` gate & `telemetry_dropped_cnt` increment

`timescale 1ns/1ps

module fingate_edge_gatekeeper (
    input  logic        clk,
    input  logic        rst_n,

    // PCIe BAR0 Shadow Registers (Updated asynchronously by pinned FinGate Host Rust Core)
    input  logic [31:0] bar0_global_kill_mask,
    input  logic [63:0] bar0_max_order_qty,
    input  logic [63:0] bar0_max_order_notional,
    input  logic [63:0] bar0_price_collar_min,
    input  logic [63:0] bar0_price_collar_max,
    input  logic [31:0] bar0_gcra_max_ops_window,
    input  logic [31:0] bar0_gcra_window_cycles,

    // Inbound AXI4-Stream Decoded SBE Order Descriptor
    input  logic        axis_in_tvalid,
    input  logic [63:0] axis_in_order_qty,
    input  logic [63:0] axis_in_order_price,
    output logic        axis_in_tready,

    // Outbound Gated AXI4-Stream to Ethernet MAC PHY
    output logic        axis_out_tvalid,
    output logic [63:0] axis_out_order_qty,
    output logic [63:0] axis_out_order_price,
    output logic [2:0]  axis_out_verdict,   // 0=PASS, 1=KILL, 2=QTY, 3=COLLAR, 4=NOTIONAL, 5=GCRA
    output logic [63:0] bar0_telemetry_dropped_cnt
);

    localparam logic [2:0] VERDICT_PASS     = 3'd0;
    localparam logic [2:0] VERDICT_KILL     = 3'd1;
    localparam logic [2:0] VERDICT_QTY      = 3'd2;
    localparam logic [2:0] VERDICT_COLLAR   = 3'd3;
    localparam logic [2:0] VERDICT_NOTIONAL = 3'd4;
    localparam logic [2:0] VERDICT_GCRA     = 3'd5;

    assign axis_in_tready = 1'b1; // Line-rate non-blocking 1 order/cycle pipeline

    // Stage 1 registers
    logic        s1_valid, s1_kill_hit;
    logic [63:0] s1_qty, s1_price;
    logic [63:0] s1_max_qty, s1_max_notional, s1_min_px, s1_max_px;
    logic [31:0] s1_gcra_max_ops, s1_gcra_win_cycles;

    // Stage 2 registers
    logic        s2_valid, s2_kill_hit, s2_qty_hit, s2_collar_hit;
    logic [63:0] s2_qty, s2_price, s2_max_notional;
    logic [31:0] s2_gcra_max_ops, s2_gcra_win_cycles;

    // Stage 3 registers
    logic        s3_valid, s3_kill_hit, s3_qty_hit, s3_collar_hit, s3_notional_hit, s3_gcra_hit;
    logic [63:0] s3_qty, s3_price;
    logic [63:0] cycle_counter, win_start_cycle;
    logic [31:0] win_ops_count;

    always_ff @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            s1_valid <= 1'b0;
            s2_valid <= 1'b0;
            s3_valid <= 1'b0;
            axis_out_tvalid <= 1'b0;
            axis_out_verdict <= VERDICT_PASS;
            bar0_telemetry_dropped_cnt <= 64'd0;
            cycle_counter <= 64'd0;
            win_start_cycle <= 64'd0;
            win_ops_count <= 32'd0;
        end else begin
            cycle_counter <= cycle_counter + 64'd1;

            // ---------------- Stage 1: Register Latch & Kill Bit ----------------
            s1_valid           <= axis_in_tvalid;
            s1_kill_hit        <= bar0_global_kill_mask[0];
            s1_qty             <= axis_in_order_qty;
            s1_price           <= axis_in_order_price;
            s1_max_qty         <= bar0_max_order_qty;
            s1_max_notional    <= bar0_max_order_notional;
            s1_min_px          <= bar0_price_collar_min;
            s1_max_px          <= bar0_price_collar_max;
            s1_gcra_max_ops    <= bar0_gcra_max_ops_window;
            s1_gcra_win_cycles <= bar0_gcra_window_cycles;

            // ---------------- Stage 2: Max Qty & Price Collar ----------------
            s2_valid           <= s1_valid;
            s2_kill_hit        <= s1_kill_hit;
            s2_qty_hit         <= (s1_qty > s1_max_qty);
            s2_collar_hit      <= ((s1_min_px != 64'd0 && s1_price < s1_min_px) ||
                                   (s1_max_px != 64'd0 && s1_price > s1_max_px));
            s2_qty             <= s1_qty;
            s2_price           <= s1_price;
            s2_max_notional    <= s1_max_notional;
            s2_gcra_max_ops    <= s1_gcra_max_ops;
            s2_gcra_win_cycles <= s1_gcra_win_cycles;

            // ---------------- Stage 3: DSP Notional & GCRA Counter ----------------
            s3_valid        <= s2_valid;
            s3_kill_hit     <= s2_kill_hit;
            s3_qty_hit      <= s2_qty_hit;
            s3_collar_hit   <= s2_collar_hit;
            s3_notional_hit <= ((s2_qty * s2_price) > s2_max_notional);
            s3_qty          <= s2_qty;
            s3_price        <= s2_price;

            if (s2_gcra_win_cycles != 32'd0 &&
                (cycle_counter - win_start_cycle) >= {32'd0, s2_gcra_win_cycles}) begin
                win_start_cycle <= cycle_counter;
                win_ops_count   <= 32'd0;
                s3_gcra_hit     <= 1'b0;
            end else begin
                s3_gcra_hit <= (s2_gcra_max_ops != 32'd0 && win_ops_count >= s2_gcra_max_ops);
            end

            // ---------------- Stage 4: AXI4-Stream Output Gate ----------------
            axis_out_order_qty   <= s3_qty;
            axis_out_order_price <= s3_price;
            if (!s3_valid) begin
                axis_out_tvalid  <= 1'b0;
                axis_out_verdict <= VERDICT_PASS;
            end else if (s3_kill_hit) begin
                axis_out_tvalid  <= 1'b0;
                axis_out_verdict <= VERDICT_KILL;
                bar0_telemetry_dropped_cnt <= bar0_telemetry_dropped_cnt + 64'd1;
            end else if (s3_qty_hit) begin
                axis_out_tvalid  <= 1'b0;
                axis_out_verdict <= VERDICT_QTY;
                bar0_telemetry_dropped_cnt <= bar0_telemetry_dropped_cnt + 64'd1;
            end else if (s3_collar_hit) begin
                axis_out_tvalid  <= 1'b0;
                axis_out_verdict <= VERDICT_COLLAR;
                bar0_telemetry_dropped_cnt <= bar0_telemetry_dropped_cnt + 64'd1;
            end else if (s3_notional_hit) begin
                axis_out_tvalid  <= 1'b0;
                axis_out_verdict <= VERDICT_NOTIONAL;
                bar0_telemetry_dropped_cnt <= bar0_telemetry_dropped_cnt + 64'd1;
            end else if (s3_gcra_hit) begin
                axis_out_tvalid  <= 1'b0;
                axis_out_verdict <= VERDICT_GCRA;
                bar0_telemetry_dropped_cnt <= bar0_telemetry_dropped_cnt + 64'd1;
            end else begin
                axis_out_tvalid  <= 1'b1;
                axis_out_verdict <= VERDICT_PASS;
                win_ops_count    <= win_ops_count + 32'd1;
            end
        end
    end
endmodule
