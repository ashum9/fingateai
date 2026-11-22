# Gap 5 (E5): AMD Vivado Out-of-Context Synthesis & Timing Closure Script
# Target FPGA: AMD Alveo U50 / UltraScale+ (xcu50-fsvh2104-2-e) @ 400 MHz (2.5 ns => 10.0 ns 4-cycle gate!)
# Usage: vivado -mode batch -source hw/fpga_gatekeeper/vivado_build.tcl

set part_name "xcu50-fsvh2104-2-e"
set top_module "fingate_edge_gatekeeper"
set out_dir "build/vivado_400mhz"
file mkdir $out_dir

read_verilog -sv hw/fpga_gatekeeper/gatekeeper.sv
read_xdc hw/fpga_gatekeeper/timing_400mhz.xdc

# Enable aggressive retiming & DSP48E2 pipelining for 64-bit notional multiply @ 400 MHz
synth_design -top $top_module -part $part_name -mode out_of_context \
    -retiming -directive PerformanceOptimized

opt_design -directive ExploreWithRemap
place_design -directive ExtraTimingOpt
phys_opt_design -directive AggressiveExplore
route_design -directive AggressiveExplore

report_timing_summary -file $out_dir/timing_400mhz.rpt
report_utilization    -file $out_dir/utilization.rpt
write_checkpoint -force $out_dir/fingate_gatekeeper_400mhz.dcp

set wns [get_property SLACK [get_timing_paths -max_paths 1 -nworst 1 -setup]]
puts "==================================================================="
puts " FinGate FPGA Gatekeeper 400 MHz WNS = $wns ns (4 cycles = 10.0 ns)"
puts "==================================================================="
if { $wns < 0.0 } {
    puts "ERROR: 400 MHz timing closure failed (WNS = $wns ns)"
    exit 1
}
exit 0
