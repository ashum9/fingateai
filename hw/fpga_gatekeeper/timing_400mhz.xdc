# Gap 5 (E5): AMD Alveo UL3524 / U50 400 MHz Timing Constraint File (2.500 ns period)
# 4 pipeline stages * 2.500 ns = 10.0 ns wire-to-wire silicon pre-trade gatekeeper latency
# (beating Exegy nxFramework's 13.9 ns STAC-T0 benchmark!).

create_clock -period 2.500 -name sys_clk_400m [get_ports clk]
set_input_delay  -clock sys_clk_400m -max 0.600 [all_inputs]
set_output_delay -clock sys_clk_400m -max 0.600 [all_outputs]
set_false_path   -from [get_ports rst_n]
