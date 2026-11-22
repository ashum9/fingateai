#!/usr/bin/env bash
# Phase C10 / Track F: Compile & verify the 64-byte PCIe BAR0 C++ ABI, 10,000-vector
# C++17 4-cycle RTL equivalence harness, and (when Verilator is installed) real SystemVerilog RTL!
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT_DIR="${SCRIPT_DIR}/build"
mkdir -p "${OUT_DIR}"

# 1. Verify C++17 PCIe BAR0 ABI static_asserts (works on macOS & Linux)
c++ -std=c++17 -O2 -Wall -Wextra -Werror \
    "${SCRIPT_DIR}/sim_main.cpp" -o "${OUT_DIR}/bar0_abi_check"
"${OUT_DIR}/bar0_abi_check"

# 2. Compile & run 10,000-vector 4-cycle RTL Equivalence Harness (works on macOS & Linux)
c++ -std=c++17 -O3 -Wall -Wextra -Werror \
    "${SCRIPT_DIR}/tb_equivalence.cpp" -o "${OUT_DIR}/tb_equivalence"
"${OUT_DIR}/tb_equivalence"

# 3. If Verilator is installed (Linux CI / workstation), compile & simulate gatekeeper.sv RTL!
if command -v verilator >/dev/null 2>&1; then
    echo "[INFO] Verilator detected — compiling SystemVerilog RTL gatekeeper.sv..."
    verilator --cc --exe --build -j 0 \
        -CFLAGS "-std=c++17 -DVERILATOR -I${SCRIPT_DIR}" \
        --Mdir "${OUT_DIR}/obj_dir" \
        "${SCRIPT_DIR}/gatekeeper.sv" \
        "${SCRIPT_DIR}/sim_main.cpp"
    "${OUT_DIR}/obj_dir/Vgatekeeper"
else
    echo "[INFO] verilator not installed on this host; C++17 10,000-vector 4-cycle equivalence & BAR0 ABI verified."
fi
