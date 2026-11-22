//! Track H: FinGate Horizon — Truly Out-of-the-Box Trading Infrastructure Inventions (`fingate::horizon`).
//!
//! Five capabilities that do not exist together in any commercial trading gateway:
//! 1. `nano_policy_vm`: Formally terminating (loop-free) register-VM bytecode risk compiler & hot-swap engine (`< 15 ns`, `0 B` alloc).
//! 2. `threshold_quorum`: Asymmetric 1-of-N trip / M-of-N Shamir Secret Sharing over Mersenne Prime `F_{2^61 - 1}` Kill-Switch disarm guard.
//! 3. `hawkes_shield`: Inline recursive Hawkes self-exciting point process + VPIN toxicity cascade detector (`< 10 ns`, `0` floats, `0` GPU).
//! 4. `relativistic_guard`: Hybrid Logical Clock (HLC) + Speed-of-Light fiber light-cone causality + O(1) cross-venue global STP (`< 8 ns`).
//! 5. `oblivious_vault`: Homomorphic additive exposure commitments over `F_{2^61 - 1}` + inline `epsilon`-DP alpha-preserving compliance telemetry (`< 10 ns`).

pub mod hawkes_shield;
pub mod nano_policy_vm;
pub mod oblivious_vault;
pub mod relativistic_guard;
pub mod threshold_quorum;
