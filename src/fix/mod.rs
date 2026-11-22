//! FinGate Month 1 Core Package (`fingate-fix` + `fingate-chaos` + `fingate-verifier`).
//!
//! Exports:
//! - `wire`: Zero-copy `FixWireView`, `FixFrameBuilder`, and `FixTcpDefragmenter`
//! - `session`: Full 25-rule `Fix44SessionEngine` + FinGate Session Shield state machine
//! - `invariants`: Formal 8-invariant verifier (`I1`..`I8`) and sub-millisecond RLVR grader
//! - `chaos`: Seeded procedural chaos generator and loopback TCP chaos socket harness

pub mod chaos;
pub mod invariants;
pub mod session;
pub mod wire;
