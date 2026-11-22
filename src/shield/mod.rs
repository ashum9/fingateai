//! Month 4: Live FinGate Session Shield Multiplexer & High-Availability Engine (`fingate-shield`).
//!
//! Exports:
//! - `multiplexer`: N:1 Strategy Pod ingress multiplexer and bidirectional O(1) ClOrdID router.
//! - `cod_engine`: Production Cancel-on-Disconnect (COD) and Pod Grace Window engine (Rules R16–R20).
//! - `standby`: Hot-standby active/passive gateway state synchronization and zero-gap failover.

pub mod cod_engine;
pub mod ingress;
pub mod multiplexer;
pub mod standby;
pub mod vsr_consensus;
pub mod vsr_net;
