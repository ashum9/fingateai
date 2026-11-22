//! Phase D3: Zero-Allocation Formal In-Flight Order Lifecycle FSM (`fingate::oms`).
//!
//! Resolves institutional `35=G` (`PendingReplace`) / `35=F` (`PendingCancel`) vs concurrent
//! `PartialFill` / `CancelReject (35=9)` race conditions with O(1) flat-slab storage and
//! Invariant `I9` conservative exposure accounting (`< 30 ns`, 0 heap allocations).

pub mod order_fsm;
