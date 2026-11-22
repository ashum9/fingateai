//! Month 5: 6-Layer Emergency Kill Switch & Real-Time Telemetry Engine (`fingate-killswitch`).
//!
//! Exports:
//! - `layers`: 6-layer defense-in-depth emergency kill switch execution pipeline (<50µs target).
//! - `telemetry`: High-performance lock-free atomic telemetry and Prometheus exporter.

pub mod layers;
pub mod telemetry;
