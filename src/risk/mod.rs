//! Month 3: Pre-Trade Risk Core & Regulatory Audit Engine (`fingate-risk`).
//!
//! Exports:
//! - `engine`: Ultra-low-latency 5-check inline pre-trade risk engine + GCRA rate limiter.
//! - `mifid_sec`: MiFID II RTS 6 Order-to-Trade Ratio (OTR) & SEC Rule 15c3-5 market access controls.
//! - `audit`: Cryptographically signed compliance evidence pack generator (`fingate audit`).

pub mod audit;
pub mod engine;
pub mod mifid_sec;
pub mod portfolio_greeks;
