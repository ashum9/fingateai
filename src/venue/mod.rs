//! Month 2: Venue Digital Twins & PCAP Engine (`fingate-twin` + `fingate-pcap`).
//!
//! Provides:
//! - `binance`: Binance Spot FIX 4.4 + SBE twin with lockout and 10-OPS rate limit.
//! - `coinbase`: Coinbase FIX 5.0 SP2 (`FIXT.1.1`) dual-session (OE / Drop-Copy) & COD twin.
//! - `cme`: CME iLink 3 SBE over TCP two-phase negotiation and retransmission twin.
//! - `nse`: NSE / BSE India SEBI Circular 2026 10-OPS and AlgoID enforcement twin.
//! - `pcap`: Wireshark-compatible synthetic Ethernet/IP/TCP PCAP trace generator.

pub mod binance;
pub mod cme;
pub mod coinbase;
pub mod nse;
pub mod pcap;
