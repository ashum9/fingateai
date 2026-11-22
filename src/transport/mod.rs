//! Phases C6 & C7: Zero-Copy Kernel-Bypass Network Transport Abstraction (`fingate::transport`).
//!
//! Decouples FinGate's FIX/SBE parsing, Pre-Trade Risk, WAL, and Multiplexer from OS TCP sockets:
//! - `af_xdp`: Linux `AF_XDP` zero-copy UMEM rings + `LinuxEbpfDropHook` (`3.5 – 6.5 µs` RTT target).
//! - `dpdk`: Bare-metal DPDK userspace polling (`librte_eal` FFI, `1.5 – 2.5 µs` RTT target).
//! - `efvi`: Solarflare `ef_vi` + CTPIO cut-through TX (`libciul` FFI, `1.3 – 1.8 µs` RTT target).
//! - `SimNicTransport`: Wait-free SPSC virtual NIC loopback for deterministic zero-copy benchmarking.

pub mod af_xdp;
pub mod dpdk;
pub mod efvi;
pub mod userspace_net;

use crate::ring::{SpscConsumer, SpscProducer, SpscRing};

/// Stack-resident inline packet buffer for zero-allocation burst polling.
#[derive(Clone, Copy)]
#[repr(align(64))]
pub struct InlineFrameSlot {
    pub len: u16,
    pub rx_tsc: u64,
    pub data: [u8; 256],
}

impl Default for InlineFrameSlot {
    fn default() -> Self {
        Self {
            len: 0,
            rx_tsc: 0,
            data: [0u8; 256],
        }
    }
}

/// Unified zero-copy polling transport trait shared across Tokio, AF_XDP, DPDK, and Solarflare ef_vi.
pub trait WireTransport {
    /// Human-readable transport identifier (e.g. `"af_xdp"`, `"dpdk"`, `"ef_vi_ctpio"`).
    fn transport_name(&self) -> &'static str;

    /// Poll up to `max_burst` inbound frames without blocking or allocating.
    fn poll_rx_burst<F: FnMut(&[u8], u64)>(&mut self, max_burst: usize, on_frame: F) -> usize;

    /// Transmit a raw wire frame inline without heap allocation.
    fn tx_frame_inline(&mut self, frame: &[u8]) -> Result<usize, &'static str>;
}

/// Wait-free zero-copy virtual NIC endpoint pair (`SpscRing` backed) for deterministic polling benchmarks.
pub struct SimNicTransport {
    tx: SpscProducer<InlineFrameSlot, 1024>,
    rx: SpscConsumer<InlineFrameSlot, 1024>,
}

impl SimNicTransport {
    /// Construct a paired bidirectional virtual NIC loopback (`(client_nic, gateway_nic)`).
    pub fn pair() -> (Self, Self) {
        let (a_tx, b_rx) = SpscRing::<InlineFrameSlot, 1024>::split();
        let (b_tx, a_rx) = SpscRing::<InlineFrameSlot, 1024>::split();
        (Self { tx: a_tx, rx: a_rx }, Self { tx: b_tx, rx: b_rx })
    }
}

impl WireTransport for SimNicTransport {
    fn transport_name(&self) -> &'static str {
        "sim_nic_zero_copy"
    }

    #[inline(always)]
    fn poll_rx_burst<F: FnMut(&[u8], u64)>(&mut self, max_burst: usize, mut on_frame: F) -> usize {
        let mut count = 0;
        while count < max_burst {
            match self.rx.try_pop() {
                Some(slot) => {
                    let len = (slot.len as usize).min(slot.data.len());
                    on_frame(&slot.data[..len], slot.rx_tsc);
                    count += 1;
                }
                None => break,
            }
        }
        count
    }

    #[inline(always)]
    fn tx_frame_inline(&mut self, frame: &[u8]) -> Result<usize, &'static str> {
        if frame.len() > 256 {
            return Err("frame exceeds 256B inline slot");
        }
        let mut slot = InlineFrameSlot {
            len: frame.len() as u16,
            rx_tsc: crate::env::HardwareTscClock::read_raw_ticks(),
            data: [0u8; 256],
        };
        slot.data[..frame.len()].copy_from_slice(frame);
        self.tx.try_push(slot).map_err(|_| "tx ring full")?;
        Ok(frame.len())
    }
}
