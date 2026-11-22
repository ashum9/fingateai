use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Core abstraction for system side-effects (time, entropy, sleeping, platform identification).
/// Enables zero-non-determinism Simulation Testing (DST), replay, and benchmark isolation.
pub trait Env: Send + Sync + 'static {
    /// Monotonic clock timestamp in nanoseconds since an arbitrary anchor or boot time.
    fn now_nanos(&self) -> u64;

    /// Standard library `Instant` for direct duration calculations.
    fn now_instant(&self) -> Instant;

    /// Asynchronous sleep / yield function.
    fn sleep(&self, duration: Duration) -> Pin<Box<dyn Future<Output = ()> + Send + '_>>;

    /// Pseudo-random number generator (64-bit integer output).
    fn next_u64(&self) -> u64;

    /// Reference platform identifier ("REF-DEV" vs "REF-PROD").
    fn platform_tag(&self) -> &'static str;
}

/// Real environment executing on host hardware using standard OS APIs and Tokio runtime.
#[derive(Debug, Clone)]
pub struct RealEnv {
    start_instant: Instant,
}

impl RealEnv {
    pub fn new() -> Self {
        Self {
            start_instant: Instant::now(),
        }
    }
}

impl Default for RealEnv {
    fn default() -> Self {
        Self::new()
    }
}

impl Env for RealEnv {
    fn now_nanos(&self) -> u64 {
        self.start_instant.elapsed().as_nanos() as u64
    }

    fn now_instant(&self) -> Instant {
        Instant::now()
    }

    fn sleep(&self, duration: Duration) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        Box::pin(tokio::time::sleep(duration))
    }

    fn next_u64(&self) -> u64 {
        rand::random()
    }

    fn platform_tag(&self) -> &'static str {
        #[cfg(target_os = "macos")]
        {
            "REF-DEV (Apple Silicon / Mac Laptop)"
        }
        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        {
            "REF-PROD (Linux x86_64 HFT Platform)"
        }
        #[cfg(not(any(target_os = "macos", all(target_os = "linux", target_arch = "x86_64"))))]
        {
            "REF-DEV (Generic Host)"
        }
    }
}

/// Deterministic Simulation Environment with controllable virtual clock and seedable PRNG.
pub struct SimEnv {
    current_nanos: AtomicU64,
    rng: Mutex<rand::rngs::StdRng>,
    start_instant: Instant,
}

impl SimEnv {
    pub fn new(seed: u64) -> Self {
        use rand::SeedableRng;
        Self {
            current_nanos: AtomicU64::new(0),
            rng: Mutex::new(rand::rngs::StdRng::seed_from_u64(seed)),
            start_instant: Instant::now(),
        }
    }

    /// Advance virtual clock by given nanoseconds.
    pub fn advance_nanos(&self, nanos: u64) {
        self.current_nanos.fetch_add(nanos, Ordering::Relaxed);
    }

    /// Set virtual clock to absolute nanosecond timestamp.
    pub fn set_nanos(&self, nanos: u64) {
        self.current_nanos.store(nanos, Ordering::Relaxed);
    }
}

impl Env for SimEnv {
    fn now_nanos(&self) -> u64 {
        self.current_nanos.load(Ordering::Relaxed)
    }

    fn now_instant(&self) -> Instant {
        let nanos = self.now_nanos();
        self.start_instant + Duration::from_nanos(nanos)
    }

    fn sleep(&self, duration: Duration) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        // In SimEnv, sleep immediately advances virtual clock and resolves
        self.advance_nanos(duration.as_nanos() as u64);
        Box::pin(async move {})
    }

    fn next_u64(&self) -> u64 {
        use rand::RngCore;
        let mut guard = self.rng.lock().unwrap();
        guard.next_u64()
    }

    fn platform_tag(&self) -> &'static str {
        "SIM-ENV (Deterministic Simulation)"
    }
}

/// Phase C4: Calibrated Hardware Cycle Counter Clock (`RDTSC` on x86_64 / `cntvct_el0` on ARM64).
///
/// Eliminates OS vDSO / kernel timer syscalls on hot-path GCRA and latency instrumentation.
#[derive(Debug, Clone, Copy)]
pub struct HardwareTscClock {
    anchor_ticks: u64,
    /// Fixed-point multiplier: `nanos = ((delta_ticks as u128 * scale_mul as u128) >> 32) as u64`.
    scale_mul: u64,
    freq_hz: u64,
}

impl HardwareTscClock {
    /// Read raw CPU cycle/counter register directly without OS syscalls.
    #[inline(always)]
    pub fn read_raw_ticks() -> u64 {
        #[cfg(target_arch = "aarch64")]
        unsafe {
            let v: u64;
            core::arch::asm!("mrs {}, cntvct_el0", out(reg) v, options(nomem, nostack, preserves_flags));
            v
        }
        #[cfg(target_arch = "x86_64")]
        unsafe {
            core::arch::x86_64::_rdtsc()
        }
        #[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
        {
            0
        }
    }

    /// Calibrate the hardware counter once at startup.
    pub fn calibrate() -> Self {
        #[cfg(target_arch = "aarch64")]
        let freq_hz: u64 = unsafe {
            let f: u64;
            core::arch::asm!("mrs {}, cntfrq_el0", out(reg) f, options(nomem, nostack, preserves_flags));
            f.max(1)
        };

        #[cfg(target_arch = "x86_64")]
        let freq_hz: u64 = {
            let t0 = Instant::now();
            let c0 = Self::read_raw_ticks();
            std::thread::sleep(Duration::from_millis(5));
            let c1 = Self::read_raw_ticks();
            let elapsed_ns = t0.elapsed().as_nanos().max(1);
            let delta_cycles = c1.wrapping_sub(c0) as u128;
            ((delta_cycles * 1_000_000_000u128) / elapsed_ns).max(1) as u64
        };

        #[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
        let freq_hz: u64 = 1_000_000_000;

        // scale_mul = (1_000_000_000 << 32) / freq_hz
        let scale_mul = ((1_000_000_000u128 << 32) / (freq_hz as u128)) as u64;
        Self {
            anchor_ticks: Self::read_raw_ticks(),
            scale_mul,
            freq_hz,
        }
    }

    /// Global singleton calibrated once on first access.
    #[inline]
    pub fn global() -> &'static Self {
        static GLOBAL_TSC: std::sync::OnceLock<HardwareTscClock> = std::sync::OnceLock::new();
        GLOBAL_TSC.get_or_init(Self::calibrate)
    }

    /// Convert delta ticks to nanoseconds using single 128-bit integer multiply + shift (no division).
    #[inline(always)]
    pub fn ticks_to_nanos(&self, delta_ticks: u64) -> u64 {
        (((delta_ticks as u128).wrapping_mul(self.scale_mul as u128)) >> 32) as u64
    }

    /// Monotonic nanoseconds since clock calibration anchor.
    #[inline(always)]
    pub fn now_nanos(&self) -> u64 {
        let delta = Self::read_raw_ticks().wrapping_sub(self.anchor_ticks);
        self.ticks_to_nanos(delta)
    }

    /// Calibrated hardware counter frequency in Hz.
    #[inline]
    pub fn freq_hz(&self) -> u64 {
        self.freq_hz
    }
}
