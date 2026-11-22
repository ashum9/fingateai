//! Phase D1: Zero-Copy POSIX `mmap(MAP_SHARED)` Borrow-Slice IPC Channel (`ShmPodChannel`).
//!
//! Exact C-compatible layout shared across Rust, C/C++ (`include/fingate.h`), and Python (`sdk/python/fingate_shm.py`):
//! - 5 cache-line-isolated 64-byte header lines (320 bytes) eliminating producer/consumer false sharing.
//! - 256 request slots (`NormalizedOrderEvent`, 64 bytes each = 16 KB) + 256 verdict slots (`ShmOrderVerdict`, 64 bytes each = 16 KB).
//! - Built-in `pod_heartbeat_tsc` & `pod_pid` enabling microsecond crashed-pod detection for COD.

use crate::protocol::NormalizedOrderEvent;
use std::fs::{File, OpenOptions};
use std::os::unix::io::AsRawFd;
use std::path::Path;
use std::ptr::NonNull;
use std::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering};

pub const SHM_MAGIC: [u8; 8] = *b"FGSHM001";
pub const SHM_VERSION: u32 = 1;
pub const SHM_RING_CAP: usize = 256;
pub const SHM_RING_MASK: usize = SHM_RING_CAP - 1;

pub const VERDICT_APPROVED: u8 = 0;
pub const VERDICT_REJECTED: u8 = 1;
pub const VERDICT_FILLED: u8 = 2;
pub const VERDICT_CANCELLED: u8 = 3;
pub const VERDICT_REPLACED: u8 = 4;

/// 64-byte cache-aligned verdict written by FinGate Core directly into shared memory.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(C, align(64))]
pub struct ShmOrderVerdict {
    pub cl_ord_id_hash: u64, // 0..8
    pub wire_seq: u64,       // 8..16
    pub leaves_qty: u64,     // 16..24
    pub cum_qty: u64,        // 24..32
    pub last_px: i64,        // 32..40
    pub egress_tsc: u64,     // 40..48
    pub status: u8,          // 48 (VERDICT_*)
    pub reject_code: u8,     // 49
    pub _pad: [u8; 14],      // 50..64
}

const _: () = assert!(std::mem::size_of::<ShmOrderVerdict>() == 64);

#[repr(C, align(64))]
pub struct ShmCacheLineUsize {
    pub val: AtomicUsize,
    _pad: [u8; 64 - std::mem::size_of::<AtomicUsize>()],
}

/// Complete `MAP_SHARED` memory-mapped IPC channel layout (exact deterministic C/Python ABI).
#[repr(C, align(64))]
pub struct ShmChannelLayout {
    // Cache line 0 (0..64): Metadata & liveness
    pub magic: [u8; 8],
    pub version: u32,
    pub ring_capacity: u32,
    pub pod_slot: u16,
    pub _pad0: u16,
    pub pod_pid: AtomicU32,
    pub gateway_pid: AtomicU32,
    pub gateway_kill_flag: AtomicU32,
    pub pod_heartbeat_tsc: AtomicU64,
    pub _pad_line0: [u8; 24],

    // Cache lines 1..4 (64..320): Isolated atomic ring cursors (0 false sharing!)
    pub req_tail: ShmCacheLineUsize,
    pub req_head: ShmCacheLineUsize,
    pub resp_tail: ShmCacheLineUsize,
    pub resp_head: ShmCacheLineUsize,

    // Arena (320..33088): 256 x 64B requests + 256 x 64B verdicts
    pub req_slots: [NormalizedOrderEvent; SHM_RING_CAP],
    pub resp_slots: [ShmOrderVerdict; SHM_RING_CAP],
}

const _: () = assert!(std::mem::offset_of!(ShmChannelLayout, req_tail) == 64);
const _: () = assert!(std::mem::offset_of!(ShmChannelLayout, req_head) == 128);
const _: () = assert!(std::mem::offset_of!(ShmChannelLayout, resp_tail) == 192);
const _: () = assert!(std::mem::offset_of!(ShmChannelLayout, resp_head) == 256);
const _: () = assert!(std::mem::offset_of!(ShmChannelLayout, req_slots) == 320);

/// Mapped POSIX shared-memory handle (`MAP_SHARED`, works identically on Linux `/dev/shm` and macOS).
pub struct MappedShmChannel {
    ptr: NonNull<ShmChannelLayout>,
    byte_len: usize,
    _file: File,
}

unsafe impl Send for MappedShmChannel {}
unsafe impl Sync for MappedShmChannel {}

impl MappedShmChannel {
    /// Create & zero-initialize a new shared-memory channel at `path` (e.g. `/dev/shm/fingate_pod0.shm`).
    pub fn create<P: AsRef<Path>>(path: P, pod_slot: u16) -> std::io::Result<Self> {
        let byte_len = std::mem::size_of::<ShmChannelLayout>();
        if let Some(parent) = path.as_ref().parent() {
            if !parent.as_os_str().is_empty() {
                let _ = std::fs::create_dir_all(parent);
            }
        }
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)?;
        file.set_len(byte_len as u64)?;
        let mut mapped = Self::mmap_file(file, byte_len)?;
        unsafe {
            let layout = mapped.ptr.as_mut();
            std::ptr::write_bytes(layout as *mut ShmChannelLayout, 0, 1);
            layout.magic = SHM_MAGIC;
            layout.version = SHM_VERSION;
            layout.ring_capacity = SHM_RING_CAP as u32;
            layout.pod_slot = pod_slot;
            layout.gateway_pid.store(std::process::id(), Ordering::Release);
        }
        Ok(mapped)
    }

    /// Attach to an existing shared-memory channel created by FinGate Gateway.
    pub fn attach<P: AsRef<Path>>(path: P) -> std::io::Result<Self> {
        let byte_len = std::mem::size_of::<ShmChannelLayout>();
        let file = OpenOptions::new().read(true).write(true).open(path)?;
        let mapped = Self::mmap_file(file, byte_len)?;
        let hdr = mapped.layout();
        if hdr.magic != SHM_MAGIC || hdr.version != SHM_VERSION {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid FinGate SHM channel magic/version",
            ));
        }
        hdr.pod_pid.store(std::process::id(), Ordering::Release);
        Ok(mapped)
    }

    fn mmap_file(file: File, byte_len: usize) -> std::io::Result<Self> {
        const PROT_READ: i32 = 1;
        const PROT_WRITE: i32 = 2;
        const MAP_SHARED: i32 = 0x01;
        extern "C" {
            fn mmap(
                addr: *mut std::ffi::c_void,
                length: usize,
                prot: i32,
                flags: i32,
                fd: i32,
                offset: i64,
            ) -> *mut std::ffi::c_void;
        }
        let raw = unsafe {
            mmap(
                std::ptr::null_mut(),
                byte_len,
                PROT_READ | PROT_WRITE,
                MAP_SHARED,
                file.as_raw_fd(),
                0,
            )
        };
        if raw == (-1isize as *mut std::ffi::c_void) || raw.is_null() {
            return Err(std::io::Error::last_os_error());
        }
        let ptr = NonNull::new(raw as *mut ShmChannelLayout)
            .ok_or_else(|| std::io::Error::other("null mmap pointer"))?;
        Ok(Self {
            ptr,
            byte_len,
            _file: file,
        })
    }

    #[inline(always)]
    pub fn layout(&self) -> &ShmChannelLayout {
        unsafe { self.ptr.as_ref() }
    }

    /// Pod-side zero-copy submit: writes `NormalizedOrderEvent` directly into shared ring slot.
    #[inline(always)]
    pub fn pod_try_submit(&self, order: NormalizedOrderEvent) -> Result<(), NormalizedOrderEvent> {
        let mem = self.layout();
        let tail = mem.req_tail.val.load(Ordering::Relaxed);
        let head = mem.req_head.val.load(Ordering::Acquire);
        if tail.wrapping_sub(head) >= SHM_RING_CAP - 1 {
            return Err(order);
        }
        unsafe {
            let base = self.ptr.as_ptr();
            let slot_ptr = (*base).req_slots.as_mut_ptr().add(tail & SHM_RING_MASK);
            std::ptr::write(slot_ptr, order);
        }
        mem.req_tail.val.store(tail.wrapping_add(1), Ordering::Release);
        Ok(())
    }

    /// Pod-side zero-copy poll for gateway verdict (`< 30 ns`).
    #[inline(always)]
    pub fn pod_try_poll_verdict(&self) -> Option<ShmOrderVerdict> {
        let mem = self.layout();
        let head = mem.resp_head.val.load(Ordering::Relaxed);
        let tail = mem.resp_tail.val.load(Ordering::Acquire);
        if head == tail {
            return None;
        }
        let verdict = unsafe {
            let base = self.ptr.as_ptr();
            std::ptr::read((*base).resp_slots.as_ptr().add(head & SHM_RING_MASK))
        };
        mem.resp_head.val.store(head.wrapping_add(1), Ordering::Release);
        Some(verdict)
    }

    /// Gateway-side zero-copy poll for inbound pod order (`< 30 ns`).
    #[inline(always)]
    pub fn gateway_try_poll_order(&self) -> Option<NormalizedOrderEvent> {
        let mem = self.layout();
        let head = mem.req_head.val.load(Ordering::Relaxed);
        let tail = mem.req_tail.val.load(Ordering::Acquire);
        if head == tail {
            return None;
        }
        let order = unsafe {
            let base = self.ptr.as_ptr();
            std::ptr::read((*base).req_slots.as_ptr().add(head & SHM_RING_MASK))
        };
        mem.req_head.val.store(head.wrapping_add(1), Ordering::Release);
        Some(order)
    }

    /// Gateway-side zero-copy verdict publish back to pod (`< 30 ns`).
    #[inline(always)]
    pub fn gateway_try_publish_verdict(&self, verdict: ShmOrderVerdict) -> Result<(), ShmOrderVerdict> {
        let mem = self.layout();
        let tail = mem.resp_tail.val.load(Ordering::Relaxed);
        let head = mem.resp_head.val.load(Ordering::Acquire);
        if tail.wrapping_sub(head) >= SHM_RING_CAP - 1 {
            return Err(verdict);
        }
        unsafe {
            let base = self.ptr.as_ptr();
            let slot_ptr = (*base).resp_slots.as_mut_ptr().add(tail & SHM_RING_MASK);
            std::ptr::write(slot_ptr, verdict);
        }
        mem.resp_tail.val.store(tail.wrapping_add(1), Ordering::Release);
        Ok(())
    }

    #[inline(always)]
    pub fn pulse_pod_heartbeat(&self, tsc_ns: u64) {
        self.layout().pod_heartbeat_tsc.store(tsc_ns, Ordering::Release);
    }

    #[inline(always)]
    pub fn is_pod_heartbeat_stale(&self, now_ns: u64, timeout_ns: u64) -> bool {
        let last = self.layout().pod_heartbeat_tsc.load(Ordering::Acquire);
        last > 0 && now_ns.saturating_sub(last) > timeout_ns
    }

    // -------------------------------------------------------------------------
    // Gap 2 (E2): True Zero-Copy Borrow-In-Place API (Eclipse `iceoryx2` style)
    // -------------------------------------------------------------------------

    /// Claim a mutable pointer directly inside shared memory (`0` intermediate stack copies).
    /// Pair with `pod_commit_tx(next_tail)` after writing fields in place.
    #[inline(always)]
    pub fn pod_claim_tx_slot(&self) -> Option<(&mut NormalizedOrderEvent, usize)> {
        let mem = self.layout();
        let tail = mem.req_tail.val.load(Ordering::Relaxed);
        let head = mem.req_head.val.load(Ordering::Acquire);
        if tail.wrapping_sub(head) >= SHM_RING_CAP - 1 {
            return None;
        }
        let slot_ref = unsafe {
            let base = self.ptr.as_ptr();
            &mut *(*base).req_slots.as_mut_ptr().add(tail & SHM_RING_MASK)
        };
        Some((slot_ref, tail.wrapping_add(1)))
    }

    #[inline(always)]
    pub fn pod_commit_tx(&self, next_tail: usize) {
        self.layout().req_tail.val.store(next_tail, Ordering::Release);
    }

    /// Borrow the next inbound order in place without copying 64 bytes out of shared memory.
    #[inline(always)]
    pub fn gateway_peek_order(&self) -> Option<(&NormalizedOrderEvent, usize)> {
        let mem = self.layout();
        let head = mem.req_head.val.load(Ordering::Relaxed);
        let tail = mem.req_tail.val.load(Ordering::Acquire);
        if head == tail {
            return None;
        }
        let slot_ref = unsafe {
            let base = self.ptr.as_ptr();
            &*(*base).req_slots.as_ptr().add(head & SHM_RING_MASK)
        };
        Some((slot_ref, head.wrapping_add(1)))
    }

    #[inline(always)]
    pub fn gateway_release_order(&self, next_head: usize) {
        self.layout().req_head.val.store(next_head, Ordering::Release);
    }

    /// Borrow the next outbound verdict slot directly inside shared memory (`0` copies).
    #[inline(always)]
    pub fn gateway_claim_verdict_slot(&self) -> Option<(&mut ShmOrderVerdict, usize)> {
        let mem = self.layout();
        let tail = mem.resp_tail.val.load(Ordering::Relaxed);
        let head = mem.resp_head.val.load(Ordering::Acquire);
        if tail.wrapping_sub(head) >= SHM_RING_CAP - 1 {
            return None;
        }
        let slot_ref = unsafe {
            let base = self.ptr.as_ptr();
            &mut *(*base).resp_slots.as_mut_ptr().add(tail & SHM_RING_MASK)
        };
        Some((slot_ref, tail.wrapping_add(1)))
    }

    #[inline(always)]
    pub fn gateway_commit_verdict(&self, next_tail: usize) {
        self.layout().resp_tail.val.store(next_tail, Ordering::Release);
    }

    /// Borrow the next verdict in place on the strategy pod side (`0` copies).
    #[inline(always)]
    pub fn pod_peek_verdict(&self) -> Option<(&ShmOrderVerdict, usize)> {
        let mem = self.layout();
        let head = mem.resp_head.val.load(Ordering::Relaxed);
        let tail = mem.resp_tail.val.load(Ordering::Acquire);
        if head == tail {
            return None;
        }
        let slot_ref = unsafe {
            let base = self.ptr.as_ptr();
            &*(*base).resp_slots.as_ptr().add(head & SHM_RING_MASK)
        };
        Some((slot_ref, head.wrapping_add(1)))
    }

    #[inline(always)]
    pub fn pod_release_verdict(&self, next_head: usize) {
        self.layout().resp_head.val.store(next_head, Ordering::Release);
    }

    /// Construct a cached-cursor high-frequency Pod endpoint (Aeron/Disruptor shadow cursor optimization).
    pub fn as_pod_endpoint(&self) -> ShmPodEndpoint<'_> {
        let mem = self.layout();
        ShmPodEndpoint {
            chan: self,
            local_req_tail: mem.req_tail.val.load(Ordering::Relaxed),
            cached_req_head: mem.req_head.val.load(Ordering::Acquire),
            local_resp_head: mem.resp_head.val.load(Ordering::Relaxed),
            cached_resp_tail: mem.resp_tail.val.load(Ordering::Acquire),
        }
    }

    /// Construct a cached-cursor high-frequency Gateway endpoint (eliminates redundant cross-core loads).
    pub fn as_gateway_endpoint(&self) -> ShmGatewayEndpoint<'_> {
        let mem = self.layout();
        ShmGatewayEndpoint {
            chan: self,
            local_req_head: mem.req_head.val.load(Ordering::Relaxed),
            cached_req_tail: mem.req_tail.val.load(Ordering::Acquire),
            local_resp_tail: mem.resp_tail.val.load(Ordering::Relaxed),
            cached_resp_head: mem.resp_head.val.load(Ordering::Acquire),
        }
    }
}

/// Aeron/Disruptor-style cached-cursor Pod endpoint: eliminates cross-core `req_head` & `resp_tail`
/// cache-line bounces on steady-state writes/reads, plus pure borrow-in-place shared slots.
pub struct ShmPodEndpoint<'a> {
    chan: &'a MappedShmChannel,
    local_req_tail: usize,
    cached_req_head: usize,
    local_resp_head: usize,
    cached_resp_tail: usize,
}

impl<'a> ShmPodEndpoint<'a> {
    /// Borrow-in-place write directly into shared memory using cached shadow `req_head`.
    #[inline(always)]
    pub fn try_submit_in_place<F: FnOnce(&mut NormalizedOrderEvent)>(&mut self, writer: F) -> bool {
        let tail = self.local_req_tail;
        if tail.wrapping_sub(self.cached_req_head) >= SHM_RING_CAP - 1 {
            self.cached_req_head = self.chan.layout().req_head.val.load(Ordering::Acquire);
            if tail.wrapping_sub(self.cached_req_head) >= SHM_RING_CAP - 1 {
                return false;
            }
        }
        unsafe {
            let base = self.chan.ptr.as_ptr();
            let slot_ref = &mut *(*base).req_slots.as_mut_ptr().add(tail & SHM_RING_MASK);
            writer(slot_ref);
        }
        let next = tail.wrapping_add(1);
        self.local_req_tail = next;
        self.chan.layout().req_tail.val.store(next, Ordering::Release);
        true
    }

    /// Zero-copy borrow-in-place poll for verdict using cached shadow `resp_tail`.
    #[inline(always)]
    pub fn try_poll_verdict_in_place<R, F: FnOnce(&ShmOrderVerdict) -> R>(&mut self, reader: F) -> Option<R> {
        let head = self.local_resp_head;
        if head == self.cached_resp_tail {
            self.cached_resp_tail = self.chan.layout().resp_tail.val.load(Ordering::Acquire);
            if head == self.cached_resp_tail {
                return None;
            }
        }
        let res = unsafe {
            let base = self.chan.ptr.as_ptr();
            let slot_ref = &*(*base).resp_slots.as_ptr().add(head & SHM_RING_MASK);
            reader(slot_ref)
        };
        let next = head.wrapping_add(1);
        self.local_resp_head = next;
        self.chan.layout().resp_head.val.store(next, Ordering::Release);
        Some(res)
    }

    /// Adaptive wait avoiding ARM64 `ISB` (`spin_loop`) pipeline stalls during hot bursts.
    #[inline(always)]
    pub fn wait_verdict_in_place<R, F: FnOnce(&ShmOrderVerdict) -> R>(&mut self, reader: F) -> R {
        let mut spins = 0u32;
        let head = self.local_resp_head;
        while head == self.cached_resp_tail {
            self.cached_resp_tail = self.chan.layout().resp_tail.val.load(Ordering::Acquire);
            if head != self.cached_resp_tail {
                break;
            }
            spins = spins.wrapping_add(1);
            if spins > 4096 {
                std::hint::spin_loop();
            }
        }
        let res = unsafe {
            let base = self.chan.ptr.as_ptr();
            let slot_ref = &*(*base).resp_slots.as_ptr().add(head & SHM_RING_MASK);
            reader(slot_ref)
        };
        let next = head.wrapping_add(1);
        self.local_resp_head = next;
        self.chan.layout().resp_head.val.store(next, Ordering::Release);
        res
    }
}

/// Aeron/Disruptor-style cached-cursor Gateway endpoint for ultra-low-latency core polling.
pub struct ShmGatewayEndpoint<'a> {
    chan: &'a MappedShmChannel,
    local_req_head: usize,
    cached_req_tail: usize,
    local_resp_tail: usize,
    cached_resp_head: usize,
}

impl<'a> ShmGatewayEndpoint<'a> {
    #[inline(always)]
    pub fn try_poll_order_in_place<R, F: FnOnce(&NormalizedOrderEvent) -> R>(&mut self, reader: F) -> Option<R> {
        let head = self.local_req_head;
        if head == self.cached_req_tail {
            self.cached_req_tail = self.chan.layout().req_tail.val.load(Ordering::Acquire);
            if head == self.cached_req_tail {
                return None;
            }
        }
        let res = unsafe {
            let base = self.chan.ptr.as_ptr();
            let slot_ref = &*(*base).req_slots.as_ptr().add(head & SHM_RING_MASK);
            reader(slot_ref)
        };
        let next = head.wrapping_add(1);
        self.local_req_head = next;
        self.chan.layout().req_head.val.store(next, Ordering::Release);
        Some(res)
    }

    #[inline(always)]
    pub fn try_publish_verdict_in_place<F: FnOnce(&mut ShmOrderVerdict)>(&mut self, writer: F) -> bool {
        let tail = self.local_resp_tail;
        if tail.wrapping_sub(self.cached_resp_head) >= SHM_RING_CAP - 1 {
            self.cached_resp_head = self.chan.layout().resp_head.val.load(Ordering::Acquire);
            if tail.wrapping_sub(self.cached_resp_head) >= SHM_RING_CAP - 1 {
                return false;
            }
        }
        unsafe {
            let base = self.chan.ptr.as_ptr();
            let slot_ref = &mut *(*base).resp_slots.as_mut_ptr().add(tail & SHM_RING_MASK);
            writer(slot_ref);
        }
        let next = tail.wrapping_add(1);
        self.local_resp_tail = next;
        self.chan.layout().resp_tail.val.store(next, Ordering::Release);
        true
    }
}

impl Drop for MappedShmChannel {
    fn drop(&mut self) {
        extern "C" {
            fn munmap(addr: *mut std::ffi::c_void, length: usize) -> i32;
        }
        unsafe {
            munmap(self.ptr.as_ptr() as *mut std::ffi::c_void, self.byte_len);
        }
    }
}

// =============================================================================
// Track I6: 128-Byte Cache-Line Isolated Single-MESI Sequence-Stamped SHM Ring
// (`FGSHM002` — Eliminates Apple Silicon 128B & Xeon Adjacent-Line False Sharing!)
// =============================================================================

pub const SHM_STAMPED_MAGIC: [u8; 8] = *b"FGSHM002";

/// Single 128-byte physical cache-line request slot: atomic `seq_stamp` + 64B `NormalizedOrderEvent`
/// share the EXACT same 128B cache line so consumer polls readiness & reads payload in **ONE MESI transfer**!
#[repr(C, align(128))]
pub struct StampedReqSlot {
    pub seq_stamp: AtomicU64,
    pub _pad: [u8; 56],
    pub payload: NormalizedOrderEvent,
}

const _: () = assert!(std::mem::size_of::<StampedReqSlot>() == 128);

/// Single 128-byte physical cache-line verdict slot: atomic `seq_stamp` + 64B `ShmOrderVerdict`.
#[repr(C, align(128))]
pub struct StampedRespSlot {
    pub seq_stamp: AtomicU64,
    pub _pad: [u8; 56],
    pub payload: ShmOrderVerdict,
}

const _: () = assert!(std::mem::size_of::<StampedRespSlot>() == 128);

/// Complete 128-byte cache-line isolated sequence-stamped POSIX `MAP_SHARED` channel (`FGSHM002`).
#[repr(C, align(128))]
pub struct ShmStampedLayout {
    pub magic: [u8; 8],             // 0..8
    pub version: u32,               // 8..12
    pub ring_capacity: u32,         // 12..16
    pub pod_slot: u16,              // 16..18
    pub _pad0: u16,                 // 18..20
    pub pod_pid: AtomicU32,         // 20..24
    pub gateway_pid: AtomicU32,     // 24..28
    pub gateway_kill_flag: AtomicU32,// 28..32
    pub pod_heartbeat_tsc: AtomicU64,// 32..40
    pub _pad_hdr: [u8; 88],         // 40..128

    pub req_slots: [StampedReqSlot; SHM_RING_CAP],
    pub resp_slots: [StampedRespSlot; SHM_RING_CAP],
}

const _: () = assert!(std::mem::offset_of!(ShmStampedLayout, req_slots) == 128);

/// Track I6: Wait-free 128B sequence-stamped POSIX SHM channel (1 MESI line transfer per message).
pub struct FastStampedShmChannel {
    ptr: NonNull<ShmStampedLayout>,
    byte_len: usize,
    _file: File,
}

unsafe impl Send for FastStampedShmChannel {}
unsafe impl Sync for FastStampedShmChannel {}

impl FastStampedShmChannel {
    pub fn create<P: AsRef<Path>>(path: P, pod_slot: u16) -> std::io::Result<Self> {
        let byte_len = std::mem::size_of::<ShmStampedLayout>();
        if let Some(parent) = path.as_ref().parent() {
            if !parent.as_os_str().is_empty() {
                let _ = std::fs::create_dir_all(parent);
            }
        }
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)?;
        file.set_len(byte_len as u64)?;
        let mut mapped = Self::mmap_file(file, byte_len)?;
        unsafe {
            let layout = mapped.ptr.as_mut();
            std::ptr::write_bytes(layout as *mut ShmStampedLayout, 0, 1);
            layout.magic = SHM_STAMPED_MAGIC;
            layout.version = 2;
            layout.ring_capacity = SHM_RING_CAP as u32;
            layout.pod_slot = pod_slot;
            layout.gateway_pid.store(std::process::id(), Ordering::Release);
            for i in 0..SHM_RING_CAP {
                layout.req_slots[i].seq_stamp.store(i as u64, Ordering::Relaxed);
                layout.resp_slots[i].seq_stamp.store(i as u64, Ordering::Relaxed);
            }
            std::sync::atomic::fence(Ordering::Release);
        }
        Ok(mapped)
    }

    pub fn open<P: AsRef<Path>>(path: P) -> std::io::Result<Self> {
        let byte_len = std::mem::size_of::<ShmStampedLayout>();
        let file = OpenOptions::new().read(true).write(true).open(path)?;
        let mapped = Self::mmap_file(file, byte_len)?;
        if mapped.layout().magic != SHM_STAMPED_MAGIC {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid FGSHM002 stamped SHM magic",
            ));
        }
        Ok(mapped)
    }

    fn mmap_file(file: File, byte_len: usize) -> std::io::Result<Self> {
        const PROT_READ: i32 = 0x1;
        const PROT_WRITE: i32 = 0x2;
        const MAP_SHARED: i32 = 0x1;
        extern "C" {
            fn mmap(
                addr: *mut std::ffi::c_void,
                length: usize,
                prot: i32,
                flags: i32,
                fd: i32,
                offset: i64,
            ) -> *mut std::ffi::c_void;
        }
        let raw = unsafe {
            mmap(
                std::ptr::null_mut(),
                byte_len,
                PROT_READ | PROT_WRITE,
                MAP_SHARED,
                file.as_raw_fd(),
                0,
            )
        };
        if raw == (!0usize as *mut std::ffi::c_void) || raw.is_null() {
            return Err(std::io::Error::last_os_error());
        }
        Ok(Self {
            ptr: NonNull::new(raw as *mut ShmStampedLayout).unwrap(),
            byte_len,
            _file: file,
        })
    }

    #[inline(always)]
    pub fn layout(&self) -> &ShmStampedLayout {
        unsafe { self.ptr.as_ref() }
    }

    #[inline]
    pub fn pod_endpoint(&self) -> StampedPodEndpoint<'_> {
        StampedPodEndpoint {
            chan: self,
            req_seq: 0,
            resp_seq: 0,
        }
    }

    #[inline]
    pub fn gateway_endpoint(&self) -> StampedGatewayEndpoint<'_> {
        StampedGatewayEndpoint {
            chan: self,
            req_seq: 0,
            resp_seq: 0,
        }
    }
}

impl Drop for FastStampedShmChannel {
    fn drop(&mut self) {
        extern "C" {
            fn munmap(addr: *mut std::ffi::c_void, length: usize) -> i32;
        }
        unsafe {
            munmap(self.ptr.as_ptr() as *mut std::ffi::c_void, self.byte_len);
        }
    }
}

/// Strategy-pod endpoint for 128B single-MESI sequence-stamped SHM (`0` false sharing, `0` allocs).
pub struct StampedPodEndpoint<'a> {
    chan: &'a FastStampedShmChannel,
    req_seq: u64,
    resp_seq: u64,
}

impl<'a> StampedPodEndpoint<'a> {
    #[inline(always)]
    pub fn try_publish_order_in_place<F: FnOnce(&mut NormalizedOrderEvent)>(&mut self, writer: F) -> bool {
        let seq = self.req_seq;
        unsafe {
            let slot = &mut *(*self.chan.ptr.as_ptr())
                .req_slots
                .as_mut_ptr()
                .add((seq as usize) & SHM_RING_MASK);
            if slot.seq_stamp.load(Ordering::Acquire) != seq {
                return false;
            }
            writer(&mut slot.payload);
            slot.seq_stamp.store(seq.wrapping_add(1), Ordering::Release);
        }
        self.req_seq = seq.wrapping_add(1);
        true
    }

    /// Wait for the next verdict in ONE single 128B cache-line transfer (`seq_stamp` + `ShmOrderVerdict` co-located!).
    #[inline(always)]
    pub fn wait_verdict_in_place<R, F: FnOnce(&ShmOrderVerdict) -> R>(&mut self, reader: F) -> R {
        let seq = self.resp_seq;
        let expected = seq.wrapping_add(1);
        unsafe {
            let slot = &*(*self.chan.ptr.as_ptr())
                .resp_slots
                .as_ptr()
                .add((seq as usize) & SHM_RING_MASK);
            let mut spins = 0u32;
            while slot.seq_stamp.load(Ordering::Acquire) != expected {
                spins = spins.wrapping_add(1);
                if spins > 8192 {
                    std::hint::spin_loop();
                }
            }
            let res = reader(&slot.payload);
            slot.seq_stamp
                .store(seq.wrapping_add(SHM_RING_CAP as u64), Ordering::Release);
            self.resp_seq = expected;
            res
        }
    }

    #[inline(always)]
    pub fn try_poll_verdict_in_place<R, F: FnOnce(&ShmOrderVerdict) -> R>(&mut self, reader: F) -> Option<R> {
        let seq = self.resp_seq;
        let expected = seq.wrapping_add(1);
        unsafe {
            let slot = &*(*self.chan.ptr.as_ptr())
                .resp_slots
                .as_ptr()
                .add((seq as usize) & SHM_RING_MASK);
            if slot.seq_stamp.load(Ordering::Acquire) != expected {
                return None;
            }
            let res = reader(&slot.payload);
            slot.seq_stamp
                .store(seq.wrapping_add(SHM_RING_CAP as u64), Ordering::Release);
            self.resp_seq = expected;
            Some(res)
        }
    }
}

/// Gateway core endpoint for 128B single-MESI sequence-stamped SHM (`0` false sharing, `0` allocs).
pub struct StampedGatewayEndpoint<'a> {
    chan: &'a FastStampedShmChannel,
    req_seq: u64,
    resp_seq: u64,
}

impl<'a> StampedGatewayEndpoint<'a> {
    #[inline(always)]
    pub fn try_poll_order_in_place<R, F: FnOnce(&NormalizedOrderEvent) -> R>(&mut self, reader: F) -> Option<R> {
        let seq = self.req_seq;
        let expected = seq.wrapping_add(1);
        unsafe {
            let slot = &*(*self.chan.ptr.as_ptr())
                .req_slots
                .as_ptr()
                .add((seq as usize) & SHM_RING_MASK);
            if slot.seq_stamp.load(Ordering::Acquire) != expected {
                return None;
            }
            let res = reader(&slot.payload);
            slot.seq_stamp
                .store(seq.wrapping_add(SHM_RING_CAP as u64), Ordering::Release);
            self.req_seq = expected;
            Some(res)
        }
    }

    #[inline(always)]
    pub fn try_publish_verdict_in_place<F: FnOnce(&mut ShmOrderVerdict)>(&mut self, writer: F) -> bool {
        let seq = self.resp_seq;
        unsafe {
            let slot = &mut *(*self.chan.ptr.as_ptr())
                .resp_slots
                .as_mut_ptr()
                .add((seq as usize) & SHM_RING_MASK);
            if slot.seq_stamp.load(Ordering::Acquire) != seq {
                return false;
            }
            writer(&mut slot.payload);
            slot.seq_stamp.store(seq.wrapping_add(1), Ordering::Release);
        }
        self.resp_seq = seq.wrapping_add(1);
        true
    }
}
