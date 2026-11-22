//! Phase C4: Bare-Metal OS Primitives — Core Pinning, Memory Locking & HugePage Arena (`fingate::sys`).
//!
//! Zero external crate dependencies:
//! - On Linux: uses direct `sched_setaffinity`, `mlockall`, and `mmap(MAP_HUGETLB)` via POSIX FFI
//!   for NUMA-pinned, TLB-miss-free execution on co-located bare-metal nodes.
//! - On macOS / non-Linux dev hosts: degrades cleanly to 64-byte cache-aligned page-backed slabs
//!   so all tests and benchmarks compile and verify deterministically offline.

use std::alloc::{alloc_zeroed, dealloc, Layout};
use std::ptr::NonNull;

/// Result of attempting bare-metal thread pinning.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinStatus {
    PinnedToCore(usize),
    UnsupportedOnHost,
}

/// Pin the calling OS thread to a specific physical CPU core (`isolcpus` compatible on Linux).
pub fn pin_current_thread_to_core(core_id: usize) -> Result<PinStatus, String> {
    #[cfg(target_os = "linux")]
    {
        // Linux `cpu_set_t` is 1024 bits (128 bytes = 16 x u64).
        #[repr(C)]
        struct CpuSet {
            bits: [u64; 16],
        }
        extern "C" {
            fn sched_setaffinity(pid: i32, cpusetsize: usize, mask: *const CpuSet) -> i32;
        }
        if core_id >= 1024 {
            return Err(format!("core_id {} exceeds Linux cpu_set_t max (1024)", core_id));
        }
        let mut set = CpuSet { bits: [0u64; 16] };
        set.bits[core_id / 64] |= 1u64 << (core_id % 64);
        let rc = unsafe { sched_setaffinity(0, std::mem::size_of::<CpuSet>(), &set) };
        if rc == 0 {
            Ok(PinStatus::PinnedToCore(core_id))
        } else {
            Err(format!("sched_setaffinity(core={}) failed with rc={}", core_id, rc))
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = core_id;
        Ok(PinStatus::UnsupportedOnHost)
    }
}

/// Lock all current and future process pages into physical RAM (`mlockall`) to prevent page faults.
pub fn lock_process_memory() -> Result<bool, String> {
    #[cfg(target_os = "linux")]
    {
        const MCL_CURRENT: i32 = 1;
        const MCL_FUTURE: i32 = 2;
        extern "C" {
            fn mlockall(flags: i32) -> i32;
        }
        let rc = unsafe { mlockall(MCL_CURRENT | MCL_FUTURE) };
        if rc == 0 {
            Ok(true)
        } else {
            Err(format!("mlockall failed (CAP_IPC_LOCK / LimitMEMLOCK=infinity required): rc={}", rc))
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        Ok(false)
    }
}

/// Contiguous 64-byte cache-line aligned memory arena backed by 2MB Linux HugePages when available.
pub struct HugePageArena {
    ptr: NonNull<u8>,
    len: usize,
    is_hugepage: bool,
    layout: Layout,
}

unsafe impl Send for HugePageArena {}
unsafe impl Sync for HugePageArena {}

impl HugePageArena {
    /// Allocate `size_bytes` rounded up to 64-byte alignment (or 2MB HugePages on Linux if enabled).
    pub fn new(size_bytes: usize) -> Result<Self, String> {
        let aligned_len = size_bytes.max(64).next_multiple_of(64);

        #[cfg(target_os = "linux")]
        {
            const PROT_READ: i32 = 1;
            const PROT_WRITE: i32 = 2;
            const MAP_PRIVATE: i32 = 0x02;
            const MAP_ANONYMOUS: i32 = 0x20;
            const MAP_HUGETLB: i32 = 0x40000;
            const TWO_MB: usize = 2 * 1024 * 1024;
            extern "C" {
                fn mmap(
                    addr: *mut std::ffi::c_void,
                    length: usize,
                    prot: i32,
                    flags: i32,
                    fd: i32,
                    offset: isize,
                ) -> *mut std::ffi::c_void;
            }
            let hp_len = aligned_len.next_multiple_of(TWO_MB);
            let raw = unsafe {
                mmap(
                    std::ptr::null_mut(),
                    hp_len,
                    PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB,
                    -1,
                    0,
                )
            };
            if raw != (-1isize as *mut std::ffi::c_void) && !raw.is_null() {
                if let Some(ptr) = NonNull::new(raw as *mut u8) {
                    let layout = Layout::from_size_align(hp_len, 64).map_err(|e| e.to_string())?;
                    return Ok(Self {
                        ptr,
                        len: hp_len,
                        is_hugepage: true,
                        layout,
                    });
                }
            }
        }

        // Standard 64-byte cache-aligned zeroed fallback
        let layout = Layout::from_size_align(aligned_len, 64).map_err(|e| e.to_string())?;
        let raw = unsafe { alloc_zeroed(layout) };
        let ptr = NonNull::new(raw).ok_or_else(|| "out of memory allocating HugePageArena".to_string())?;
        Ok(Self {
            ptr,
            len: aligned_len,
            is_hugepage: false,
            layout,
        })
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.len
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    #[inline]
    pub fn is_hugepage_backed(&self) -> bool {
        self.is_hugepage
    }

    #[inline]
    pub fn as_slice(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.ptr.as_ptr(), self.len) }
    }

    #[inline]
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        unsafe { std::slice::from_raw_parts_mut(self.ptr.as_ptr(), self.len) }
    }
}

impl Drop for HugePageArena {
    fn drop(&mut self) {
        #[cfg(target_os = "linux")]
        if self.is_hugepage {
            extern "C" {
                fn munmap(addr: *mut std::ffi::c_void, length: usize) -> i32;
            }
            unsafe {
                munmap(self.ptr.as_ptr() as *mut std::ffi::c_void, self.len);
            }
            return;
        }
        unsafe {
            dealloc(self.ptr.as_ptr(), self.layout);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hugepage_arena_alignment_and_rw() {
        let mut arena = HugePageArena::new(4096).unwrap();
        assert_eq!((arena.as_slice().as_ptr() as usize) % 64, 0);
        arena.as_mut_slice()[0] = 0xAA;
        arena.as_mut_slice()[4095] = 0x55;
        assert_eq!(arena.as_slice()[0], 0xAA);
        assert_eq!(arena.as_slice()[4095], 0x55);
    }
}
