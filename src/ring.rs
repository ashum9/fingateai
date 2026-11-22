//! Phase C1: Lock-Free Cache-Padded Wait-Free SPSC Ring Buffer (`fingate::ring`).
//!
//! Eliminates `Arc<tokio::sync::Mutex<...>>` contention between network ingress threads,
//! core risk/multiplexer workers, async WAL persistence threads, and DPU telemetry pipelines.
//! Zero external dependencies; zero heap allocation after ring creation.

use std::cell::UnsafeCell;
use std::mem::MaybeUninit;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

/// Cache-line padded wrapper preventing false sharing between producer and consumer cores.
#[repr(align(64))]
pub struct CachePadded<T> {
    pub value: T,
}

impl<T> CachePadded<T> {
    #[inline]
    pub const fn new(value: T) -> Self {
        Self { value }
    }
}

/// Bounded wait-free Single-Producer Single-Consumer ring buffer.
/// Capacity `N` MUST be a power of two (enforced at compile time via const assertion).
pub struct SpscRing<T, const N: usize> {
    head: CachePadded<AtomicUsize>, // Consumer read cursor
    tail: CachePadded<AtomicUsize>, // Producer write cursor
    buffer: Box<[UnsafeCell<MaybeUninit<T>>; N]>,
}

// SAFETY: Access to disjoint ring slots is synchronized via Acquire/Release on `head` and `tail`.
unsafe impl<T: Send, const N: usize> Send for SpscRing<T, N> {}
unsafe impl<T: Send, const N: usize> Sync for SpscRing<T, N> {}

impl<T, const N: usize> SpscRing<T, N> {
    const _POWER_OF_TWO_CHECK: () = assert!(N >= 2 && (N & (N - 1)) == 0, "SpscRing N must be power of two");

    /// Allocate a single contiguous ring buffer and split into Producer/Consumer handles.
    pub fn split() -> (SpscProducer<T, N>, SpscConsumer<T, N>) {
        let _ = Self::_POWER_OF_TWO_CHECK;
        let mut vec: Vec<UnsafeCell<MaybeUninit<T>>> = Vec::with_capacity(N);
        for _ in 0..N {
            vec.push(UnsafeCell::new(MaybeUninit::uninit()));
        }
        let boxed_slice = vec.into_boxed_slice();
        // SAFETY: `vec` has exact length `N`.
        let buffer: Box<[UnsafeCell<MaybeUninit<T>>; N]> = unsafe {
            Box::from_raw(Box::into_raw(boxed_slice) as *mut [UnsafeCell<MaybeUninit<T>>; N])
        };

        let shared = Arc::new(Self {
            head: CachePadded::new(AtomicUsize::new(0)),
            tail: CachePadded::new(AtomicUsize::new(0)),
            buffer,
        });

        (
            SpscProducer {
                ring: shared.clone(),
                cached_head: 0,
            },
            SpscConsumer {
                ring: shared,
                cached_tail: 0,
            },
        )
    }

    #[inline(always)]
    pub const fn capacity() -> usize {
        N - 1
    }
}

impl<T, const N: usize> Drop for SpscRing<T, N> {
    fn drop(&mut self) {
        let mut h = self.head.value.load(Ordering::Relaxed);
        let t = self.tail.value.load(Ordering::Relaxed);
        let mask = N - 1;
        while h != t {
            unsafe {
                (*self.buffer[h & mask].get()).assume_init_drop();
            }
            h = h.wrapping_add(1);
        }
    }
}

/// Producer endpoint pinned to a single thread/core.
pub struct SpscProducer<T, const N: usize> {
    ring: Arc<SpscRing<T, N>>,
    cached_head: usize,
}

impl<T, const N: usize> SpscProducer<T, N> {
    /// Wait-free push. Returns `Err(item)` if ring is full without blocking or locking.
    #[inline(always)]
    pub fn try_push(&mut self, item: T) -> Result<(), T> {
        let tail = self.ring.tail.value.load(Ordering::Relaxed);
        let next_tail = tail.wrapping_add(1);
        let mask = N - 1;

        if next_tail.wrapping_sub(self.cached_head) > N - 1 {
            self.cached_head = self.ring.head.value.load(Ordering::Acquire);
            if next_tail.wrapping_sub(self.cached_head) > N - 1 {
                return Err(item);
            }
        }

        unsafe {
            (*self.ring.buffer[tail & mask].get()).write(item);
        }
        self.ring.tail.value.store(next_tail, Ordering::Release);
        Ok(())
    }

    /// Gap 4 (E4): Zero-intermediate-copy in-place producer write directly into the ring slot.
    #[inline(always)]
    pub fn try_push_in_place<F: FnOnce(*mut T)>(&mut self, writer: F) -> bool {
        let tail = self.ring.tail.value.load(Ordering::Relaxed);
        let next_tail = tail.wrapping_add(1);
        let mask = N - 1;

        if next_tail.wrapping_sub(self.cached_head) > N - 1 {
            self.cached_head = self.ring.head.value.load(Ordering::Acquire);
            if next_tail.wrapping_sub(self.cached_head) > N - 1 {
                return false;
            }
        }

        unsafe {
            let slot_ptr = (*self.ring.buffer[tail & mask].get()).as_mut_ptr();
            writer(slot_ptr);
        }
        self.ring.tail.value.store(next_tail, Ordering::Release);
        true
    }

    #[inline(always)]
    pub fn len(&self) -> usize {
        let tail = self.ring.tail.value.load(Ordering::Relaxed);
        let head = self.ring.head.value.load(Ordering::Acquire);
        tail.wrapping_sub(head)
    }

    #[inline(always)]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Consumer endpoint pinned to a single thread/core.
pub struct SpscConsumer<T, const N: usize> {
    ring: Arc<SpscRing<T, N>>,
    cached_tail: usize,
}

impl<T, const N: usize> SpscConsumer<T, N> {
    /// Wait-free pop. Returns `None` if ring is empty without blocking or locking.
    #[inline(always)]
    pub fn try_pop(&mut self) -> Option<T> {
        let head = self.ring.head.value.load(Ordering::Relaxed);
        let mask = N - 1;

        if head == self.cached_tail {
            self.cached_tail = self.ring.tail.value.load(Ordering::Acquire);
            if head == self.cached_tail {
                return None;
            }
        }

        let val = unsafe { (*self.ring.buffer[head & mask].get()).assume_init_read() };
        self.ring
            .head
            .value
            .store(head.wrapping_add(1), Ordering::Release);
        Some(val)
    }

    /// Drain up to `max_batch` items in a single amortized Acquire/Release pass.
    #[inline]
    pub fn pop_batch(&mut self, out: &mut Vec<T>, max_batch: usize) -> usize {
        let head = self.ring.head.value.load(Ordering::Relaxed);
        self.cached_tail = self.ring.tail.value.load(Ordering::Acquire);
        let avail = self.cached_tail.wrapping_sub(head);
        if avail == 0 {
            return 0;
        }
        let count = avail.min(max_batch);
        let mask = N - 1;
        for i in 0..count {
            let val = unsafe {
                (*self.ring.buffer[head.wrapping_add(i) & mask].get()).assume_init_read()
            };
            out.push(val);
        }
        self.ring
            .head
            .value
            .store(head.wrapping_add(count), Ordering::Release);
        count
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_spsc_ring_wait_free_fifo_and_wraparound() {
        let (mut tx, mut rx) = SpscRing::<u64, 16>::split();
        assert_eq!(SpscRing::<u64, 16>::capacity(), 15);
        for round in 0..10u64 {
            for i in 0..15u64 {
                tx.try_push(round * 100 + i).unwrap();
            }
            assert!(tx.try_push(999).is_err());
            for i in 0..15u64 {
                assert_eq!(rx.try_pop(), Some(round * 100 + i));
            }
            assert_eq!(rx.try_pop(), None);
        }
    }
}
