//! Phase D8: Stable C-ABI Foreign Function Interface (`fingate::ffi` matching `include/fingate.h`).
//!
//! Enables C, C++, Go (`cgo`), and Python (`ctypes`) strategy pods to attach directly to
//! FinGate's zero-copy POSIX `MappedShmChannel` and submit 64-byte `NormalizedOrderEvent`
//! orders / poll `ShmOrderVerdict` replies with zero serialization overhead.

use std::ffi::CStr;
use std::os::raw::{c_char, c_int};

use crate::ipc::shm_channel::{FastStampedShmChannel, MappedShmChannel, ShmOrderVerdict};
use crate::protocol::NormalizedOrderEvent;

/// Opaque C handle owning a mapped POSIX shared-memory channel (`FGSHM001`).
pub struct FinGateShmHandle {
    inner: MappedShmChannel,
}

/// Track I6/I8: Opaque C handle owning a 128B single-MESI sequence-stamped SHM channel (`FGSHM002`).
pub struct FinGateStampedShmHandle {
    inner: FastStampedShmChannel,
}

/// Returns packed FinGate ABI version (`0x0001_0800` = v1.8.0 Track D+ compatible).
#[no_mangle]
pub extern "C" fn fingate_abi_version() -> u32 {
    0x0001_0800
}

/// Track I1/I8: Returns `1` if native silicon SHA-256 (`ARMv8 FEAT_SHA256` / `x86 SHA-NI`) is active, else `0`.
#[no_mangle]
pub extern "C" fn fingate_sha256_hw_accelerated() -> c_int {
    if crate::attestation::sha256_hw_accelerated() {
        1
    } else {
        0
    }
}

/// Attach to an existing FinGate shared-memory channel created by the gateway.
/// Returns NULL on error; caller must release via `fingate_shm_close`.
#[no_mangle]
pub unsafe extern "C" fn fingate_shm_connect(path: *const c_char) -> *mut FinGateShmHandle {
    if path.is_null() {
        return std::ptr::null_mut();
    }
    let Ok(cstr) = CStr::from_ptr(path).to_str() else {
        return std::ptr::null_mut();
    };
    match MappedShmChannel::attach(cstr) {
        Ok(inner) => Box::into_raw(Box::new(FinGateShmHandle { inner })),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Create a new FinGate shared-memory channel (for gateway / standalone tests).
#[no_mangle]
pub unsafe extern "C" fn fingate_shm_create(
    path: *const c_char,
    pod_slot: u16,
) -> *mut FinGateShmHandle {
    if path.is_null() {
        return std::ptr::null_mut();
    }
    let Ok(cstr) = CStr::from_ptr(path).to_str() else {
        return std::ptr::null_mut();
    };
    match MappedShmChannel::create(cstr, pod_slot) {
        Ok(inner) => Box::into_raw(Box::new(FinGateShmHandle { inner })),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Submit a 64-byte `NormalizedOrderEvent` into the lock-free SHM ring (`0` = ok, `-1` = ring full / null).
#[no_mangle]
pub unsafe extern "C" fn fingate_shm_submit_order(
    handle: *mut FinGateShmHandle,
    order: *const NormalizedOrderEvent,
) -> c_int {
    if handle.is_null() || order.is_null() {
        return -1;
    }
    let h = &*handle;
    match h.inner.pod_try_submit(*order) {
        Ok(()) => 0,
        Err(_) => -1,
    }
}

/// Poll a 64-byte `ShmOrderVerdict` from FinGate (`1` = verdict written, `0` = empty, `-1` = null).
#[no_mangle]
pub unsafe extern "C" fn fingate_shm_poll_verdict(
    handle: *mut FinGateShmHandle,
    out_verdict: *mut ShmOrderVerdict,
) -> c_int {
    if handle.is_null() || out_verdict.is_null() {
        return -1;
    }
    let h = &*handle;
    match h.inner.pod_try_poll_verdict() {
        Some(v) => {
            *out_verdict = v;
            1
        }
        None => 0,
    }
}

/// Update the pod's liveness heartbeat TSC timestamp in shared memory.
#[no_mangle]
pub unsafe extern "C" fn fingate_shm_pulse_heartbeat(
    handle: *mut FinGateShmHandle,
    tsc_ns: u64,
) {
    if !handle.is_null() {
        (*handle).inner.pulse_pod_heartbeat(tsc_ns);
    }
}

/// Close and unmap a FinGate shared-memory handle.
#[no_mangle]
pub unsafe extern "C" fn fingate_shm_close(handle: *mut FinGateShmHandle) {
    if !handle.is_null() {
        drop(Box::from_raw(handle));
    }
}

/// Track I6/I8: Create a 128B single-MESI sequence-stamped SHM channel (`FGSHM002`).
#[no_mangle]
pub unsafe extern "C" fn fingate_stamped_shm_create(
    path: *const c_char,
    pod_slot: u16,
) -> *mut FinGateStampedShmHandle {
    if path.is_null() {
        return std::ptr::null_mut();
    }
    let Ok(cstr) = CStr::from_ptr(path).to_str() else {
        return std::ptr::null_mut();
    };
    match FastStampedShmChannel::create(cstr, pod_slot) {
        Ok(inner) => Box::into_raw(Box::new(FinGateStampedShmHandle { inner })),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Track I6/I8: Open an existing 128B sequence-stamped SHM channel (`FGSHM002`).
#[no_mangle]
pub unsafe extern "C" fn fingate_stamped_shm_open(
    path: *const c_char,
) -> *mut FinGateStampedShmHandle {
    if path.is_null() {
        return std::ptr::null_mut();
    }
    let Ok(cstr) = CStr::from_ptr(path).to_str() else {
        return std::ptr::null_mut();
    };
    match FastStampedShmChannel::open(cstr) {
        Ok(inner) => Box::into_raw(Box::new(FinGateStampedShmHandle { inner })),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Track I6/I8: Close and unmap a 128B sequence-stamped SHM handle.
#[no_mangle]
pub unsafe extern "C" fn fingate_stamped_shm_close(handle: *mut FinGateStampedShmHandle) {
    if !handle.is_null() {
        let _ = &(*handle).inner;
        drop(Box::from_raw(handle));
    }
}
