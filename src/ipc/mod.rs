//! Phase D1: Cross-Process Zero-Copy Shared-Memory IPC (`fingate::ipc`).
//!
//! Inspired by Real Logic `Aeron IPC` and Eclipse `iceoryx2`:
//! Eliminates the `~33–37.5 µs` OS kernel TCP loopback penalty for co-located strategy pods
//! via file-backed/tmpfs `MAP_SHARED` `mmap` dual lock-free rings (`< 300 ns` round-trip).

pub mod shm_channel;
