//! Phase C6: Linux `AF_XDP` Zero-Copy UMEM Rings & Real `eBPF / XDP` Layer-5 Kernel Drop Hook.
//!
//! Provides:
//! 1. `AfXdpUmemConfig` and `XdpDesc` matching Linux `<linux/if_xdp.h>` binary layout.
//! 2. `LinuxEbpfDropHook`: implements `KernelPacketDropHook` updating pinned BPF map
//!    `/sys/fs/bpf/fingate_kill_xdp` via Linux `SYS_bpf` (`BPF_OBJ_GET` + `BPF_MAP_UPDATE_ELEM`).
//! 3. `evaluate_xdp_packet_filter`: deterministic userspace mirror of `crates/fingate-xdp-ebpf/src/main.rs`
//!    allowing full ETH/IPv4/TCP XDP verifier-logic testing on any platform (macOS & Linux).

use crate::killswitch::layers::KernelPacketDropHook;
use crate::sys::HugePageArena;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// XDP verdict mirroring `linux/bpf.h` `enum xdp_action`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum XdpAction {
    Aborted = 0,
    Drop = 1,
    Pass = 2,
    Tx = 3,
    Redirect = 4,
}

/// Binary-compatible `<linux/if_xdp.h>` `struct xdp_desc` descriptor (16 bytes).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[repr(C)]
pub struct XdpDesc {
    pub addr: u64,
    pub len: u32,
    pub options: u32,
}

/// Configuration for a page-aligned zero-copy `AF_XDP` UMEM region.
#[derive(Debug, Clone, Copy)]
pub struct AfXdpUmemConfig {
    pub frame_size: u32,      // Usually 2048 or 4096 bytes
    pub num_frames: u32,      // Power of 2 (e.g., 4096 frames = 16 MB UMEM)
    pub headroom: u32,        // XDP packet headroom
    pub rx_queue_id: u32,     // NIC RX hardware queue index
}

impl Default for AfXdpUmemConfig {
    fn default() -> Self {
        Self {
            frame_size: 2048,
            num_frames: 4096,
            headroom: 0,
            rx_queue_id: 0,
        }
    }
}

/// Zero-copy `AF_XDP` UMEM slab allocator backed by `HugePageArena`.
pub struct AfXdpUmem {
    pub config: AfXdpUmemConfig,
    arena: HugePageArena,
    free_frames: Vec<u64>,
}

impl AfXdpUmem {
    pub fn allocate(config: AfXdpUmemConfig) -> Result<Self, String> {
        let total = (config.frame_size as usize)
            .checked_mul(config.num_frames as usize)
            .ok_or_else(|| "UMEM size overflow".to_string())?;
        let arena = HugePageArena::new(total)?;
        let mut free_frames = Vec::with_capacity(config.num_frames as usize);
        for i in (0..config.num_frames).rev() {
            free_frames.push((i as u64) * (config.frame_size as u64));
        }
        Ok(Self {
            config,
            arena,
            free_frames,
        })
    }

    #[inline]
    pub fn alloc_frame_addr(&mut self) -> Option<u64> {
        self.free_frames.pop()
    }

    #[inline]
    pub fn free_frame_addr(&mut self, addr: u64) {
        self.free_frames.push(addr);
    }

    #[inline]
    pub fn frame_slice(&self, desc: XdpDesc) -> Option<&[u8]> {
        let start = desc.addr as usize;
        let end = start.checked_add(desc.len as usize)?;
        if end <= self.arena.len() {
            Some(&self.arena.as_slice()[start..end])
        } else {
            None
        }
    }

    #[inline]
    pub fn frame_slice_mut(&mut self, addr: u64, len: usize) -> Option<&mut [u8]> {
        let start = addr as usize;
        let end = start.checked_add(len)?;
        if end <= self.arena.len() {
            Some(&mut self.arena.as_mut_slice()[start..end])
        } else {
            None
        }
    }
}

/// Pure-Rust mirror of `crates/fingate-xdp-ebpf/src/main.rs` XDP packet filter logic.
/// Parses Ethernet (14B) -> IPv4 (IHL*4) -> TCP dst_port and enforces Kill Switch `XDP_DROP`
/// or `AF_XDP` `XDP_REDIRECT`.
#[inline]
pub fn evaluate_xdp_packet_filter(
    eth_frame: &[u8],
    kill_flag: u32,
    watched_port: u16,
) -> XdpAction {
    if eth_frame.len() < 14 {
        return XdpAction::Pass;
    }
    let eth_proto = u16::from_be_bytes([eth_frame[12], eth_frame[13]]);
    if eth_proto != 0x0800 {
        return XdpAction::Pass;
    }
    if eth_frame.len() < 34 {
        return XdpAction::Pass;
    }
    let ihl = ((eth_frame[14] & 0x0F) as usize) * 4;
    if ihl < 20 || eth_frame.len() < 14 + ihl + 4 {
        return XdpAction::Pass;
    }
    let ip_proto = eth_frame[14 + 9];
    if ip_proto != 6 {
        return XdpAction::Pass; // Not TCP
    }
    let tcp_off = 14 + ihl;
    let dst_port = u16::from_be_bytes([eth_frame[tcp_off + 2], eth_frame[tcp_off + 3]]);
    let matches = watched_port == 0 || dst_port == watched_port;

    if kill_flag != 0 && matches {
        return XdpAction::Drop;
    }
    if watched_port != 0 && dst_port == watched_port {
        return XdpAction::Redirect;
    }
    XdpAction::Pass
}

/// Phase C6: Production Linux `eBPF / XDP` Layer-5 Kernel Packet Drop Hook.
///
/// Updates pinned BPF map `/sys/fs/bpf/fingate_kill_xdp` index `0` -> `1` directly via Linux
/// `SYS_bpf` (`BPF_OBJ_GET` + `BPF_MAP_UPDATE_ELEM`) without spawning external `bpftool` processes.
pub struct LinuxEbpfDropHook {
    pub bpf_map_path: String,
    pub drop_active: AtomicBool,
    pub updates_performed: AtomicU64,
}

impl LinuxEbpfDropHook {
    pub fn new(bpf_map_path: &str) -> Self {
        Self {
            bpf_map_path: bpf_map_path.to_string(),
            drop_active: AtomicBool::new(false),
            updates_performed: AtomicU64::new(0),
        }
    }

    pub fn default_pinned() -> Self {
        Self::new("/sys/fs/bpf/fingate_kill_xdp")
    }
}

impl KernelPacketDropHook for LinuxEbpfDropHook {
    fn drop_all_inbound_packets(&self, _interface_name: &str) -> std::io::Result<()> {
        self.drop_active.store(true, Ordering::SeqCst);
        self.updates_performed.fetch_add(1, Ordering::Relaxed);

        #[cfg(target_os = "linux")]
        {
            // Direct Linux bpf() syscall constants:
            // BPF_MAP_UPDATE_ELEM = 2, BPF_OBJ_GET = 7, SYS_bpf = 321 (x86_64) / 280 (aarch64)
            #[cfg(target_arch = "x86_64")]
            const SYS_BPF: i64 = 321;
            #[cfg(target_arch = "aarch64")]
            const SYS_BPF: i64 = 280;
            const BPF_MAP_UPDATE_ELEM: i32 = 2;
            const BPF_OBJ_GET: i32 = 7;

            #[repr(C)]
            struct BpfObjAttr {
                pathname: u64,
                bpf_fd: u32,
                file_flags: u32,
            }
            #[repr(C)]
            struct BpfMapUpdateAttr {
                map_fd: u32,
                _pad: u32,
                key: u64,
                value: u64,
                flags: u64,
            }
            extern "C" {
                fn syscall(number: i64, ...) -> i64;
                fn close(fd: i32) -> i32;
            }

            let c_path = std::ffi::CString::new(self.bpf_map_path.as_str())
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
            let mut obj_attr = BpfObjAttr {
                pathname: c_path.as_ptr() as u64,
                bpf_fd: 0,
                file_flags: 0,
            };
            let map_fd = unsafe {
                syscall(
                    SYS_BPF,
                    BPF_OBJ_GET,
                    &mut obj_attr as *mut BpfObjAttr,
                    std::mem::size_of::<BpfObjAttr>(),
                )
            };
            if map_fd < 0 {
                return Err(std::io::Error::last_os_error());
            }
            let key: u32 = 0;
            let val: u32 = 1;
            let mut upd_attr = BpfMapUpdateAttr {
                map_fd: map_fd as u32,
                _pad: 0,
                key: (&key as *const u32) as u64,
                value: (&val as *const u32) as u64,
                flags: 0,
            };
            let rc = unsafe {
                syscall(
                    SYS_BPF,
                    BPF_MAP_UPDATE_ELEM,
                    &mut upd_attr as *mut BpfMapUpdateAttr,
                    std::mem::size_of::<BpfMapUpdateAttr>(),
                )
            };
            unsafe {
                close(map_fd as i32);
            }
            if rc < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        }

        #[cfg(not(target_os = "linux"))]
        {
            Ok(())
        }
    }
}

// =============================================================================
// Track F (F2): Native Linux `<linux/if_xdp.h>` Zero-Copy `AF_XDP` Socket Driver
// =============================================================================

pub const AF_XDP: i32 = 44;
pub const SOL_XDP: i32 = 283;
pub const XDP_RX_RING: i32 = 2;
pub const XDP_TX_RING: i32 = 3;
pub const XDP_UMEM_REG: i32 = 4;
pub const XDP_UMEM_FILL_RING: i32 = 5;
pub const XDP_UMEM_COMPLETION_RING: i32 = 6;
pub const XDP_ZEROCOPY: u16 = 1 << 2;
pub const XDP_USE_NEED_WAKEUP: u16 = 1 << 3;

/// Exact Linux `<linux/if_xdp.h>` `sockaddr_xdp` (16 bytes).
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct SockaddrXdp {
    pub sxdp_family: u16,
    pub sxdp_flags: u16,
    pub sxdp_ifindex: u32,
    pub sxdp_queue_id: u32,
    pub sxdp_shared_umem_fd: u32,
}
const _: () = assert!(std::mem::size_of::<SockaddrXdp>() == 16);

/// Exact Linux `<linux/if_xdp.h>` `xdp_umem_reg` (32 bytes).
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct XdpUmemReg {
    pub addr: u64,
    pub len: u64,
    pub chunk_size: u32,
    pub headroom: u32,
    pub flags: u32,
    pub tx_metadata_len: u32,
}
const _: () = assert!(std::mem::size_of::<XdpUmemReg>() == 32);

/// Native Linux `AF_XDP` `XDP_ZEROCOPY` socket binding helper (zero external crates).
pub struct AfXdpZeroCopySocket {
    pub fd: i32,
    pub ifindex: u32,
    pub queue_id: u32,
    pub zero_copy_bound: bool,
}

impl AfXdpZeroCopySocket {
    /// Open `socket(AF_XDP, SOCK_RAW, 0)`, register `AfXdpUmem` via `XDP_UMEM_REG`,
    /// configure RX/TX/Fill/Completion rings, and `bind()` with `XDP_ZEROCOPY` on Linux.
    pub fn open_and_bind(ifindex: u32, queue_id: u32, umem: &AfXdpUmem, ring_size: u32) -> std::io::Result<Self> {
        #[cfg(target_os = "linux")]
        {
            extern "C" {
                fn socket(domain: i32, ty: i32, protocol: i32) -> i32;
                fn setsockopt(fd: i32, level: i32, optname: i32, optval: *const std::ffi::c_void, optlen: u32) -> i32;
                fn bind(fd: i32, addr: *const std::ffi::c_void, addrlen: u32) -> i32;
                fn close(fd: i32) -> i32;
            }
            const SOCK_RAW: i32 = 3;
            let fd = unsafe { socket(AF_XDP, SOCK_RAW, 0) };
            if fd < 0 {
                return Err(std::io::Error::last_os_error());
            }
            let reg = XdpUmemReg {
                addr: umem.arena.as_slice().as_ptr() as u64,
                len: umem.arena.as_slice().len() as u64,
                chunk_size: umem.config.frame_size,
                headroom: umem.config.headroom,
                flags: 0,
                tx_metadata_len: 0,
            };
            let rc_reg = unsafe {
                setsockopt(
                    fd,
                    SOL_XDP,
                    XDP_UMEM_REG,
                    &reg as *const XdpUmemReg as *const std::ffi::c_void,
                    std::mem::size_of::<XdpUmemReg>() as u32,
                )
            };
            if rc_reg != 0 {
                let err = std::io::Error::last_os_error();
                unsafe { close(fd); }
                return Err(err);
            }
            for opt in [XDP_UMEM_FILL_RING, XDP_UMEM_COMPLETION_RING, XDP_RX_RING, XDP_TX_RING] {
                let rc = unsafe {
                    setsockopt(
                        fd,
                        SOL_XDP,
                        opt,
                        &ring_size as *const u32 as *const std::ffi::c_void,
                        std::mem::size_of::<u32>() as u32,
                    )
                };
                if rc != 0 {
                    let err = std::io::Error::last_os_error();
                    unsafe { close(fd); }
                    return Err(err);
                }
            }
            let sxdp = SockaddrXdp {
                sxdp_family: AF_XDP as u16,
                sxdp_flags: XDP_ZEROCOPY | XDP_USE_NEED_WAKEUP,
                sxdp_ifindex: ifindex,
                sxdp_queue_id: queue_id,
                sxdp_shared_umem_fd: 0,
            };
            let rc_bind = unsafe {
                bind(
                    fd,
                    &sxdp as *const SockaddrXdp as *const std::ffi::c_void,
                    std::mem::size_of::<SockaddrXdp>() as u32,
                )
            };
            if rc_bind != 0 {
                let err = std::io::Error::last_os_error();
                unsafe { close(fd); }
                return Err(err);
            }
            Ok(Self {
                fd,
                ifindex,
                queue_id,
                zero_copy_bound: true,
            })
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (ifindex, queue_id, umem, ring_size);
            Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "AF_XDP XDP_ZEROCOPY requires Linux kernel >= 5.10 with native XDP NIC driver",
            ))
        }
    }
}

impl Drop for AfXdpZeroCopySocket {
    fn drop(&mut self) {
        #[cfg(target_os = "linux")]
        if self.fd >= 0 {
            extern "C" {
                fn close(fd: i32) -> i32;
            }
            unsafe {
                close(self.fd);
            }
        }
    }
}
