//! Phase D7: Linux Kernel TLS (`kTLS` / `SOL_TLS`) Zero-Copy Socket Offload Configurator.
//!
//! Offloads symmetric TLS 1.3 AES-GCM encryption directly into the Linux kernel / SmartNIC
//! via `setsockopt(SOL_TCP, TCP_ULP, "tls")` + `setsockopt(SOL_TLS, TLS_TX/TLS_RX, ...)`,
//! eliminating user-space TLS framing copies on encrypted exchange uplinks.
//!
//! On non-Linux hosts (e.g. macOS development), reports `NotSupportedOnPlatform` cleanly.

pub const SOL_TCP: i32 = 6;
pub const TCP_ULP: i32 = 31;
pub const SOL_TLS: i32 = 282;
pub const TLS_TX: i32 = 1;
pub const TLS_RX: i32 = 2;

pub const TLS_1_3_VERSION: u16 = 0x0304;
pub const TLS_CIPHER_AES_GCM_128: u16 = 51;
pub const TLS_CIPHER_AES_GCM_256: u16 = 52;

/// Exact Linux `<linux/tls.h>` `tls12_crypto_info_aes_gcm_128` ABI struct (40 bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct TlsCryptoInfoAesGcm128 {
    pub version: u16,     // TLS_1_3_VERSION (0x0304)
    pub cipher_type: u16, // TLS_CIPHER_AES_GCM_128 (51)
    pub iv: [u8; 8],
    pub key: [u8; 16],
    pub salt: [u8; 4],
    pub rec_seq: [u8; 8],
}

const _: () = assert!(std::mem::size_of::<TlsCryptoInfoAesGcm128>() == 40);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KtlsOffloadStatus {
    /// Linux kernel `tls` ULP successfully attached to socket fd.
    EnabledKernelOffload,
    /// Platform does not support Linux `SOL_TLS` kTLS offload (e.g., macOS).
    NotSupportedOnPlatform(&'static str),
    /// Linux kernel rejected `setsockopt` (e.g. `CONFIG_TLS` / `modprobe tls` not loaded).
    KernelError(i32),
}

/// Attempt to attach the Linux `tls` Upper-Layer Protocol (`TCP_ULP`) to an open TCP socket `fd`.
pub fn try_enable_ktls_ulp(fd: i32) -> KtlsOffloadStatus {
    #[cfg(target_os = "linux")]
    {
        extern "C" {
            fn setsockopt(
                socket: i32,
                level: i32,
                name: i32,
                value: *const std::ffi::c_void,
                option_len: u32,
            ) -> i32;
        }
        let ulp = b"tls\0";
        let rc = unsafe {
            setsockopt(
                fd,
                SOL_TCP,
                TCP_ULP,
                ulp.as_ptr() as *const std::ffi::c_void,
                ulp.len() as u32,
            )
        };
        if rc == 0 {
            KtlsOffloadStatus::EnabledKernelOffload
        } else {
            let err = std::io::Error::last_os_error().raw_os_error().unwrap_or(-1);
            KtlsOffloadStatus::KernelError(err)
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = fd;
        KtlsOffloadStatus::NotSupportedOnPlatform(
            "Linux kTLS (SOL_TLS) requires Linux kernel >= 4.17 with CONFIG_TLS=y",
        )
    }
}

/// Install negotiated TLS 1.3 AES-128-GCM TX & RX keys into the kernel socket via `SOL_TLS`.
pub fn install_ktls_aes128_keys(
    fd: i32,
    tx_info: &TlsCryptoInfoAesGcm128,
    rx_info: &TlsCryptoInfoAesGcm128,
) -> KtlsOffloadStatus {
    #[cfg(target_os = "linux")]
    {
        extern "C" {
            fn setsockopt(
                socket: i32,
                level: i32,
                name: i32,
                value: *const std::ffi::c_void,
                option_len: u32,
            ) -> i32;
        }
        let sz = std::mem::size_of::<TlsCryptoInfoAesGcm128>() as u32;
        let rc_tx = unsafe {
            setsockopt(
                fd,
                SOL_TLS,
                TLS_TX,
                tx_info as *const TlsCryptoInfoAesGcm128 as *const std::ffi::c_void,
                sz,
            )
        };
        if rc_tx != 0 {
            let err = std::io::Error::last_os_error().raw_os_error().unwrap_or(-1);
            return KtlsOffloadStatus::KernelError(err);
        }
        let rc_rx = unsafe {
            setsockopt(
                fd,
                SOL_TLS,
                TLS_RX,
                rx_info as *const TlsCryptoInfoAesGcm128 as *const std::ffi::c_void,
                sz,
            )
        };
        if rc_rx != 0 {
            let err = std::io::Error::last_os_error().raw_os_error().unwrap_or(-1);
            return KtlsOffloadStatus::KernelError(err);
        }
        KtlsOffloadStatus::EnabledKernelOffload
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = (fd, tx_info, rx_info);
        KtlsOffloadStatus::NotSupportedOnPlatform(
            "Linux kTLS (SOL_TLS) requires Linux kernel >= 4.17 with CONFIG_TLS=y",
        )
    }
}
