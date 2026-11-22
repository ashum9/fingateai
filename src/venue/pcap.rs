//! Month 2, Week 4: Automated PCAP Generator & Failure Reproducer (`fingate-pcap`).
//!
//! Generates standard Wireshark-compatible `.pcap` capture files containing synthetic
//! Ethernet + IPv4 + TCP encapsulated FIX / SBE packets, enabling quant teams to inspect
//! chaos failure timelines visually in Wireshark.

use anyhow::Result;
use std::fs::File;
use std::io::Write;
use std::path::Path;

pub const PCAP_MAGIC_LE: u32 = 0xa1b2c3d4;
pub const PCAP_VERSION_MAJOR: u16 = 2;
pub const PCAP_VERSION_MINOR: u16 = 4;
pub const LINKTYPE_ETHERNET: u32 = 1;

pub struct PcapWriter {
    file: File,
    packet_count: usize,
}

impl PcapWriter {
    /// Create a new PCAP file and write the standard 24-byte PCAP global header.
    pub fn create(path: impl AsRef<Path>) -> Result<Self> {
        if let Some(parent) = path.as_ref().parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut file = File::create(path)?;

        let mut global_hdr = [0u8; 24];
        global_hdr[0..4].copy_from_slice(&PCAP_MAGIC_LE.to_le_bytes());
        global_hdr[4..6].copy_from_slice(&PCAP_VERSION_MAJOR.to_le_bytes());
        global_hdr[6..8].copy_from_slice(&PCAP_VERSION_MINOR.to_le_bytes());
        global_hdr[8..12].copy_from_slice(&0i32.to_le_bytes()); // thiszone
        global_hdr[12..16].copy_from_slice(&0u32.to_le_bytes()); // sigfigs
        global_hdr[16..20].copy_from_slice(&65535u32.to_le_bytes()); // snaplen
        global_hdr[20..24].copy_from_slice(&LINKTYPE_ETHERNET.to_le_bytes()); // linktype

        file.write_all(&global_hdr)?;
        Ok(Self { file, packet_count: 0 })
    }

    /// Write a FIX/SBE application payload wrapped in Ethernet (14) + IPv4 (20) + TCP (20) headers.
    pub fn write_tcp_packet(
        &mut self,
        timestamp_ns: u64,
        src_port: u16,
        dst_port: u16,
        seq_num: u32,
        ack_num: u32,
        payload: &[u8],
    ) -> Result<()> {
        let ts_sec = (timestamp_ns / 1_000_000_000) as u32;
        let ts_usec = ((timestamp_ns % 1_000_000_000) / 1_000) as u32;

        let total_frame_len = 14 + 20 + 20 + payload.len(); // Eth(14) + IP(20) + TCP(20) + Payload

        // 1. Packet Record Header (16 bytes)
        let mut pkt_hdr = [0u8; 16];
        pkt_hdr[0..4].copy_from_slice(&ts_sec.to_le_bytes());
        pkt_hdr[4..8].copy_from_slice(&ts_usec.to_le_bytes());
        pkt_hdr[8..12].copy_from_slice(&(total_frame_len as u32).to_le_bytes());
        pkt_hdr[12..16].copy_from_slice(&(total_frame_len as u32).to_le_bytes());
        self.file.write_all(&pkt_hdr)?;

        // 2. Synthetic Ethernet Header (14 bytes)
        let mut eth_hdr = [0u8; 14];
        eth_hdr[0..6].copy_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x02]); // Dst MAC
        eth_hdr[6..12].copy_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x01]); // Src MAC
        eth_hdr[12..14].copy_from_slice(&0x0800u16.to_be_bytes()); // IPv4 EtherType (0x0800)
        self.file.write_all(&eth_hdr)?;

        // 3. Synthetic IPv4 Header (20 bytes)
        let mut ip_hdr = [0u8; 20];
        ip_hdr[0] = 0x45; // Version 4, IHL 5 (20 bytes)
        ip_hdr[1] = 0x00; // DSCP / ECN
        let ip_total_len = (20 + 20 + payload.len()) as u16;
        ip_hdr[2..4].copy_from_slice(&ip_total_len.to_be_bytes());
        ip_hdr[4..6].copy_from_slice(&(self.packet_count as u16).to_be_bytes()); // Identification
        ip_hdr[6..8].copy_from_slice(&0x4000u16.to_be_bytes()); // Don't fragment
        ip_hdr[8] = 64; // TTL
        ip_hdr[9] = 6; // Protocol = TCP (6)
        ip_hdr[10..12].copy_from_slice(&0u16.to_be_bytes()); // Checksum (0 for mock/synthetic)
        ip_hdr[12..16].copy_from_slice(&[127, 0, 0, 1]); // Src IP 127.0.0.1
        ip_hdr[16..20].copy_from_slice(&[127, 0, 0, 1]); // Dst IP 127.0.0.1
        self.file.write_all(&ip_hdr)?;

        // 4. Synthetic TCP Header (20 bytes)
        let mut tcp_hdr = [0u8; 20];
        tcp_hdr[0..2].copy_from_slice(&src_port.to_be_bytes());
        tcp_hdr[2..4].copy_from_slice(&dst_port.to_be_bytes());
        tcp_hdr[4..8].copy_from_slice(&seq_num.to_be_bytes());
        tcp_hdr[8..12].copy_from_slice(&ack_num.to_be_bytes());
        tcp_hdr[12] = 0x50; // Data offset 5 (20 bytes), reserved 0
        tcp_hdr[13] = 0x18; // Flags: ACK (0x10) | PSH (0x08)
        tcp_hdr[14..16].copy_from_slice(&65535u16.to_be_bytes()); // Window size
        tcp_hdr[16..18].copy_from_slice(&0u16.to_be_bytes()); // Checksum
        tcp_hdr[18..20].copy_from_slice(&0u16.to_be_bytes()); // Urgent pointer
        self.file.write_all(&tcp_hdr)?;

        // 5. Payload
        self.file.write_all(payload)?;
        self.packet_count += 1;
        Ok(())
    }

    pub fn packet_count(&self) -> usize {
        self.packet_count
    }
}
