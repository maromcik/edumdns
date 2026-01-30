//! eBPF XDP program for packet rewriting and proxying.
//!
//! This module contains the eBPF program that runs in the Linux kernel. It intercepts
//! packets at the XDP (eXpress Data Path) hook and rewrites packet headers for packets
//! that match entries in the rewrite maps.
//!
//! The program:
//! - Checks if a packet's source IP matches an entry in the rewrite map
//! - If matched, rewrites Ethernet MAC addresses, IP addresses, and updates checksums
//! - Supports both IPv4 and IPv6
//! - Handles TCP and UDP protocols
//! - Returns XDP_TX to transmit the modified packet
//! - Returns XDP_PASS for unmatched packets
//!
//! This code runs in a restricted eBPF environment with no standard library.

#![no_std]
#![no_main]

use crate::checksum::ChecksumUpdate;
use aya_ebpf::macros::map;
use aya_ebpf::maps::{Array, HashMap};
use aya_ebpf::{bindings::xdp_action, macros::xdp, programs::XdpContext};
use core::mem;
use aya_log_ebpf::info;
use network_types::eth::{EthHdr, EtherType};
use network_types::ip::{IpProto, Ipv4Hdr, Ipv6Hdr};
use network_types::tcp::TcpHdr;
use network_types::udp::UdpHdr;

mod checksum;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct Config {
    /// IPv4 address that will replace the original source address.
    /// Stored in network‑byte order (big endian) – exactly the same layout
    /// as the `src_addr` field of `Ipv4Hdr`.
    pub proxy_ip: [u8; 4],
    pub proxy_ip6: [u8; 16],
    /// MAC address that will become the new Ethernet source.
    pub src_mac: [u8; 6],

    /// MAC address that will become the new Ethernet destination.
    pub dst_mac: [u8; 6],
}

#[map(name = "CONFIG")]
static CONFIG: Array<Config> = Array::with_max_entries(1, 0);

// IPv4 redirect map: key = original source IPv4, value = new destination IPv4
#[map(name = "EDUMDNS_PROXY_REWRITE_MAP_V4")]
static REWRITE_MAP_V4: HashMap<u32, u32> = HashMap::<u32, u32>::with_max_entries(4096, 0);

// IPv6 redirect map: key = original source IPv6, value = new destination IPv6
#[map(name = "EDUMDNS_PROXY_REWRITE_MAP_V6")]
static REWRITE_MAP_V6: HashMap<[u8; 16], [u8; 16]> =
    HashMap::<[u8; 16], [u8; 16]>::with_max_entries(4096, 0);

#[xdp]
pub fn edumdns_proxy(ctx: XdpContext) -> u32 {
    match try_edumdns_proxy(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

/// Main XDP program entry point.
///
/// This function is called by the kernel for each packet received on the attached
/// interface. It determines the packet type (IPv4 or IPv6) and delegates to the
/// appropriate handler.
///
/// # Arguments
///
/// * `ctx` - XDP context containing packet data and metadata
///
/// # Returns
///
/// Returns an XDP action code:
/// - `XDP_PASS` - Pass the packet unchanged to the kernel network stack
/// - `XDP_TX` - Transmit the modified packet back out the same interface
/// - `XDP_ABORTED` - Abort processing (on error)
fn try_edumdns_proxy(ctx: XdpContext) -> Result<u32, ()> {
    let cfg = get_cfg()?;

    let ethhdr: *mut EthHdr = ptr_at(&ctx, 0)?; //
    match unsafe { (*ethhdr).ether_type() } {
        Ok(EtherType::Ipv4) => handle_ipv4(&ctx, ethhdr, cfg),
        Ok(EtherType::Ipv6) => handle_ipv6(&ctx, ethhdr, cfg),
        _ => Ok(xdp_action::XDP_PASS),
    }
}

/// Handles IPv4 packet rewriting.
///
/// This function checks if the packet's source IPv4 address matches an entry in the
/// rewrite map. If it does, it rewrites:
/// - Ethernet source and destination MAC addresses
/// - IPv4 source address (to proxy IP)
/// - IPv4 destination address (from rewrite map)
/// - IP header checksum
/// - TCP or UDP checksum (depending on protocol)
///
/// # Arguments
///
/// * `ctx` - XDP context containing the packet
/// * `ethhdr` - Pointer to the Ethernet header
/// * `cfg` - Configuration containing proxy IPs and MAC addresses
///
/// # Returns
///
/// Returns `Ok(XDP_TX)` if the packet was rewritten and should be transmitted,
/// or `Ok(XDP_PASS)` if the packet didn't match any rewrite rules.
fn handle_ipv4(ctx: &XdpContext, ethhdr: *mut EthHdr, cfg: Config) -> Result<u32, ()> {
    let ipv4hdr: *mut Ipv4Hdr = ptr_at(ctx, EthHdr::LEN)?;
    let source = u32::from_be_bytes(unsafe { (*ipv4hdr).src_addr });

    unsafe {
        if let Some(new_dst) = REWRITE_MAP_V4.get(&source) {
            (*ethhdr).src_addr = cfg.src_mac;
            (*ethhdr).dst_addr = cfg.dst_mac;

            let old_ipv4_check = (*ipv4hdr).checksum();
            let old_ipv4_len = (*ipv4hdr).tot_len();
            let old_src = (*ipv4hdr).src_addr;
            let old_dst = (*ipv4hdr).dst_addr;

            let proxy_ip = u32::from_be_bytes(cfg.proxy_ip);
            let old_dst_u32 = u32::from_be_bytes((*ipv4hdr).dst_addr);

            (*ipv4hdr).src_addr = proxy_ip.to_be_bytes();
            (*ipv4hdr).dst_addr = new_dst.to_be_bytes();
            let new_ipv4_len = (*ipv4hdr).tot_len();

            (*ipv4hdr).set_checksum(
                ChecksumUpdate::new(old_ipv4_check)
                    .remove_u32(u32::from_be_bytes(old_src))
                    .remove_u32(u32::from_be_bytes(old_dst))
                    .remove_u16(old_ipv4_len)
                    .add_u32(proxy_ip)
                    .add_u32(*new_dst)
                    .add_u16(new_ipv4_len)
                    .into_ip_checksum(),
            );

            match (*ipv4hdr).proto {
                IpProto::Tcp => {
                    let tcphdr: *mut TcpHdr = ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
                    info!(
                        &ctx,
                        "Rewriting packet; old_src: {:i}; new_src {:i}; old_dst: {:i}; new_dst {:i}; src tcp: {}; dst tcp: {}",
                        source,
                        proxy_ip,
                        old_dst_u32,
                        *new_dst,
                        u16::from_be_bytes((*tcphdr).source),
                        u16::from_be_bytes((*tcphdr).dest)
                    );
                    let old_checksum = u16::from_be_bytes((*tcphdr).check);
                    (*tcphdr).check = u16::to_be_bytes(
                        ChecksumUpdate::new(old_checksum)
                            .remove_u32(u32::from_be_bytes(old_src))
                            .remove_u32(u32::from_be_bytes(old_dst))
                            .add_u32(proxy_ip)
                            .add_u32(*new_dst)
                            .into_tcp_checksum(),
                    );
                }
                IpProto::Udp => {
                    let udphdr: *mut UdpHdr = ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
                    info!(
                        &ctx,
                        "Rewriting packet; old_src: {:i}; new_src {:i}; old_dst: {:i}; new_dst {:i}; src udp: {}; dst udp: {}",
                        source,
                        proxy_ip,
                        old_dst_u32,
                        *new_dst,
                        u16::from_be_bytes((*udphdr).src),
                        u16::from_be_bytes((*udphdr).dst)
                    );
                    let old_checksum = u16::from_be_bytes((*udphdr).check);
                    (*udphdr).check = u16::to_be_bytes(
                        ChecksumUpdate::new(old_checksum)
                            .remove_u32(u32::from_be_bytes(old_src))
                            .remove_u32(u32::from_be_bytes(old_dst))
                            .add_u32(proxy_ip)
                            .add_u32(*new_dst)
                            .into_udp_checksum(),
                    );
                }
                _ => return Err(()),
            };

            return Ok(xdp_action::XDP_TX);
        }
    }
    Ok(xdp_action::XDP_PASS)
}

/// Handles IPv6 packet rewriting.
///
/// This function checks if the packet's source IPv6 address matches an entry in the
/// rewrite map. If it does, it rewrites:
/// - Ethernet source and destination MAC addresses
/// - IPv6 source address (to proxy IP)
/// - IPv6 destination address (from rewrite map)
/// - TCP or UDP checksum (depending on protocol)
///
/// # Arguments
///
/// * `ctx` - XDP context containing the packet
/// * `ethhdr` - Pointer to the Ethernet header
/// * `cfg` - Configuration containing proxy IPs and MAC addresses
///
/// # Returns
///
/// Returns `Ok(XDP_TX)` if the packet was rewritten and should be transmitted,
/// or `Ok(XDP_PASS)` if the packet didn't match any rewrite rules.
fn handle_ipv6(ctx: &XdpContext, ethhdr: *mut EthHdr, cfg: Config) -> Result<u32, ()> {
    let ipv6hdr: *mut Ipv6Hdr = ptr_at(ctx, EthHdr::LEN)?;
    let old_src = unsafe { (*ipv6hdr).src_addr };
    let old_dst = unsafe { (*ipv6hdr).dst_addr };

    unsafe {
        if let Some(new_dst) = REWRITE_MAP_V6.get(&old_src) {
            (*ethhdr).src_addr = cfg.src_mac;
            (*ethhdr).dst_addr = cfg.dst_mac;

            (*ipv6hdr).src_addr = cfg.proxy_ip6;
            (*ipv6hdr).dst_addr = *new_dst;

            match (*ipv6hdr).next_hdr {
                IpProto::Tcp => {
                    let tcphdr: *mut TcpHdr = ptr_at(ctx, EthHdr::LEN + Ipv6Hdr::LEN)?;

                    info!(
                        &ctx,
                        "Rewriting packet; old_src: {:i}; new_src {:i}; old_dst: {:i}; new_dst {:i}; src tcp: {}; dst tcp: {}",
                        old_src,
                        cfg.proxy_ip6,
                        old_dst,
                        *new_dst,
                        u16::from_be_bytes((*tcphdr).source),
                        u16::from_be_bytes((*tcphdr).dest)
                    );

                    let old_checksum = u16::from_be_bytes((*tcphdr).check);
                    (*tcphdr).check = u16::to_be_bytes(
                        ChecksumUpdate::new(old_checksum)
                            .remove_u128(u128::from_be_bytes(old_src))
                            .remove_u128(u128::from_be_bytes(old_dst))
                            .add_u128(u128::from_be_bytes(cfg.proxy_ip6))
                            .add_u128(u128::from_be_bytes(*new_dst))
                            .into_tcp_checksum(),
                    );
                }
                IpProto::Udp => {
                    let udphdr: *mut UdpHdr = ptr_at(ctx, EthHdr::LEN + Ipv6Hdr::LEN)?;
                    info!(
                        &ctx,
                        "Rewriting packet; old_src: {:i}; new_src {:i}; old_dst: {:i}; new_dst {:i}; src udp: {}; dst udp: {}",
                        old_src,
                        cfg.proxy_ip6,
                        old_dst,
                        *new_dst,
                        u16::from_be_bytes((*udphdr).src),
                        u16::from_be_bytes((*udphdr).dst)
                    );
                    let old_checksum = u16::from_be_bytes((*udphdr).check);
                    (*udphdr).check = u16::to_be_bytes(
                        ChecksumUpdate::new(old_checksum)
                            .remove_u128(u128::from_be_bytes(old_src))
                            .remove_u128(u128::from_be_bytes(old_dst))
                            .add_u128(u128::from_be_bytes(cfg.proxy_ip6))
                            .add_u128(u128::from_be_bytes(*new_dst))
                            .into_udp_checksum(),
                    );
                }
                _ => return Err(()),
            }

            return Ok(xdp_action::XDP_TX);
        }
    }

    Ok(xdp_action::XDP_PASS)
}

#[inline(always)]
fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*mut T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *mut T)
}

#[inline(always)]
fn get_cfg() -> Result<Config, ()> {
    // `Array::get_ptr` returns a raw pointer; we deref it safely because the
    // map is pinned and we know it contains exactly one entry.
    unsafe { CONFIG.get_ptr(0).ok_or(()).map(|ptr| core::ptr::read(ptr)) }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
