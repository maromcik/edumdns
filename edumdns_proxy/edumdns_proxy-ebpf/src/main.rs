#![no_std]
#![no_main]

use aya_ebpf::macros::map;
use aya_ebpf::maps::HashMap;
use aya_ebpf::{bindings::xdp_action, macros::xdp, programs::XdpContext};
use aya_log_ebpf::{debug, info};
use core::{mem};
use aya_ebpf::bindings::tcphdr;
use network_types::eth::{EthHdr, EtherType};
use network_types::ip::{IpProto, Ipv4Hdr};
use network_types::tcp::TcpHdr;
use network_types::udp::UdpHdr;
use crate::checksum::ChecksumUpdate;

mod checksum;

// IPv4 redirect map: key = original source IPv4, value = new destination IPv4
#[map(name = "REWRITE_MAP_V4")]
static REWRITE_MAP_V4: HashMap<u32, u32> =
    HashMap::<u32, u32>::with_max_entries(4096, 0);

#[map(name = "REWRITE_MAP_V4_MAC")]
static REWRITE_MAP_V4_MAC: HashMap<u32, [u8; 6]> =
    HashMap::<u32, [u8; 6]>::with_max_entries(4096, 0);


// IPv6 redirect map: key = original source IPv6, value = new destination IPv6
#[map(name = "REWRITE_MAP_V6")]
static REWRITE_MAP_V6: HashMap<[u8; 16], [u8; 16]> =
    HashMap::<[u8; 16], [u8; 16]>::with_max_entries(4096, 0);

static PROXY_IP: [u8; 4] = [192, 168, 0, 32];
static SRC_MAC: [u8; 6] = [0xe4, 0x1d, 0x82, 0x72, 0x43, 0xc6];
static DST_MAC: [u8; 6] = [0x18, 0x7a,0x3b,0x5e,0xc6,0x4c];


#[xdp]
pub fn edumdns_proxy(ctx: XdpContext) -> u32 {
    match try_edumdns_proxy(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

fn try_edumdns_proxy(ctx: XdpContext) -> Result<u32, ()> {
    debug!(&ctx, "received a packet");

    let ethhdr: *mut EthHdr = ptr_at(&ctx, 0)?; //

    match unsafe { (*ethhdr).ether_type() } {
        Ok(EtherType::Ipv4) => {}
        _ => return Ok(xdp_action::XDP_PASS),
    }

    let ipv4hdr: *mut Ipv4Hdr = unsafe { ptr_at(&ctx, EthHdr::LEN)? };
    let source = u32::from_be_bytes(unsafe { (*ipv4hdr).src_addr });

    unsafe {
        if let Some(new_dst) = REWRITE_MAP_V4.get(&source) {
            (*ethhdr).src_addr = SRC_MAC;
            (*ethhdr).dst_addr = DST_MAC;

            let old_ipv4_check =  (*ipv4hdr).checksum();
            let old_ipv4_len = (*ipv4hdr).tot_len();
            let old_src = (*ipv4hdr).src_addr;
            let old_dst = (*ipv4hdr).dst_addr;

            let proxy_ip = u32::from_be_bytes(PROXY_IP);
            let old_dst_u32 = u32::from_be_bytes((*ipv4hdr).dst_addr);
            info!(&ctx, "Rewriting packet; old_src: {:i}; new_src {:i}", source, proxy_ip);
            info!(&ctx, "Rewriting packet; old_dst: {:i}; new_dst {:i}", old_dst_u32, *new_dst);
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

            match unsafe { (*ipv4hdr).proto } {
                IpProto::Tcp => {
                    let tcphdr: *mut TcpHdr =
                        ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;


                    let old_checksum = u16::from_be_bytes((*tcphdr).check);
                    (*tcphdr).check = u16::to_be_bytes(ChecksumUpdate::new(old_checksum)
                        .remove_u32(u32::from_be_bytes(old_src))
                        .remove_u32(u32::from_be_bytes(old_dst))
                        .add_u32(proxy_ip)
                        .add_u32(*new_dst)
                        .into_udp_checksum());

                }
                IpProto::Udp => {
                    let udphdr: *mut UdpHdr =
                        ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;

                    let old_checksum = u16::from_be_bytes((*udphdr).check);
                    (*udphdr).check = u16::to_be_bytes(ChecksumUpdate::new(old_checksum)
                        .remove_u32(u32::from_be_bytes(old_src))
                        .remove_u32(u32::from_be_bytes(old_dst))
                        .add_u32(proxy_ip)
                        .add_u32(*new_dst)
                        .into_udp_checksum());

                }
                _ => return Err(()),
            };



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

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
