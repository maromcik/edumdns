#![no_std]
#![no_main]

use aya_ebpf::helpers::bpf_redirect_map;
use aya_ebpf::macros::map;
use aya_ebpf::maps::HashMap;
use aya_ebpf::maps::XskMap;
use aya_ebpf::{bindings::xdp_action, macros::xdp, programs::XdpContext};
use aya_log_ebpf::info;
use core::{mem, ptr};
use network_types::eth::{EthHdr, EtherType};
use network_types::ip::Ipv4Hdr;

#[map(name = "XSKS")]
static mut XSKS: XskMap = XskMap::with_max_entries(64, 0); // one entry per RX queue

#[map] //
static REDIRECT_MAP: HashMap<u32, u32> = HashMap::<u32, u32>::with_max_entries(1024, 0);

#[xdp]
pub fn edumdns_proxy(ctx: XdpContext) -> u32 {
    match try_edumdns_proxy(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

fn try_edumdns_proxy(ctx: XdpContext) -> Result<u32, ()> {
    info!(&ctx, "received a packet");

    let ethhdr: *const EthHdr = ptr_at(&ctx, 0)?; //

    match unsafe { (*ethhdr).ether_type() } {
        Ok(EtherType::Ipv4) => {}
        _ => return Ok(xdp_action::XDP_PASS),
    }

    let ipv4hdr: *const Ipv4Hdr = unsafe { ptr_at(&ctx, EthHdr::LEN)? };
    let source = u32::from_be_bytes(unsafe { (*ipv4hdr).src_addr });

    unsafe {
        if REDIRECT_MAP.get(&source).is_some() {
            info!(&ctx, "Redirecting packet to userspace; source: {:i}", source);
            let rxq = unsafe { (*ctx.ctx).rx_queue_index };
            let act = unsafe {
                bpf_redirect_map(
                    &raw mut XSKS as *mut aya_ebpf::cty::c_void,
                    rxq as u64,
                    0u64,
                )
            };
            return Ok(act as u32);
        }
    }
    Ok(xdp_action::XDP_PASS)
}

#[inline(always)]
fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *const T)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
