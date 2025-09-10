use std::net::Ipv4Addr;
use anyhow::Context as _;
use aya::maps::HashMap;
use aya::programs::{Xdp};
use clap::Parser;
#[rustfmt::skip]
use log::{debug, warn};
use tokio::signal;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "eth0")]
    iface: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opt = Opt::parse();

    env_logger::init();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {ret}");
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/edumdns_proxy"
    )))?;
    match aya_log::EbpfLogger::init(&mut ebpf) {
        Err(e) => {
            // This can happen if you remove all log statements from your eBPF program.
            warn!("failed to initialize eBPF logger: {e}");
        }
        Ok(logger) => {
            let mut logger =
                tokio::io::unix::AsyncFd::with_interest(logger, tokio::io::Interest::READABLE)?;
            tokio::task::spawn(async move {
                loop {
                    let mut guard = logger.readable_mut().await.unwrap();
                    guard.get_inner_mut().flush();
                    guard.clear_ready();
                }
            });
        }
    }
    let Opt { iface } = opt;
    let program: &mut Xdp = ebpf.program_mut("edumdns_proxy").unwrap().try_into()?;
    program.load()?;
    program.attach(&iface, aya::programs::XdpFlags::default())
        .context("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE")?;

    let wg1: u32 = Ipv4Addr::new(192, 168, 0, 17).into();
    let cctv1: u32 = Ipv4Addr::new(192, 168, 0, 21).into();

    // let mut redirect_map_v4_mac: HashMap<_, u32, [u8; 6]> =
    //     HashMap::try_from(ebpf.map_mut("REWRITE_MAP_V4_MAC").unwrap())?;

    // redirect_map_v4_mac.insert(cctv1, [0x52, 0x54, 0x00, 0x0e, 0xf2, 0xd4], 0)?;
    // redirect_map_v4_mac.insert(dev_fedora, [0x52, 0x54, 0x00, 0xe5, 0xa8, 0xf8], 0)?;

    let mut redirect_map_v4: HashMap<_, u32, u32> =
        HashMap::try_from(ebpf.map_mut("REWRITE_MAP_V4").unwrap())?;


    redirect_map_v4.insert(wg1, cctv1, 0)?;
    redirect_map_v4.insert(cctv1, wg1, 0)?;


    let ctrl_c = signal::ctrl_c();
    println!("Waiting for Ctrl-C...");
    ctrl_c.await?;
    println!("Exiting...");

    Ok(())
}
