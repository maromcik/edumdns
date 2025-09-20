mod error;
use anyhow::Context as _;
use bytemuck::{Zeroable};
use aya::programs::Xdp;
use clap::Parser;
use std::path::Path;
use aya::Pod;
use aya::maps::{Array, Map, MapData};
#[rustfmt::skip]
use log::{debug, warn};
use crate::error::{ProxyError, ProxyErrorKind};
use log::info;
use pnet::datalink::MacAddr;
use tokio::signal;

#[repr(C)]
#[derive(Zeroable, Clone, Copy, Debug, Default)]
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

unsafe impl Pod for Config {

}

#[derive(Debug, Parser)]
#[clap(author, version, about, long_about = None)]
struct Cli {
    /// Interface to attach the eBPF program to.
    #[clap(short, long, value_name = "INTERFACE")]
    interface: String,

    /// Path to the eBPF map pin directory, must be mounted as BPFFS.
    #[clap(short, long, default_value = "/sys/fs/bpf/edumdns", value_name = "PIN_PATH")]
    pin_path: String,

    /// New source IP that the program will use (e.g. 192.168.0.32)
    #[clap(long, required = true, value_name="PROXY_IP")]
    proxy_ip: std::net::Ipv4Addr,

    #[clap(long, required = true, value_name="PROXY_IP6")]
    proxy_ip6: std::net::Ipv6Addr,

    /// New Ethernet source MAC (e.g. e4:1d:82:72:43:c6)
    #[clap(long, required = true, value_name="NEW_SRC_MAC")]
    src_mac: MacAddr,

    /// New Ethernet destination MAC (e.g. 18:7a:3b:5e:c6:4c)
    #[clap(long, required = true, value_name="NEW_DST_MAC")]
    dst_mac: MacAddr,
}

#[tokio::main]
async fn main() -> Result<(), ProxyError> {
    let cli = Cli::parse();
    env_logger::init();

    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {ret}");
    }

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
    let program: &mut Xdp = ebpf.program_mut("edumdns_proxy").unwrap().try_into()?;
    program.load()?;
    program.attach(&cli.interface, aya::programs::XdpFlags::default())
        .context("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE")?;

    if let Some(cfg_map) = ebpf.map_mut("CONFIG") {
        // `cfg_map` is a generic `Map` – we need to down‑cast to `Array<Config>`

        // let cfg: Config = Config::try_from(cfg_map).unwrap()

        let mut cfg_array: Array<_, Config> = Array::try_from(cfg_map)?;

        let cfg = Config {
            proxy_ip: cli.proxy_ip.octets(),
            proxy_ip6: cli.proxy_ip6.octets(),
            src_mac: cli.src_mac.octets(),
            dst_mac: cli.dst_mac.octets(),
        };

        cfg_array.set(0, cfg, 0)?;

        info!("configuration written to CONFIG map: {:?}", cfg);
    } else {
        return Err(ProxyError::new(ProxyErrorKind::MapMissing, "CONFIG map is missing"));
    }

    let pin_dir = cli.pin_path.as_str();
    std::fs::create_dir_all(pin_dir)?;
    if let Some(map_v4) = ebpf.map_mut("REWRITE_MAP_V4") {
        map_v4.pin(Path::new(&format!("{}/edumdns_proxy_rewrite_v4", pin_dir)))?;
        info!("pinned map_v4 to: {}/edumdns_proxy_rewrite_v4", pin_dir);
    }

    if let Some(map_v6) = ebpf.map_mut("REWRITE_MAP_V6") {
        map_v6.pin(Path::new(&format!("{}/edumdns_proxy_rewrite_v6", pin_dir)))?;
        info!("pinned map_v6 to: {}/edumdns_proxy_rewrite_v4", pin_dir);
    }

    let ctrl_c = signal::ctrl_c();
    info!("Waiting for Ctrl-C...");
    ctrl_c.await?;
    info!("Exiting...");

    std::fs::remove_dir_all(pin_dir)?;
    info!("unpinned maps");

    Ok(())
}
