mod error;
use anyhow::Context as _;
use aya::programs::Xdp;
use clap::Parser;
use std::path::Path;
#[rustfmt::skip]
use log::{debug, warn};
use crate::error::ProxyError;
use log::info;
use tokio::signal;
#[derive(Debug, Parser)]
struct Cli {
    #[clap(short, long)]
    interface: String,
    #[clap(short, long, default_value = "/sys/fs/bpf/edumdns")]
    ebpf_pin_path: String,
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

    let pin_dir = cli.ebpf_pin_path.as_str();
    std::fs::create_dir_all(pin_dir)?;
    if let Some(map_v4) = ebpf.map_mut("REWRITE_MAP_V4") {
        map_v4.pin(Path::new(&format!("{}/rewrite_v4", pin_dir)))?;
        info!("pinned map_v4 to: {}/rewrite_v4", pin_dir);
    }

    if let Some(map_v6) = ebpf.map_mut("REWRITE_MAP_V6") {
        map_v6.pin(Path::new(&format!("{}/rewrite_v6", pin_dir)))?;
        info!("pinned map_v6 to: {}/rewrite_v6", pin_dir);
    }

    let ctrl_c = signal::ctrl_c();
    info!("Waiting for Ctrl-C...");
    ctrl_c.await?;
    info!("Exiting...");

    std::fs::remove_dir_all(pin_dir)?;
    info!("unpinned maps");

    Ok(())
}
