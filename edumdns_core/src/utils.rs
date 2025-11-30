//! Small utilities and macros used across the core crate.
//!
//! - `retry!` — async retry macro with configurable attempts and interval (logs failures)
//! - `Cancellable` — simple trait for cooperative cancellation in state machines
//! - `parse_and_lookup_host` — reads host/port from env and resolves to socket addresses
use crate::error::CoreError;
use std::env;
use std::net::SocketAddr;
use tokio::net::lookup_host;

#[macro_export]
macro_rules! retry {
    ($f:expr, $count:expr, $interval:expr) => {{
        let mut retries = 1;
        let result = loop {
            let result = $f;
            if result.is_ok() {
                break result;
            } else if retries > $count {
                error!("Failed; giving up after {} attempts", $count);
                break result;
            } else {
                error!(
                    "Failed: {}",
                    result.err().expect("Should always be an error")
                );
                warn!("Attempt {} out of {}", retries, $count);
                retries += 1;
                tokio::time::sleep($interval).await;
            }
        };
        result
    }};
    ($f:expr) => {
        retry!($f, 5, 1000)
    };
}

pub trait Cancellable {
    fn cancel(&mut self);
    fn is_cancelled(&self) -> bool;
}

pub async fn parse_and_lookup_host(
    hostname_env_key: &str,
    port_env_key: &str,
    default_hostname: &str,
    default_port: &str,
) -> Result<Vec<SocketAddr>, CoreError> {
    let port = env::var(port_env_key).unwrap_or(default_port.to_string());
    let hostnames_string = env::var(hostname_env_key).unwrap_or(default_hostname.to_string());
    let mut hostnames = Vec::default();
    for hostname in hostnames_string.split(',') {
        hostnames.extend(lookup_host(format!("{hostname}:{port}")).await?)
    }
    Ok(hostnames)
}
