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

/// Parses hostname and port from environment variables and resolves them to socket addresses.
///
/// This function reads hostname and port values from environment variables (with fallback
/// defaults), supports comma-separated hostnames for multiple bind addresses, and resolves
/// each hostname to one or more socket addresses (IPv4 and/or IPv6).
///
/// # Arguments
///
/// * `hostname_env_key` - Environment variable name for the hostname (e.g., "EDUMDNS_WEB_HOSTNAME")
/// * `port_env_key` - Environment variable name for the port (e.g., "EDUMDNS_WEB_PORT")
/// * `default_hostname` - Default hostname if environment variable is not set
/// * `default_port` - Default port if environment variable is not set
///
/// # Returns
///
/// Returns `Ok(Vec<SocketAddr>)` containing all resolved socket addresses, or a `CoreError`
/// if DNS resolution fails for any hostname.
///
/// # Behavior
///
/// - If the hostname environment variable contains commas, it splits on commas and resolves
///   each hostname separately
/// - Each hostname is resolved to all available addresses (IPv4 and IPv6)
/// - All resolved addresses are combined into a single vector
/// - The same port is used for all hostnames
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
