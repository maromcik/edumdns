//! Small utilities and macros used across the core crate.
//!
//! - `retry!` — async retry macro with configurable attempts and interval (logs failures)
//! - `Cancellable` — simple trait for cooperative cancellation in state machines
//! - `parse_and_lookup_host` — reads host/port from env and resolves to socket addresses

use std::collections::HashSet;
use crate::error::CoreError;
use std::net::SocketAddr;
use log::info;
use rustls::ServerConfig;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use rustls_pki_types::pem::PemObject;
use serde::{Deserialize, Serialize};
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

pub async fn lookup_hosts(
    hostname_set: HashSet<String>,
) -> Result<Vec<SocketAddr>, CoreError> {
    let mut hostnames = Vec::default();
    for hostname in hostname_set {
        hostnames.extend(lookup_host(hostname).await?)
    }
    Ok(hostnames)
}

pub async fn parse_tls_config(tls_config: &Option<TlsConfig>) -> Result<Option<ServerConfig>, CoreError> {
    let server_config = match tls_config {
        None => {
            info!("No TLS configuration provided");
            None
        }
        Some(config) => {
            let certs = CertificateDer::pem_file_iter(&config.cert_path)?
                .collect::<Result<Vec<_>, _>>()?;
            let key = PrivateKeyDer::from_pem_file(&config.key_path)?;
            info!("TLS certificates loaded");
            Some(
                ServerConfig::builder()
                    .with_no_client_auth()
                    .with_single_cert(certs, key)?,
            )
        }
    };
    Ok(server_config)
}

#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq, Hash)]
pub struct TlsConfig {
    pub cert_path: String,
    pub key_path: String,
}