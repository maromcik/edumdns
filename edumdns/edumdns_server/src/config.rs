use edumdns_core::utils::TlsConfig;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::Duration;

#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
#[serde(default)]
pub struct ServerConfig {
    #[serde(default = "default_server_hostname")]
    pub hostnames: HashSet<String>,
    #[serde(default = "default_channel_buffer_capacity")]
    pub channel_buffer_capacity: usize,
    #[serde(default)]
    pub connection: ConnectionConfig,
    #[serde(default)]
    pub transmit: TransmitConfig,
    #[serde(default)]
    pub ebpf: Option<EbpfConfig>,
    #[serde(default)]
    pub tls: Option<TlsConfig>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            hostnames: default_server_hostname(),
            channel_buffer_capacity: 1000,
            connection: ConnectionConfig::default(),
            transmit: TransmitConfig::default(),
            ebpf: None,
            tls: None,
        }
    }
}

fn default_server_hostname() -> HashSet<String> {
    HashSet::from(["[::]:5000".into()])
}

fn default_channel_buffer_capacity() -> usize {
    1000
}

#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq, Hash)]
pub struct EbpfConfig {
    pub proxy_ipv4: Ipv4Addr,
    pub proxy_ipv6: Ipv6Addr,
    #[serde(default = "default_ebpf_ping_location")]
    pub pin_location: String,
}

fn default_ebpf_ping_location() -> String {
    "/sys/fs/bpf/edumdns".to_owned()
}

#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq, Hash)]
#[serde(default)]
pub struct TransmitConfig {
    pub max_transmit_subnet_size: u32,
    pub transmit_repeat_delay_multiplicator: u32,
}

impl Default for TransmitConfig {
    fn default() -> Self {
        Self {
            max_transmit_subnet_size: 512,
            transmit_repeat_delay_multiplicator: 5,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq, Hash)]
#[serde(default)]
pub struct ConnectionConfig {
    #[serde(deserialize_with = "duration_from_secs")]
    pub global_timeout: Duration,
    pub buffer_capacity: usize,
}

impl Default for ConnectionConfig {
    fn default() -> Self {
        Self {
            global_timeout: Duration::from_secs(10),
            buffer_capacity: 1000,
        }
    }
}

fn duration_from_secs<'de, D>(deserializer: D) -> Result<Duration, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let secs = u64::deserialize(deserializer)?;
    Ok(Duration::from_secs(secs))
}
