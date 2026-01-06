//! eBPF map integration for cast data proxying.
//!
//! `EbpfUpdater` attaches to pinned kernel maps and maintains bi-directional
//! mappings between the client and the device for either IPv4 and IPv6.

use crate::error::ServerError;
use aya::maps::{HashMap, Map, MapData};
use ipnetwork::IpNetwork;
use log::{error, info};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Clone)]
/// Holds proxy configuration and a handle to the eBPF updater.
///
/// When proxying is enabled for the server, the server rewrites A/AAAA answers to point to
/// a proxy IP pair and maintains kernel eBPF maps with client<->device IP
/// mappings. This struct groups the configured proxy IPs and a shared, mutex-
/// protected `EbpfUpdater` used to update those maps.
pub(crate) struct Proxy {
    /// IPv4/IPv6 pair to which DNS answers will be rewritten.
    pub(crate) proxy_ip: ProxyIp,
    /// Shared eBPF maps updater used to add/remove rewrite rules.
    pub(crate) ebpf_updater: Arc<Mutex<EbpfUpdater>>,
}

#[derive(Clone)]
/// Pair of proxy IPs used for DNS A/AAAA rewriting.
///
/// These addresses are substituted into outgoing DNS responses when proxying is
/// enabled. Both IPv4 and IPv6 must be provided.
pub(crate) struct ProxyIp {
    /// IPv4 address that replaces A records in DNS payloads.
    pub(crate) ipv4: Ipv4Addr,
    /// IPv6 address that replaces AAAA records in DNS payloads.
    pub(crate) ipv6: Ipv6Addr,
}

/// Fields:
/// - `rewrite_map_v4`: pinned `HashMap<u32, u32>` for IPv4 address rewrites. Keys
///   and values are native-endian IPv4 addresses represented as `u32`.
/// - `rewrite_map_v6`: pinned `HashMap<[u8; 16], [u8; 16]>` for IPv6 address
///   rewrites. Keys and values are 16-byte IPv6 addresses.
pub struct EbpfUpdater {
    /// IPv4 rewrite map: original IPv4 → proxy IPv4 and proxy → original.
    pub rewrite_map_v4: HashMap<MapData, u32, u32>,
    /// IPv6 rewrite map: original IPv6 → proxy IPv6 and proxy → original.
    pub rewrite_map_v6: HashMap<MapData, [u8; 16], [u8; 16]>,
}

impl EbpfUpdater {
    /// Attach to the pinned eBPF maps.
    ///
    /// Returns:
    /// - `Ok(EbpfUpdater)` when both maps are successfully opened and wrapped
    ///   into `aya::maps::HashMap` handles.
    /// - `Err(ServerError::EbpfMapError)` if the maps can't be opened or wrapped.
    pub fn new(ebpf_dir: &str) -> Result<Self, ServerError> {
        let map_path_v4 = format!("{ebpf_dir}/edumdns_proxy_rewrite_v4");
        let map_path_v6 = format!("{ebpf_dir}/edumdns_proxy_rewrite_v6");
        info!(
            "Trying to attach to eBPF maps at: {} and {} ",
            map_path_v4, map_path_v6
        );
        let map_data_v4 = MapData::from_pin(Path::new(map_path_v4.as_str()))?;
        let map_data_v6 = MapData::from_pin(Path::new(map_path_v6.as_str()))?;
        let rewrite_map_v4: HashMap<MapData, u32, u32> =
            HashMap::try_from(Map::HashMap(map_data_v4))?;
        let rewrite_map_v6: HashMap<MapData, [u8; 16], [u8; 16]> =
            HashMap::try_from(Map::HashMap(map_data_v6))?;
        info!("Pinned eBPF maps: {} and {} ", map_path_v4, map_path_v6);
        Ok(Self {
            rewrite_map_v4,
            rewrite_map_v6,
        })
    }

    /// Add a bi-directional rewrite rule for a pair of IP addresses.
    ///
    /// This inserts two entries into the corresponding eBPF map, one in each
    /// direction, effectively establishing a symmetric mapping between the
    /// original and proxy addresses. Both arguments must have IPs of the same
    /// family (both IPv4 or both IPv6); the network prefix of `IpNetwork` is
    /// ignored here and only the host IP is used.
    ///
    /// Parameters:
    /// - `a`: first IP.
    /// - `b`: second IP.
    ///
    /// Returns:
    /// - `Ok(())` if both map updates succeed.
    /// - `Err(ServerError)` if the IP versions mismatch or map operations fail.
    pub fn add_ip(&mut self, a: IpNetwork, b: IpNetwork) -> Result<(), ServerError> {
        let err = |ip_a, ip_b, e| {
            ServerError::EbpfMapError(format!(
                "Could not add IP pair <{ip_a}, {ip_b}> to the eBPF map: {e}"
            ))
        };
        match (a.ip(), b.ip()) {
            (IpAddr::V4(a_ipv4), IpAddr::V4(b_ipv4)) => {
                let a_bytes: u32 = a_ipv4.into();
                let b_bytes: u32 = b_ipv4.into();
                self.rewrite_map_v4
                    .insert(a_bytes, b_bytes, 0)
                    .map_err(|e| err(a, b, e))?;
                self.rewrite_map_v4
                    .insert(b_bytes, a_bytes, 0)
                    .map_err(|e| err(b, a, e))?;
            }
            (IpAddr::V6(a_ipv6), IpAddr::V6(b_ipv6)) => {
                let a_bytes: [u8; 16] = a_ipv6.octets();
                let b_bytes: [u8; 16] = b_ipv6.octets();
                self.rewrite_map_v6
                    .insert(a_bytes, b_bytes, 0)
                    .map_err(|e| err(a, b, e))?;
                self.rewrite_map_v6
                    .insert(b_bytes, a_bytes, 0)
                    .map_err(|e| err(b, a, e))?;
            }
            _ => {
                let e = ServerError::DiscoveryRequestProcessingError(format!(
                    "Could not add IP pair <{a}, {b}> to the eBPF map - both IPs must be of the same type"
                ));
                error!("{e}");
                return Err(e);
            }
        }
        info!("Added IPs to eBPF maps: {} and {} ", a, b);
        Ok(())
    }

    /// Remove a bi-directional rewrite rule for a pair of IP networks.
    ///
    /// Deletes both directions of the mapping that were previously inserted by
    /// `add_ip`. If one of the removals fails (e.g., the key doesn't exist), an
    /// error is returned. When IP families differ, the function is a no-op.
    ///
    /// Parameters:
    /// - `a`: first IP (as `IpNetwork`). Only the host IP is used.
    /// - `b`: second IP (as `IpNetwork`). Only the host IP is used.
    ///
    /// Returns:
    /// - `Ok(())` if both entries are successfully removed (or nothing to do on
    ///   family mismatch).
    /// - `Err(ServerError)` if a removal from the corresponding eBPF map fails.
    pub fn remove_ip(&mut self, a: IpNetwork, b: IpNetwork) -> Result<(), ServerError> {
        let err = |ip, e| {
            ServerError::EbpfMapError(format!("Could not remove IP {ip} from the eBPF map: {e}"))
        };
        match (a.ip(), b.ip()) {
            (IpAddr::V4(a_ipv4), IpAddr::V4(b_ipv4)) => {
                let a_bytes: u32 = a_ipv4.into();
                let b_bytes: u32 = b_ipv4.into();
                self.rewrite_map_v4
                    .remove(&a_bytes)
                    .map_err(|e| err(a, e))?;
                self.rewrite_map_v4
                    .remove(&b_bytes)
                    .map_err(|e| err(b, e))?;
            }
            (IpAddr::V6(a_ipv6), IpAddr::V6(b_ipv6)) => {
                let a_bytes: [u8; 16] = a_ipv6.octets();
                let b_bytes: [u8; 16] = b_ipv6.octets();
                self.rewrite_map_v6
                    .remove(&a_bytes)
                    .map_err(|e| err(a, e))?;
                self.rewrite_map_v6
                    .remove(&b_bytes)
                    .map_err(|e| err(b, e))?;
            }
            _ => {}
        }
        info!("Removed IPs from eBPF maps: {} and {} ", a, b);
        Ok(())
    }
}
