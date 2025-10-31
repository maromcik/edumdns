use crate::error::{ServerError};
use aya::maps::{HashMap, Map, MapData};
use ipnetwork::IpNetwork;
use log::{error, info, warn};
use std::env;
use std::net::IpAddr;
use std::path::Path;

pub struct EbpfUpdater {
    pub rewrite_map_v4: HashMap<MapData, u32, u32>,
    pub rewrite_map_v6: HashMap<MapData, [u8; 16], [u8; 16]>,
}

impl EbpfUpdater {
    pub fn new() -> Result<Self, ServerError> {
        let ebpf_dir = env::var("EDUMDNS_SERVER_EBPF_PIN_LOCATION")
            .unwrap_or("/sys/fs/bpf/edumdns".to_string());
        let map_path_v4 = format!("{ebpf_dir}/edumdns_proxy_rewrite_v4");
        let map_path_v6 = format!("{ebpf_dir}/edumdns_proxy_rewrite_v6");
        info!(
            "Trying to pin eBPF maps at: {} and {} ",
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

    pub fn add_ip(&mut self, a: IpNetwork, b: IpNetwork) -> Result<(), ServerError> {
        let err = |ip_a, ip_b, e| {
            ServerError::EbpfMapError(format!("Could not add IP pair <{ip_a}, {ip_b}> to the eBPF map: {e}"))
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
                return Err(ServerError::EbpfMapError(format!("Could not add IP pair <{a}, {b}> to the eBPF map - both IPs must be of the same type")));
            }
        }
        info!("Added IPs to eBPF maps: {} and {} ", a, b);
        Ok(())
    }

    pub fn remove_ip(&mut self, a: IpNetwork, b: IpNetwork) -> Result<(), ServerError> {
        let err = |ip, e| {
            ServerError::EbpfMapError(
                format!("Could not remove IP {ip} from the eBPF map: {e}"))
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
