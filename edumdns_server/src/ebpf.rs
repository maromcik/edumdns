use crate::error::ServerError;
use aya::maps::{HashMap, Map, MapData};
use ipnetwork::IpNetwork;
use log::{error, info};
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
        match (a.ip(), b.ip()) {
            (IpAddr::V4(a), IpAddr::V4(b)) => {
                let a: u32 = a.into();
                let b: u32 = b.into();
                self.rewrite_map_v4.insert(a, b, 0)?;
                self.rewrite_map_v4.insert(b, a, 0)?;
            }
            (IpAddr::V6(a), IpAddr::V6(b)) => {
                let a: [u8; 16] = a.octets();
                let b: [u8; 16] = b.octets();
                self.rewrite_map_v6.insert(a, b, 0)?;
                self.rewrite_map_v6.insert(b, a, 0)?;
            }
            _ => {}
        }
        for el in self.rewrite_map_v4.iter() {
            error!("AFTER {:?}", el);
        }
        info!("Added IPs to eBPF maps: {} and {} ", a, b);
        Ok(())
    }

    pub fn remove_ip(&mut self, a: IpNetwork, b: IpNetwork) -> Result<(), ServerError> {
        match (a.ip(), b.ip()) {
            (IpAddr::V4(a), IpAddr::V4(b)) => {
                let a: u32 = a.into();
                let b: u32 = b.into();
                self.rewrite_map_v4.remove(&a)?;
                self.rewrite_map_v4.remove(&b)?;
            }
            (IpAddr::V6(a), IpAddr::V6(b)) => {
                let a: [u8; 16] = a.octets();
                let b: [u8; 16] = b.octets();
                self.rewrite_map_v6.remove(&a)?;
                self.rewrite_map_v6.remove(&b)?;
            }
            _ => {}
        }
        for el in self.rewrite_map_v4.iter() {
            error!("AFTER {:?}", el);
        }
        info!("Removed IPs from eBPF maps: {} and {} ", a, b);
        Ok(())
    }
}
