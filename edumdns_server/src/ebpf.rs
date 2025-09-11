use std::env;
use crate::error::ServerError;
use aya::maps::{HashMap, Map, MapData};
use ipnetwork::IpNetwork;
use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;
use log::info;

pub struct EbpfUpdater {
    pub rewrite_map_v4: HashMap<MapData, u32, u32>,
    pub rewrite_map_v6: HashMap<MapData, [u8; 16], [u8; 16]>,
}

impl EbpfUpdater {
    pub fn new() -> Result<Self, ServerError> {
        let ebpf_dir = env::var("EDUMDNS_SERVER_EBPF_PIN_LOCATION").unwrap_or("/sys/fs/bpf/edumdns".to_string());
        let map_path_v4 = format!("{ebpf_dir}/rewrite_v4");
        let map_path_v6 = format!("{ebpf_dir}/rewrite_v6");
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
        // TODO remove this
        // let wg1: u32 = Ipv4Addr::new(192, 168, 0, 17).into();
        // let cctv1: u32 = Ipv4Addr::new(192, 168, 0, 21).into();
        // self.rewrite_map_v4.insert(wg1, cctv1, 0)?;
        // self.rewrite_map_v4.insert(cctv1, wg1, 0)?;
        match (a.ip(), b.ip()) {
            (IpAddr::V4(a), IpAddr::V4(b)) => {
                let a: u32 = a.into();
                let b: u32 = b.into();
                self.rewrite_map_v4.insert(a, b, 0)?;
                self.rewrite_map_v4.insert(b, a, 0)?;
            }
            (IpAddr::V6(a), IpAddr::V6(b)) => {}
            _ => {}
        }
        Ok(())
    }

    pub fn remove_ip(&mut self, a: IpNetwork, b: IpNetwork) -> Result<(), ServerError> {
        // TODO remove this
        // let wg1: u32 = Ipv4Addr::new(192, 168, 0, 17).into();
        // let cctv1: u32 = Ipv4Addr::new(192, 168, 0, 21).into();
        // self.rewrite_map_v4.remove(&wg1)?;
        // self.rewrite_map_v4.remove(&cctv1)?;
        match (a.ip(), b.ip()) {
            (IpAddr::V4(a), IpAddr::V4(b)) => {
                let a: u32 = a.into();
                let b: u32 = b.into();
                self.rewrite_map_v4.remove(&a)?;
                self.rewrite_map_v4.remove(&b)?;
            }
            (IpAddr::V6(a), IpAddr::V6(b)) => {}
            _ => {}
        }
        Ok(())
    }
}
