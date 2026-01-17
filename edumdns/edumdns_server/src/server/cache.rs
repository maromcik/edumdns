use crate::app_packet::{LocalAppPacket, LocalDataPacket, PacketTransmitRequestPacket};
use edumdns_core::app_packet::{EntityType, ProbePacket};
use edumdns_core::bincode_types::{IpNetwork, MacAddr, Uuid};
use log::{debug, info};
use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::mpsc::Sender;

#[derive(Default)]
/// Cached data for a single device (MAC, IP) observed by a probe.
///
/// - `packets` keeps a deduplicated in-memory set of recently seen `ProbePacket`s
///  acting as a simple cache to alleviate the load on the database.
/// - `live_updates_transmitter` is an optional channel tied to an active
///   transmitter job; when present, newly arriving packets are forwarded to the
///   transmitter as live updates.
struct DeviceItem {
    /// Recent, deduplicated packets captured for this device.
    packets: HashSet<ProbePacket>,
    /// If set, sender used to push live updates to the transmitter.
    live_updates_transmitter: Option<Sender<LocalAppPacket>>,
}

impl DeviceItem {
    fn clear_if_needed(&mut self, capacity: usize) {
        if self.packets.len() > capacity {
            self.packets.clear();
        }
    }

    fn send_live_update(&mut self, packet: &ProbePacket) {
        if let Some(chan) = &self.live_updates_transmitter
            && chan
                .try_send(LocalAppPacket::Data(
                    LocalDataPacket::TransmitterLiveUpdateData(packet.payload.clone()),
                ))
                .is_err()
        {
            self.live_updates_transmitter = None;
        }
    }
}

pub(crate) enum CacheMiss {
    Packet,
    PacketAndDevice,
    None,
}

pub(crate) struct Cache {
    packets: HashMap<Uuid, HashMap<(MacAddr, IpNetwork), DeviceItem>>,
    cache_capacity: usize,
}

impl Cache {
    pub(crate) fn new(cache_capacity: usize) -> Self {
        Self {
            packets: HashMap::new(),
            cache_capacity,
        }
    }

    pub(crate) fn invalidate_cache(&mut self, entity: EntityType) {
        match entity {
            EntityType::Probe { probe_id } => {
                self.packets.remove(&probe_id);
            }
            EntityType::Device {
                probe_id,
                device_mac,
                device_ip,
            } => {
                if let Some(probe_entry) = self.packets.get_mut(&probe_id) {
                    probe_entry.remove(&(device_mac, device_ip));
                }
            }
            EntityType::Packet(_) => {}
        }
        info!("Cache invalidated for entity: {:?}", entity);
    }

    pub(crate) async fn set_transmitter(
        &mut self,
        request_packet: Arc<PacketTransmitRequestPacket>,
        live_updater_sender: Sender<LocalAppPacket>,
    ) {
        let device_entry = self
            .packets
            .entry(Uuid(request_packet.device.probe_id))
            .or_default();
        let packet_data = device_entry
            .entry((
                MacAddr::from_octets(request_packet.device.mac),
                IpNetwork(request_packet.device.ip),
            ))
            .or_default();
        packet_data.live_updates_transmitter = Some(live_updater_sender);
    }

    pub(crate) async fn add(&mut self, probe_packet: ProbePacket) -> CacheMiss {
        let src_mac = probe_packet
            .packet_metadata
            .datalink_metadata
            .mac_metadata
            .src_mac;

        let src_ip = probe_packet.packet_metadata.ip_metadata.src_ip;
        match self.packets.entry(probe_packet.probe_metadata.id) {
            Entry::Occupied(mut probe_entry) => {
                match probe_entry.get_mut().entry((src_mac, src_ip)) {
                    Entry::Occupied(mut device_entry) => {
                        let device_item = device_entry.get_mut();
                        device_item.clear_if_needed(self.cache_capacity);

                        if !device_item.packets.contains(&probe_packet) {
                            device_item.packets.insert(probe_packet.clone());
                            device_item.send_live_update(&probe_packet);
                            debug!("Probe and device found; stored packet in database");
                            return CacheMiss::Packet;
                        } else {
                            debug!("Probe, device and packet found; no action");
                        }
                    }
                    Entry::Vacant(device_entry) => {
                        let device_entry = device_entry.insert(DeviceItem::default());
                        device_entry.packets.insert(probe_packet.clone());
                        debug!("Probe found; stored device and packet in database");
                        return CacheMiss::PacketAndDevice;
                    }
                }
            }
            Entry::Vacant(probe_entry) => {
                let probe_entry = probe_entry.insert(HashMap::default());
                probe_entry
                    .entry((src_mac, src_ip))
                    .or_default()
                    .packets
                    .insert(probe_packet.clone());
                debug!("Probe not found in hashmap; stored device and packet in database");
                return CacheMiss::PacketAndDevice;
            }
        }
        debug!("Packet <MAC: {src_mac}, IP: {src_ip}> stored in memory");
        CacheMiss::None
    }
}
