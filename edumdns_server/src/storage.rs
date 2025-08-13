use crate::error::ServerError;
use crate::transmitter::{PacketTransmitter, PacketTransmitterTask};
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use diesel_async::pooled_connection::deadpool::Pool;
use diesel_async::pooled_connection::{AsyncDieselConnectionManager, PoolError};
use edumdns_core::app_packet::{
    AppPacket, CommandPacket, PacketTransmitRequest, ProbePacket, StatusPacket,
};
use edumdns_core::bincode_types::{IpNetwork, MacAddr, Uuid};
use edumdns_db::error::DbError;
use edumdns_db::repositories::common::{DbCreate, DbReadMany, DbReadOne, DbResultMultiple, DbResultSingle};
use edumdns_db::repositories::device::models::CreateDevice;
use edumdns_db::repositories::device::repository::PgDeviceRepository;
use edumdns_db::repositories::packet::models::{CreatePacket, SelectManyFilter};
use edumdns_db::repositories::packet::repository::PgPacketRepository;
use edumdns_db::repositories::probe::models::CreateProbe;
use edumdns_db::repositories::probe::repository::PgProbeRepository;
use edumdns_db::schema::probe::dsl::probe;
use ipnetwork::Ipv4Network;
use log::{debug, error, info, warn};
use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tokio::sync::mpsc::{Receiver, Sender};
use uuid::uuid;
use edumdns_db::schema::packet::dst_mac;

pub struct PacketStorage {
    pub packets: HashMap<Uuid, HashMap<(MacAddr, IpNetwork), HashSet<ProbePacket>>>,
    pub packet_receiver: Receiver<AppPacket>,
    pub transmitter_tasks: Vec<PacketTransmitterTask>,
    pub error_sender: Sender<ServerError>,
    pub db_pool: Pool<AsyncPgConnection>,
    pub pg_probe_repository: PgProbeRepository,
    pub pg_device_repository: PgDeviceRepository,
    pub pg_packet_repository: PgPacketRepository,
}

impl PacketStorage {
    pub fn new(
        receiver: Receiver<AppPacket>,
        error_sender: Sender<ServerError>,
        db_pool: Pool<AsyncPgConnection>,
    ) -> Self {
        Self {
            packets: HashMap::new(),
            packet_receiver: receiver,
            transmitter_tasks: Vec::new(),
            error_sender,
            pg_probe_repository: PgProbeRepository::new(db_pool.clone()),
            pg_device_repository: PgDeviceRepository::new(db_pool.clone()),
            pg_packet_repository: PgPacketRepository::new(db_pool.clone()),
            db_pool,
        }
    }

    pub async fn handle_packets(&mut self) {
        while let Some(packet) = self.packet_receiver.recv().await {
            match packet {
                AppPacket::Command(command) => match command {
                    CommandPacket::TransmitDevicePackets(target) => {
                        self.transmit_device_packets(target);
                    }
                    CommandPacket::ReconnectProbe => todo!(),
                },
                AppPacket::Status(status) => {},
                AppPacket::Data(probe_packet) => {
                    let src_mac = probe_packet
                        .packet_metadata
                        .datalink_metadata
                        .mac_metadata
                        .src_mac;

                    let src_ip = probe_packet.packet_metadata.ip_metadata.src_ip;


                    self
                        .packets
                        .entry(probe_packet.probe_metadata.id)
                        .or_default()
                        .entry((src_mac, src_ip))
                        .or_default()
                        .insert(probe_packet.clone());
                    debug!("Packet <MAC: {src_mac}, IP: {src_ip}> stored in memory");
                    self.store_in_database(probe_packet).await;
                    // match self.packets.entry(probe_packet.probe_metadata.id) {
                    //     Entry::Occupied(mut probe_entry) => {
                    //         match probe_entry.get_mut().entry((src_mac, src_ip)) {
                    //             Entry::Occupied(mut device_entry) => {
                    //                 device_entry.get_mut().insert(probe_packet.clone());
                    //             }
                    //             Entry::Vacant(device_entry) => {
                    //                 let device_entry = device_entry.insert(HashSet::new());
                    //                 device_entry.insert(probe_packet.clone());
                    //             }
                    //         }
                    //     }
                    //     Entry::Vacant(probe_entry) => {
                    //         let probe_entry = probe_entry.insert(HashMap::new());
                    //         match probe_entry.entry((src_mac, src_ip)) {
                    //             Entry::Occupied(mut device_entry) => {
                    //                 device_entry.get_mut().insert(probe_packet.clone());
                    //             }
                    //             Entry::Vacant(device_entry) => {
                    //                 let device_entry = device_entry.insert(HashSet::new());
                    //                 device_entry.insert(probe_packet.clone());
                    //             }
                    //         }
                    //     }
                    // }
                }
            }
        }
    }

    pub async fn store_in_database(&self, packet: ProbePacket) {
        let src_mac = packet
            .packet_metadata
            .datalink_metadata
            .mac_metadata
            .src_mac;
        let src_ip = packet.packet_metadata.ip_metadata.src_ip;
        let packet_repo = self.pg_packet_repository.clone();
        let device_repo = self.pg_device_repository.clone();
        tokio::task::spawn(async move {
            let device = device_repo
                .create(&CreateDevice::new(
                    packet.probe_metadata.id.0,
                    src_mac
                        .0
                        .octets(),
                    src_ip
                        .0,
                    packet.packet_metadata.transport_metadata.dst_port,
                ))
                .await;
            let device = match device {
                Ok(d) => {
                    debug!("Device <ID: {}, MAC: {}, IP: {}> stored in database", d.id, src_mac, d.ip);
                    d
                },
                Err(e) => {
                    error!("Could not store device <MAC: {}, IP: {}> in database: {e}", src_mac, src_ip);
                    return;
                },
            };

            let packet = packet_repo
                .create(&CreatePacket::new(
                    device.id,
                    src_mac.0.octets(),
                    packet.packet_metadata.datalink_metadata.mac_metadata.dst_mac.0.octets(),
                    src_ip.0,
                    packet.packet_metadata.ip_metadata.dst_ip.0,
                    packet.packet_metadata.transport_metadata.src_port,
                    packet.packet_metadata.transport_metadata.dst_port,
                    packet.payload
                ))
                .await;
            match packet {
                Ok(p) => debug!("Packet <ID: {}, MAC: {}, IP: {}> stored in database", p.id, src_mac, p.src_addr),
                Err(e) => error!("Could not store packet <MAC: {}, IP: {}> in database: {e}", src_mac, src_ip)
            }
        });
    }


    pub fn transmit_device_packets(
        &mut self,
        transmit_request: PacketTransmitRequest,
    ) {

        let packet_repo = self.pg_packet_repository.clone();
        let device_repo = self.pg_device_repository.clone();
        
        tokio::task::spawn(async move {
            let device = match device_repo.read_one(&transmit_request.device.probe_uuid.0).await {
                Ok(d) => d,
                Err(e) => {
                    warn!("No target device: {transmit_request}: {e}");
                    return;
                }
            };

            info!("Target device found: {}", transmit_request);
            
            let packets = match packet_repo.read_many(&SelectManyFilter::new(Some(device.id), None, None, None,None,None,None,None)).await {
                Ok(p) => p,
                Err(e) => {
                    warn!("No packets found for device: {device}");
                    return;
                }
            };

            info!("Packets found for target: {}", transmit_request);
            
            let payloads = packets.into_iter().map(|(d, p)| p.payload).collect::<HashSet<Vec<u8>>>();
            let transmitter = PacketTransmitter::new(
                payloads,
                transmit_request.clone(),
                Duration::from_secs(60),
                Duration::from_millis(100),
                Duration::from_secs(1),
            ).await;
            
            let Ok(transmitter) = transmitter else {
                error!("Could not create transmitter for target: {transmit_request}");
                return;
            };
            PacketTransmitterTask::new(transmitter);
            
        });
    }
}
