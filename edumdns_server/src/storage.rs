use crate::error::ServerError;
use crate::transmitter::{PacketTransmitter, PacketTransmitterTask};
use diesel_async::AsyncPgConnection;
use diesel_async::pooled_connection::deadpool::Pool;
use diesel_async::pooled_connection::{AsyncDieselConnectionManager, PoolError};
use edumdns_core::app_packet::{AppPacket, CommandPacket, PacketTransmitRequest, ProbePacket};
use edumdns_core::bincode_types::{IpNetwork, MacAddr, Uuid};
use edumdns_db::error::DbError;
use edumdns_db::repositories::common::DbCreate;
use edumdns_db::repositories::device::models::CreateDevice;
use edumdns_db::repositories::device::repository::PgDeviceRepository;
use edumdns_db::repositories::packet::models::CreatePacket;
use edumdns_db::repositories::packet::repository::PgPacketRepository;
use edumdns_db::repositories::probe::models::CreateProbe;
use edumdns_db::repositories::probe::repository::PgProbeRepository;
use edumdns_db::schema::probe::dsl::probe;
use log::{debug, error, info, warn};
use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tokio::sync::mpsc::{Receiver, Sender};
use uuid::uuid;

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
            // println!("Channel: {}", self.packet_receiver.len());
            // if let Some(hash) = self.packets.get(&MacAddr(
            //     "00:00:00:00:00:00"
            //         .parse::<pnet::datalink::MacAddr>()
            //         .unwrap(),
            // )) {
            //     let x = hash.read().await.len();
            //     println!("Hash: {}", x);
            // }
            match packet {
                AppPacket::Command(command) => match command {
                    CommandPacket::TransmitDevicePackets(target) => {
                        if let Err(e) = self.transmit_device_packets(&target).await {
                            error!(
                                "Error while transmitting packets to target {}: {}",
                                &target, e
                            );
                        };
                    }
                    _ => {}
                },
                AppPacket::Status(status) => {}
                AppPacket::Data(probe_packet) => {
                    let src_mac = probe_packet
                        .packet_metadata
                        .datalink_metadata
                        .mac_metadata
                        .src_mac;

                    let src_ip = probe_packet.packet_metadata.ip_metadata.src_ip;

                    let packet_repo = self.pg_packet_repository.clone();
                    let device_repo = self.pg_device_repository.clone();

                    match self.packets.entry(probe_packet.probe_metadata.id) {
                        Entry::Occupied(mut probe_entry) => {
                            match probe_entry.get_mut().entry((src_mac, src_ip)) {
                                Entry::Occupied(mut device_entry) => {
                                    device_entry.get_mut().insert(probe_packet.clone());
                                }
                                Entry::Vacant(device_entry) => {
                                    let device_entry = device_entry.insert(HashSet::new());
                                    device_entry.insert(probe_packet.clone());
                                }
                            }
                            // let packet = packet_repo
                            //     .create(&CreatePacket::new(
                            //         &5,
                            //         &src_mac.to_octets(),
                            //         &probe_packet
                            //             .packet_metadata
                            //             .datalink_metadata
                            //             .mac_metadata
                            //             .dst_mac
                            //             .to_octets(),
                            //         &probe_packet.packet_metadata.ip_metadata.src_ip.0,
                            //         &probe_packet.packet_metadata.ip_metadata.dst_ip.0,
                            //         &probe_packet.packet_metadata.transport_metadata.src_port,
                            //         &probe_packet.packet_metadata.transport_metadata.dst_port,
                            //         probe_packet.payload,
                            //     ))
                            //     .await
                            //     .unwrap();
                        }
                        Entry::Vacant(probe_entry) => {
                            let probe_entry = probe_entry.insert(HashMap::new());
                            match probe_entry.entry((src_mac, src_ip)) {
                                Entry::Occupied(mut device_entry) => {
                                    device_entry.get_mut().insert(probe_packet.clone());
                                }
                                Entry::Vacant(device_entry) => {
                                    let device_entry = device_entry.insert(HashSet::new());
                                    device_entry.insert(probe_packet.clone());
                                }
                            }

                            tokio::task::spawn(async move {
                                let uuid = uuid!("00000000-0000-0000-0000-000000000020");
                                // let device = device_repo.create(&CreateDevice::new(uuid, src_mac.0.octets(), IpNetwork::V4(Ipv4Network::new(Ipv4Addr::new(0,0,0,0),0).unwrap()), 0)).await.unwrap();
                                // let packet = packet_repo
                                //     .create(&CreatePacket::new(
                                //         &5,
                                //         &src_mac.to_octets(),
                                //         &probe_packet
                                //             .packet_metadata
                                //             .datalink_metadata
                                //             .mac_metadata
                                //             .dst_mac
                                //             .to_octets(),
                                //         &probe_packet.packet_metadata.ip_metadata.src_ip.0,
                                //         &probe_packet.packet_metadata.ip_metadata.dst_ip.0,
                                //         &probe_packet.packet_metadata.transport_metadata.src_port,
                                //         &probe_packet.packet_metadata.transport_metadata.dst_port,
                                //         probe_packet.payload,
                                //     ))
                                //     .await
                                //     .unwrap();
                            });
                        }
                    }

                    debug!("Packet stored in memory: {:?}", src_mac);
                }
            }
        }
    }

    pub async fn transmit_device_packets(
        &mut self,
        target: &PacketTransmitRequest,
    ) -> Result<(), ServerError> {
        let probe_packets = self.packets.get(&target.device.probe_uuid);
        let Some(packets) = probe_packets else {
            warn!("No packets found for mac address: {}", target.device.mac);
            return Ok(());
        };

        let device_packets = packets.get(&(target.device.mac, target.device.ip));

        let Some(packets) = device_packets else {
            warn!("No packets found for target: {}", target);
            return Ok(());
        };

        info!("Packets found for target: {}", target);
        let packets = packets.clone();
        let transmitter = PacketTransmitter::new(
            packets,
            target,
            Duration::from_secs(60),
            Duration::from_millis(100),
            Duration::from_secs(1),
        )
        .await?;
        self.transmitter_tasks
            .push(PacketTransmitterTask::new(transmitter));

        Ok(())
    }
}
