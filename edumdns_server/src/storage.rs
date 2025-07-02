use crate::error::ServerError;
use crate::transmitter::{PacketTransmitter, PacketTransmitterTask};
use edumdns_core::bincode_types::MacAddr;
use edumdns_core::app_packet::{AppPacket, CommandPacket, PacketTransmitTarget, ProbePacket};
use log::{debug, error, info, warn};
use std::collections::{HashMap, HashSet};
use std::collections::hash_map::Entry;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Duration;
use diesel_async::AsyncPgConnection;
use diesel_async::pooled_connection::deadpool::Pool;
use diesel_async::pooled_connection::{AsyncDieselConnectionManager, PoolError};
use ipnetwork::{IpNetwork, Ipv4Network};
use tokio::sync::RwLock;
use tokio::sync::mpsc::{Receiver, Sender};
use uuid::uuid;
use edumdns_db::error::DbError;
use edumdns_db::repositories::common::DbCreate;
use edumdns_db::repositories::device::models::CreateDevice;
use edumdns_db::repositories::device::repository::PgDeviceRepository;
use edumdns_db::repositories::packet::models::CreatePacket;
use edumdns_db::repositories::packet::repository::PgPacketRepository;
use edumdns_db::repositories::probe::models::CreateProbe;
use edumdns_db::repositories::probe::repository::PgProbeRepository;

pub struct PacketStorage {
    pub packets: HashMap<MacAddr, Arc<RwLock<HashSet<ProbePacket>>>>,
    pub packet_receiver: Receiver<AppPacket>,
    pub transmitter_tasks: Vec<PacketTransmitterTask>,
    pub error_sender: Sender<ServerError>,
    pub db_pool: Pool<AsyncPgConnection>,
    pub pg_probe_repository: PgProbeRepository,
    pub pg_device_repository: PgDeviceRepository,
    pub pg_packet_repository: PgPacketRepository,
}

impl PacketStorage {
    pub fn new(receiver: Receiver<AppPacket>, error_sender: Sender<ServerError>, db_pool: Pool<AsyncPgConnection>) -> Self {
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
                            error!("Error while transmitting packets to target {}: {}", &target, e);
                        };
                    }
                    CommandPacket::PingRequest() => {}
                    CommandPacket::PingResponse() => {}
                },
                AppPacket::Data(probe_packet) => {
                    let src_mac = probe_packet.packet_metadata.datalink_metadata.mac_metadata.src_mac;

                    // self.packets
                    //     .entry(src_mac)
                    //     .or_default()
                    //     .write()
                    //     .await
                    //     .insert(probe_packet);

                    let packet_repo = self.pg_packet_repository.clone();
                    let device_repo = self.pg_device_repository.clone();

                    match self.packets.entry(src_mac) {
                        Entry::Occupied(mut e) => {
                            let e = e.get_mut();
                            e.write().await.insert(probe_packet.clone());
                            let packet = packet_repo.create(&CreatePacket::new(
                                &5,
                                &src_mac.to_octets(),
                                &probe_packet.packet_metadata.datalink_metadata.mac_metadata.dst_mac.to_octets(),
                                &probe_packet.packet_metadata.ip_metadata.src_ip.0,
                                &probe_packet.packet_metadata.ip_metadata.dst_ip.0,
                                &probe_packet.packet_metadata.transport_metadata.src_port,
                                &probe_packet.packet_metadata.transport_metadata.dst_port,
                                probe_packet.payload
                            )).await.unwrap();
                        }
                        Entry::Vacant(e) => {
                            let e = e.insert(Default::default());
                            e.write().await.insert(probe_packet.clone());
                            tokio::task::spawn(async move {
                                let uuid = uuid!("5eec1f02-90f6-4212-97ed-012168bf124f");
                                // let device = device_repo.create(&CreateDevice::new(uuid, src_mac.0.octets(), IpNetwork::V4(Ipv4Network::new(Ipv4Addr::new(0,0,0,0),0).unwrap()), 0)).await.unwrap();
                                let packet = packet_repo.create(&CreatePacket::new(
                                    &5,
                                    &src_mac.to_octets(),
                                    &probe_packet.packet_metadata.datalink_metadata.mac_metadata.dst_mac.to_octets(),
                                    &probe_packet.packet_metadata.ip_metadata.src_ip.0,
                                    &probe_packet.packet_metadata.ip_metadata.dst_ip.0,
                                    &probe_packet.packet_metadata.transport_metadata.src_port,
                                    &probe_packet.packet_metadata.transport_metadata.dst_port,
                                    probe_packet.payload
                                )).await.unwrap();                                                  
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
        target: &PacketTransmitTarget,
    ) -> Result<(), ServerError> {
        let packets = self.packets.get(&target.mac);
        let Some(packets) = packets else {
            warn!("No packets found for mac address: {}", target.mac);
            return Ok(());
        };

        info!("Packets found for mac address: {}", target.mac);
        let packets = packets.clone();
        let transmitter = PacketTransmitter::new(
            packets,
            target,
            Duration::from_secs(60),
            Duration::from_millis(100),
        )
        .await?;
        self.transmitter_tasks
            .push(PacketTransmitterTask::new(transmitter));

        Ok(())
    }
}
