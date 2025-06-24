use crate::error::ServerError;
use crate::transmitter::{PacketTransmitter, PacketTransmitterTask};
use edumdns_core::addr_types::MacAddr;
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
use pnet::ipnetwork::{IpNetwork, Ipv4Network};
use tokio::sync::RwLock;
use tokio::sync::mpsc::{Receiver, Sender};
use edumdns_db::error::DbError;
use edumdns_db::repositories::common::DbCreate;
use edumdns_db::repositories::device::repository::PgDeviceRepository;
use edumdns_db::repositories::probe::models::CreateProbe;
use edumdns_db::repositories::probe::repository::PgProbeRepository;

pub struct PacketStorage {
    pub packets: HashMap<MacAddr, Arc<RwLock<HashSet<ProbePacket>>>>,
    pub packet_receiver: Receiver<AppPacket>,
    pub transmitter_tasks: Vec<PacketTransmitterTask>,
    pub error_sender: Sender<ServerError>,
    pub db_pool: Pool<AsyncPgConnection>,
    pub pg_device_repository: PgDeviceRepository,
    pub pg_probe_repository: PgProbeRepository,
}

impl PacketStorage {
    pub fn new(receiver: Receiver<AppPacket>, error_sender: Sender<ServerError>, db_pool: Pool<AsyncPgConnection>) -> Self {
        Self {
            packets: HashMap::new(),
            packet_receiver: receiver,
            transmitter_tasks: Vec::new(),
            error_sender,
            pg_device_repository: PgDeviceRepository::new(db_pool.clone()),
            pg_probe_repository: PgProbeRepository::new(db_pool.clone()),
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
                    let src_mac = probe_packet.metadata.datalink_metadata.mac_metadata.src_mac;
                    
                    // self.packets
                    //     .entry(src_mac)
                    //     .or_default()
                    //     .write()
                    //     .await
                    //     .insert(probe_packet);

                    let probe_repo = self.pg_probe_repository.clone();
                    let device_repo = self.pg_device_repository.clone();
                    
                    match self.packets.entry(src_mac) {
                        Entry::Occupied(mut e) => {
                            let e = e.get_mut();
                            e.write().await.insert(probe_packet);
                            
                        }
                        Entry::Vacant(e) => {
                            let e = e.insert(Default::default());
                            e.write().await.insert(probe_packet);
                            tokio::task::spawn(async move {
                                // probe_repo.create(&CreateProbe::new(src_mac.0.octets(), IpNetwork::V4(Ipv4Network::new(Ipv4Addr::new(0,0,0,0),0).unwrap()), 0))
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
