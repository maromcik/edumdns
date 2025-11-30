//! Asynchronous database tasks for persisting devices and packets.
//! 
//! The `DatabaseManager` consumes `DbCommand`s from a channel and performs
//! non-blocking writes to the PostgreSQL database using `diesel_async`.
//! Packet inserts are pipelined and rate-limited with a small in-flight queue.

use diesel_async::AsyncPgConnection;
use diesel_async::pooled_connection::deadpool::Pool;
use edumdns_core::app_packet::ProbePacket;
use edumdns_db::repositories::common::DbCreate;
use edumdns_db::repositories::device::models::CreateDevice;
use edumdns_db::repositories::device::repository::PgDeviceRepository;
use edumdns_db::repositories::packet::models::CreatePacket;
use edumdns_db::repositories::packet::repository::PgPacketRepository;
use futures::stream::{FuturesUnordered, StreamExt};
use log::{debug, error};
use std::time::Duration;
use tokio::time::sleep;

pub enum DbCommand {
    StoreDevice(ProbePacket),
    StorePacket(ProbePacket),
    // RemovePacketTransmitRequest
}

pub struct DatabaseManager {
    pub receiver: tokio::sync::mpsc::Receiver<DbCommand>,
    pub device_repo: PgDeviceRepository,
    pub packet_repo: PgPacketRepository,
}

impl DatabaseManager {
    pub fn new(
        receiver: tokio::sync::mpsc::Receiver<DbCommand>,
        pool: Pool<AsyncPgConnection>,
    ) -> Self {
        Self {
            receiver,
            device_repo: PgDeviceRepository::new(pool.clone()),
            packet_repo: PgPacketRepository::new(pool.clone()),
        }
    }

    pub async fn handle_database(&mut self) {
        let mut futs = FuturesUnordered::new();
        loop {
            tokio::select! {
                Some(command) = self.receiver.recv() => {
                                match command {
                                    DbCommand::StoreDevice(device_packet) => {
                                        Self::store_device_in_database(&self.device_repo, device_packet).await;
                                    }
                                    DbCommand::StorePacket(probe_packet) => {
                                        futs.push(Self::store_packet_in_database(&self.packet_repo, probe_packet));
                                        if futs.len() > 10 {
                                            futs.next().await;
                                        }
                                    }
                                }
                }
                ret = futs.next() => {
                    if ret.is_none() {
                            sleep(Duration::from_millis(1)).await;
                        }
                }

            }
        }
    }

    async fn store_device_in_database(device_repo: &PgDeviceRepository, packet: ProbePacket) {
        let src_mac = packet
            .packet_metadata
            .datalink_metadata
            .mac_metadata
            .src_mac;
        let src_ip = packet.packet_metadata.ip_metadata.src_ip;
        let device = device_repo
            .create(&CreateDevice::new_discover(
                packet.probe_metadata.id.0,
                src_mac.to_octets(),
                src_ip.0,
                packet.packet_metadata.transport_metadata.dst_port,
            ))
            .await;
        match device {
            Ok(d) => {
                debug!(
                    "Device <ID: {}, MAC: {}, IP: {}> stored in database",
                    d.id, src_mac, d.ip
                );
                d
            }
            Err(e) => {
                error!(
                    "Could not store device <MAC: {}, IP: {}> in database: {e}",
                    src_mac, src_ip
                );
                return;
            }
        };
    }

    pub async fn store_packet_in_database(packet_repo: &PgPacketRepository, packet: ProbePacket) {
        let src_mac = packet
            .packet_metadata
            .datalink_metadata
            .mac_metadata
            .src_mac;
        let src_ip = packet.packet_metadata.ip_metadata.src_ip;
        let packet = packet_repo
            .create(&CreatePacket::new(
                packet.probe_metadata.id.0,
                src_mac.to_octets(),
                packet
                    .packet_metadata
                    .datalink_metadata
                    .mac_metadata
                    .dst_mac
                    .0
                    .octets(),
                src_ip.0,
                packet.packet_metadata.ip_metadata.dst_ip.0,
                packet.packet_metadata.transport_metadata.src_port,
                packet.packet_metadata.transport_metadata.dst_port,
                packet.payload,
                packet.payload_hash as i64,
            ))
            .await;
        match packet {
            Ok(p) => debug!(
                "Packet <ProbeID: {}, MAC: {}, IP: {}> stored in database",
                p.probe_id, src_mac, p.src_addr
            ),
            Err(e) => error!(
                "Could not store packet <MAC: {}, IP: {}> in database: {e}",
                src_mac, src_ip
            ),
        }
    }
}
