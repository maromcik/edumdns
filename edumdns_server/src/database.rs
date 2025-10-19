use diesel_async::AsyncPgConnection;
use diesel_async::pooled_connection::deadpool::Pool;
use edumdns_core::app_packet::ProbePacket;
use edumdns_db::repositories::common::DbCreate;
use edumdns_db::repositories::device::models::CreateDevice;
use edumdns_db::repositories::device::repository::PgDeviceRepository;
use edumdns_db::repositories::packet::models::CreatePacket;
use edumdns_db::repositories::packet::repository::PgPacketRepository;
use log::{debug, error};

pub enum DbCommand {
    StoreDevice(ProbePacket),
    StorePacket(ProbePacket),
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
        while let Some(command) = self.receiver.recv().await {
            match command {
                DbCommand::StoreDevice(device_packet) => {
                    self.store_device_in_database(device_packet).await;
                }
                DbCommand::StorePacket(probe_packet) => {
                    self.store_packet_in_database(probe_packet).await;
                }
            }
        }
    }

    async fn store_device_in_database(&self, packet: ProbePacket) {
        let src_mac = packet
            .packet_metadata
            .datalink_metadata
            .mac_metadata
            .src_mac;
        let src_ip = packet.packet_metadata.ip_metadata.src_ip;
        let device = self
            .device_repo
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

    pub async fn store_packet_in_database(&self, packet: ProbePacket) {
        let src_mac = packet
            .packet_metadata
            .datalink_metadata
            .mac_metadata
            .src_mac;
        let src_ip = packet.packet_metadata.ip_metadata.src_ip;
        let packet = self
            .packet_repo
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
