use crate::error::{ServerError, ServerErrorKind};
use diesel_async::AsyncPgConnection;
use diesel_async::pooled_connection::deadpool::Pool;
use edumdns_core::app_packet::{AppPacket, CommandPacket, ProbeConfigElement, ProbeConfigPacket, StatusPacket};
use edumdns_core::bincode_types::Uuid;
use edumdns_core::connection::TcpConnection;
use edumdns_db::repositories::common::{DbCreate, DbReadOne};
use edumdns_db::repositories::probe::repository::PgProbeRepository;
use std::time::Duration;
use ipnetwork::IpNetwork;
use tokio::net::TcpStream;
use tokio::sync::mpsc::Sender;
use tokio::time::sleep;
use edumdns_core::metadata::ProbeMetadata;
use edumdns_db::models::Probe;
use edumdns_db::repositories::probe::models::CreateProbe;

pub struct ConnectionManager {
    connection: TcpConnection,
    pg_probe_repository: PgProbeRepository,
}

impl ConnectionManager {
    pub async fn new(
        stream: TcpStream,
        pool: Pool<AsyncPgConnection>,
    ) -> Result<Self, ServerError> {
        Ok(Self {
            connection: TcpConnection::stream_to_framed(stream).await?,
            pg_probe_repository: PgProbeRepository::new(pool.clone()),
        })
    }

    pub async fn connection_init_server(&mut self) -> Result<(), ServerError> {
        let error = Err(ServerError::new(
            ServerErrorKind::InvalidConnectionInitiation,
            "invalid connection initiation",
        ));
        let packet = self.receive_init_packet().await?;

        let AppPacket::Status(StatusPacket::ProbeHello(hello_metadata)) = packet else {
            return error;
        };

        // TODO check uuid in DB
        // TODO create it in the db
        
        let probe = self.upsert_probe(&hello_metadata).await?;
        if probe.adopted {
            self.connection
                .send_packet(&AppPacket::Status(StatusPacket::ProbeAdopted))
                .await?;
        } else {
            self.connection
                .send_packet(&AppPacket::Status(StatusPacket::ProbeUnknown))
                .await?;
            return Err(ServerError::new(
                ServerErrorKind::ProbeNotAdopted,
                "adopt it in the web interface first",
            ));
        }

        let packet = self.receive_init_packet().await?;

        let AppPacket::Status(StatusPacket::ProbeRequestConfig(config_metadata)) = packet else {
            return error;
        };

        if config_metadata != hello_metadata {
            return error;
        }

        // TODO pull config from DB

        let probe_config = ProbeConfigElement {
            interface_name: "wlp2s0".to_string(),
            bpf_filter: None,
        };

        let probe_config_packet = ProbeConfigPacket {
            interface_filter_map: vec![probe_config],
        };
        self.connection
            .send_packet(&AppPacket::Status(StatusPacket::ProbeResponseConfig(
                probe_config_packet,
            )))
            .await?;

        Ok(())
    }

    pub async fn receive_init_packet(&mut self) -> Result<AppPacket, ServerError> {
        let packet: Option<(AppPacket, usize)> = self.connection.receive_next().await?;
        let Some((app_packet, _)) = packet else {
            return Err(ServerError::new(
                ServerErrorKind::InvalidConnectionInitiation,
                "invalid connection initiation",
            ));
        };
        Ok(app_packet)
    }

    pub async fn transfer_packets(&mut self, tx: Sender<AppPacket>) -> Result<(), ServerError> {
        while let Some((packet, length)) = self.connection.receive_next::<AppPacket>().await? {
            tx.send(packet).await.expect("Poisoned");
        }
        Ok(())
    }

    pub async fn upsert_probe(&self, probe_metadata: &ProbeMetadata) -> Result<Probe, ServerError> {
        Ok(self.pg_probe_repository.create(&CreateProbe::new(probe_metadata.id, probe_metadata.mac, IpNetwork::from(probe_metadata.ip))).await?)
        
    }
}
