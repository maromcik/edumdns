use std::time::Duration;
use crate::error::{ServerError, ServerErrorKind};
use edumdns_core::app_packet::{AppPacket, CommandPacket, ProbeConfigElement, ProbeConfigPacket};
use edumdns_core::connection::TcpConnection;
use tokio::net::TcpStream;
use tokio::sync::mpsc::Sender;
use tokio::time::sleep;

pub struct ConnectionManager {
    connection: TcpConnection,
}

impl ConnectionManager {
    pub async fn new(stream: TcpStream) -> Result<Self, ServerError> {
        Ok(Self {
            connection: TcpConnection::stream_to_framed(stream).await?,
        })
    }

    pub async fn connection_init_server(&mut self) -> Result<(), ServerError> {
        let error = Err(ServerError::new(
            ServerErrorKind::InvalidConnectionInitiation,
            "invalid connection initiation",
        ));
        let packet = self.receive_init_packet().await?;

        let AppPacket::Command(CommandPacket::ProbeHello(hello_metadata)) = packet else {
            return error;
        };

        // TODO check uuid in DB
        // TODO create it in the db
        let adopted = true;
        if adopted {
            self.connection
                .send_packet(&AppPacket::Command(CommandPacket::ProbeAdopted))
                .await?;
        } else {
            self.connection
                .send_packet(&AppPacket::Command(CommandPacket::ProbeUnknown))
                .await?;
            return Err(ServerError::new(ServerErrorKind::ProbeNotAdopted, "adopt it in the web interface first"))
        }

        let packet = self.receive_init_packet().await?;

        let AppPacket::Command(CommandPacket::ProbeRequestConfig(config_metadata)) = packet else {
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
            .send_packet(&AppPacket::Command(CommandPacket::ProbeResponseConfig(
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
}
