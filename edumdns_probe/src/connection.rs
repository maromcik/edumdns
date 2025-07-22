use crate::error::{ProbeError, ProbeErrorKind};
use edumdns_core::app_packet::CommandPacket::ProbeHello;
use edumdns_core::app_packet::{AppPacket, CommandPacket, ProbeConfigPacket};
use edumdns_core::bincode_types::Uuid;
use edumdns_core::connection::TcpConnection;
use edumdns_core::retry;
use log::{debug, error, warn};
use tokio::sync::mpsc::Receiver;

pub struct ConnectionManager {
    server_connection_string: String,
    data_interface_name: String,
    pub connection: TcpConnection,
    rx: Receiver<AppPacket>,
    max_retries: usize,
}

impl ConnectionManager {
    pub async fn new(server_connection_string: &str, data_interface_name: &str, rx: Receiver<AppPacket>, max_retries: usize,
    ) -> Result<Self, ProbeError> {
        Ok(Self {
            server_connection_string: server_connection_string.to_owned(),
            data_interface_name: data_interface_name.to_owned(),
            connection: retry!(TcpConnection::new(server_connection_string, data_interface_name).await, max_retries, 1000)?,
            rx,
            max_retries,
        })
    }
    pub async fn connection_init_probe(
        &mut self,
        uuid: Uuid,
    ) -> Result<ProbeConfigPacket, ProbeError> {
        let error = Err(ProbeError::new(
            ProbeErrorKind::InvalidConnectionInitiation,
            "invalid connection initiation",
        ));

        let hello_packet = AppPacket::Command(ProbeHello(uuid));
        self.connection.send_packet(&hello_packet).await?;

        let packet = self.receive_init_packet().await?;

        let AppPacket::Command(CommandPacket::ProbeAdopted) = packet else {
            return Err(ProbeError::new(
                ProbeErrorKind::ProbeNotAdopted,
                "probe is not adopted by the server",
            ));
        };

        self.connection
            .send_packet(&AppPacket::Command(CommandPacket::ProbeRequestConfig(uuid)))
            .await?;

        let packet = self.receive_init_packet().await?;

        let AppPacket::Command(CommandPacket::ProbeResponseConfig(config)) = packet else {
            return error;
        };

        Ok(config)
    }

    pub async fn receive_init_packet(&mut self) -> Result<AppPacket, ProbeError> {
        let packet: Option<(AppPacket, usize)> = self.connection.receive_next().await?;
        let Some((app_packet, _)) = packet else {
            return Err(ProbeError::new(
                ProbeErrorKind::InvalidConnectionInitiation,
                "invalid connection initiation",
            ));
        };
        Ok(app_packet)
    }

    pub async fn transmit_packets(&mut self) -> Result<(), ProbeError> {
        while let Some(packet) = self.rx.recv().await {
            self.connection.send_with_reconnect(&self.server_connection_string, &packet, self.max_retries).await?;
        }
        Ok(())
    }
}
