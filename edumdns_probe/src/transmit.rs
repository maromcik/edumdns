use crate::error::ProbeError;

use edumdns_core::app_packet::AppPacket;
use log::{error, warn};
use std::time::Duration;
use tokio::sync::mpsc::Receiver;
use tokio::time::sleep;
use edumdns_core::connection::TcpConnection;
use edumdns_core::{retry, utils};
pub struct Transmitter {
    server_addr_port: String,
    data_interface: String,
    rx: Receiver<AppPacket>,
    max_retries: usize,
}
impl Transmitter {
    pub fn new(
        server_addr_port: String,
        data_interface: String,
        rx: Receiver<AppPacket>,
        max_retries: usize,
    ) -> Self {
        Self {
            server_addr_port,
            data_interface,
            rx,
            max_retries,
        }
    }
    pub async fn transmit_packets(&mut self) -> Result<(), ProbeError> {
        let mut connection=  retry!(TcpConnection::new(self.server_addr_port.as_str(), self.data_interface.as_str()).await)?;
        while let Some(packet) = self.rx.recv().await {
            connection.send_with_reconnect(&self.server_addr_port, &packet, self.max_retries).await?;
        }
        Ok(())
    }
}
