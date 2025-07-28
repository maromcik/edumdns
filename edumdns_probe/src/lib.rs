use crate::connection::{ConnectionManager, ReceivePacketTargets};
use crate::error::ProbeError;
use crate::probe::ProbeCapture;
use edumdns_core::app_packet::{AppPacket, CommandPacket};
use edumdns_core::bincode_types::{MacAddr, Uuid};
use edumdns_core::metadata::ProbeMetadata;
use log::warn;
use std::net::IpAddr;
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;

pub mod capture;
pub mod connection;
pub mod error;
pub mod probe;

pub async fn probe_init() -> Result<(), ProbeError> {
    let uuid = Uuid(uuid::Uuid::from_u128(32));
    let bind_ip = "192.168.80.41:0";
    let server_addr_port = "127.0.0.1:5000";

    let probe_metadata = ProbeMetadata {
        id: uuid,
        ip: "127.0.0.1".parse::<IpAddr>()?,
        mac: MacAddr::from_octets([1, 0, 0, 0, 0, 0]),
    };

    let retry_interval = Duration::from_secs(1);
    let global_timeout = Duration::from_secs(10);
    let max_retries = 5;

    let mut connection_manager = ConnectionManager::new(
        probe_metadata.clone(),
        server_addr_port,
        bind_ip,
        max_retries,
        retry_interval,
        global_timeout,
    )
    .await?;

    let config = connection_manager.connection_init_probe().await?;

    loop {
        let handle_local = connection_manager.handle.clone();
        let cancellation_token = CancellationToken::new();
        let mut join_set = tokio::task::JoinSet::new();

        let (send_transmitter, send_receiver) = mpsc::channel(1000);
        let (command_transmitter, mut command_receiver) = mpsc::channel(1000);
        let (pinger_receive_transmitter, pinger_receive_receiver) = mpsc::channel(1000);

        let probe_capture = ProbeCapture::new(
            send_transmitter.clone(),
            probe_metadata.clone(),
            config.clone(),
        );

        let targets = ReceivePacketTargets {
            pinger: pinger_receive_transmitter,
        };

        probe_capture
            .start_captures(&mut join_set, cancellation_token.clone())
            .await?;
        ConnectionManager::transmit_packets(
            &mut join_set,
            connection_manager.handle.clone(),
            send_receiver,
            command_transmitter.clone(),
            cancellation_token.clone(),
            max_retries,
            retry_interval,
        )
        .await?;
        ConnectionManager::receive_packets(
            &mut join_set,
            connection_manager.handle.clone(),
            targets,
            command_transmitter.clone(),
            cancellation_token.clone(),
        )
        .await?;
        ConnectionManager::pinger(
            &mut join_set,
            handle_local,
            pinger_receive_receiver,
            command_transmitter.clone(),
            retry_interval,
            cancellation_token.clone(),
        )
        .await?;

        tokio::select! {
            result = join_set.join_all() => {
                result.into_iter().map(|res| {res?;
                        Ok::<(), ProbeError>(())
                    }).collect::<Result<Vec<_>, ProbeError>>()?;
            },
            Some(AppPacket::Command(CommandPacket::ReconnectProbe)) = command_receiver.recv() => {
                warn!("Reconnect signal received. Canceling tasks and reconnecting...");
                cancellation_token.cancel();
                connection_manager.reconnect().await?;
            },
        }
    }
    Ok(())
}
