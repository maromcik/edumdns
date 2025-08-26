use crate::connection::{ConnectionManager, ReceivePacketTargets};
use crate::error::ProbeError;
use crate::probe::ProbeCapture;
use edumdns_core::app_packet::{AppPacket, CommandPacket, StatusPacket};
use edumdns_core::bincode_types::{MacAddr, Uuid};
use edumdns_core::connection::TcpConnectionMessage;
use edumdns_core::metadata::ProbeMetadata;
use log::{error, info, warn};
use std::net::IpAddr;
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};
use tokio::time::sleep;
use tokio_util::sync::{CancellationToken, WaitForCancellationFuture};
use edumdns_core::utils::Cancellable;

pub mod capture;
pub mod connection;
pub mod error;
pub mod probe;


#[derive(Clone)]
pub struct CancelToken {
    task_token: CancellationToken,
    main_token: CancellationToken,
}

impl Cancellable for CancelToken {
    fn cancel(&mut self) {
        self.task_token.cancel();
        self.main_token.cancel();
    }

    fn is_cancelled(&self) -> bool {
        self.task_token.is_cancelled() || self.main_token.is_cancelled()
    }
}

impl CancelToken {
    pub fn new(main_token: CancellationToken) -> Self {
        let task_token = CancellationToken::new();
        Self {
            task_token,
            main_token,
        }
    }
}

pub async fn probe_init(main_cancellation_token: CancellationToken) -> Result<(), ProbeError> {
    let uuid = Uuid(uuid::Uuid::from_u128(32));
    let bind_ip = "127.0.0.1:0";
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

    let mut config = connection_manager.connection_init_probe().await?;



    loop {
        let handle = connection_manager.handle.clone();
        let handle_local = connection_manager.handle.clone();
        let mut cancellation_token = CancelToken::new(main_cancellation_token.clone());
        let mut join_set = tokio::task::JoinSet::new();

        let (send_transmitter, send_receiver) = mpsc::channel(1000);
        let (command_transmitter, mut command_receiver) = mpsc::channel(1000);
        let (pinger_receive_transmitter, pinger_receive_receiver) = mpsc::channel(1000);

        let probe_capture =
            ProbeCapture::new(send_transmitter, probe_metadata.clone(), config.clone());

        let targets = ReceivePacketTargets {
            pinger: pinger_receive_transmitter,
        };

        let capture_handles = probe_capture
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

        // tokio::spawn(async move {
        //     sleep(Duration::from_secs(8)).await;
        //     command_transmitter.send(AppPacket::Command(CommandPacket::ReconnectProbe)).await.unwrap();
        // });

        tokio::select! {

            result = async {
                while let Some(task) = join_set.join_next_with_id().await {
                    let res = task?;
                    if capture_handles.contains(&res.0) {
                        if let Err(e) = res.1 {
                            error!("{e}");
                            handle.send_message_with_response(|tx| TcpConnectionMessage::send_packet(tx, AppPacket::Status(StatusPacket::ProbeInvalidConfig(e.to_string())))).await??;
                        }
                    }
                    else {
                        res.1?;
                    }
            }
                Ok::<_, ProbeError>(())
            } => {
                result?;
            },
            Some(AppPacket::Command(CommandPacket::ReconnectThisProbe)) = command_receiver.recv() => {
                warn!("Reconnect signal received. Canceling tasks.");
                cancellation_token.task_token.cancel();
                info!("Reconnecting...");
                config = connection_manager.reconnect().await?;
            },
        }
    }
}
