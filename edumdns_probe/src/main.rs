use crate::connection::{ConnectionManager, ReceivePacketTargets};
use crate::error::{ProbeError, ProbeErrorKind};
use crate::probe::ProbeCapture;
use edumdns_core::app_packet::{AppPacket, CommandPacket, StatusPacket};
use edumdns_core::bincode_types::{MacAddr, Uuid};
use edumdns_core::connection::TcpConnectionMessage;
use edumdns_core::metadata::ProbeMetadata;
use log::{error, info, warn};
use std::env;
use std::fs::OpenOptions;
use std::io::{Read, Seek, SeekFrom, Write};
use std::net::IpAddr;
use std::time::Duration;
use pnet::ipnetwork::IpNetwork;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing_subscriber::EnvFilter;
use uuid::Timestamp;

pub mod capture;
pub mod connection;
pub mod error;
pub mod probe;

#[tokio::main]
async fn main() -> Result<(), ProbeError> {
    dotenvy::dotenv().ok();
    let env = EnvFilter::try_from_env("EDUMDNS_LOG_LEVEL").unwrap_or(EnvFilter::new("info"));
    let timer = tracing_subscriber::fmt::time::LocalTime::rfc_3339();
    tracing_subscriber::fmt()
        .with_timer(timer)
        .with_target(true)
        .with_env_filter(env)
        .init();

    let bind_ip = env::var("EDUMDNS_PROBE_BIND_IP")?;
    let bind_port = env::var("EDUMDNS_PROBE_BIND_PORT").unwrap_or("0".to_string());
    let server_host = env::var("EDUMDNS_SERVER_HOST")?;
    let server_port = env::var("EDUMDNS_SERVER_PORT")?;
    let retry_interval = Duration::from_secs(
        env::var("EDUMDNS_PROBE_RETRY_INTERVAL")
            .unwrap_or("1".to_string())
            .parse::<u64>()?,
    );
    let global_timeout = Duration::from_secs(
        env::var("EDUMDNS_PROBE_GLOBAL_TIMOUT")
            .unwrap_or("10".to_string())
            .parse::<u64>()?,
    );
    let max_retries = env::var("EDUMDNS_PROBE_MAX_RETRIES")
        .unwrap_or("5".to_string())
        .parse::<usize>()?;

    let uuid = generate_uuid()?;

    info!("Starting probe with id: {}", uuid);
    info!("Binding to IP: {}:{}", bind_ip, bind_port);
    info!("Connecting to server: {}:{}", server_host, server_port);

    let probe_metadata = ProbeMetadata {
        id: uuid,
        ip: bind_ip.parse::<IpAddr>()?,
        mac: determine_mac(&bind_ip)?,
    };

    let mut connection_manager = ConnectionManager::new(
        probe_metadata.clone(),
        format!("{}:{}", server_host, server_port).as_str(),
        format!("{}:{}", bind_ip, bind_port).as_str(),
        max_retries,
        retry_interval,
        global_timeout,
    )
    .await?;

    let mut config = connection_manager.connection_init_probe().await?;

    loop {
        let handle = connection_manager.handle.clone();
        let handle_local = connection_manager.handle.clone();
        let cancellation_token = CancellationToken::new();
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
                cancellation_token.cancel();
                info!("Reconnecting...");
                config = connection_manager.reconnect().await?;
            },
        }
    }
}

fn generate_uuid() -> Result<Uuid, ProbeError> {
    let mut file = OpenOptions::new()
        .write(true)
        .read(true)
        .create(true)
        .truncate(false)
        .open("uuid")?;
    let mut uuid = String::new();
    file.read_to_string(&mut uuid)?;
    match uuid::Uuid::parse_str(uuid.trim()) {
        Ok(uuid) => {
            info!("UUID found");
            Ok(Uuid(uuid))
        }
        Err(e) => {
            warn!("UUID file is invalid: {}", e);
            info!("Generating new UUID");
            let ts = Timestamp::now(uuid::NoContext);
            let uuid = Uuid(uuid::Uuid::new_v7(ts));
            file.set_len(0)?;
            file.seek(SeekFrom::Start(0))?;
            file.write_all(uuid.to_string().as_bytes())?;
            file.flush()?;

            Ok(uuid)
        }
    }
}

fn determine_mac(bind_ip: &str) -> Result<MacAddr, ProbeError> {
    let probe_ip = bind_ip.parse::<IpNetwork>()?;
    let interfaces = pnet::datalink::interfaces();
    let Some(interface) = interfaces
        .iter()
        .find(|i| i.is_up() && i.ips.iter().any(|ip| ip.ip() == probe_ip.ip())) else {
        return Err(ProbeError::new(ProbeErrorKind::ArgumentError, format!("No interface found for IP: {} or interface is not up", bind_ip).as_str()))
    };
    let Some(mac) = interface.mac else {
        return Err(ProbeError::new(ProbeErrorKind::ArgumentError, format!("No MAC address found for interface with IP: {}", bind_ip).as_str()))
    };

    Ok(MacAddr(mac))
}