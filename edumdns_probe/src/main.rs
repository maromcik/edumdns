use crate::connection::{
    ConnectionInfo, ConnectionLimits, ConnectionManager, ReceivePacketTargets,
};
use crate::error::ProbeError;
use crate::probe::ProbeCapture;
use clap::Parser;
use edumdns_core::app_packet::{
    NetworkAppPacket, NetworkCommandPacket, NetworkStatusPacket, ProbeResponse,
};
use edumdns_core::bincode_types::{MacAddr, Uuid};
use edumdns_core::connection::TcpConnectionMessage;
use edumdns_core::metadata::ProbeMetadata;
use log::{error, info, warn};
use pnet::ipnetwork::IpNetwork;
use std::fs::OpenOptions;
use std::io::{Read, Seek, SeekFrom, Write};
use std::net::IpAddr;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing_subscriber::EnvFilter;
use uuid::Timestamp;

pub mod capture;
pub mod connection;
pub mod error;
pub mod probe;

#[derive(Debug, Parser, Default)]
struct PreCli {
    /// Optional `.env` file path for loading environment variables.
    #[clap(short, long, value_name = "ENV_FILE")]
    env_file: Option<String>,
}

#[derive(Debug, Parser)]
#[clap(author, version, about, long_about = None)]
struct Cli {
    /// Optional `.env` file path for loading environment variables.
    #[clap(short, long, value_name = "ENV_FILE")]
    env_file: Option<String>,

    /// Optional UUID file path used for persistent probe identity.
    #[clap(short = 'u', long, value_name = "UUID", env = "EDUMDNS_PROBE_UUID")]
    uuid: Option<uuid::Uuid>,

    /// Optional UUID file path used for persistent probe identity.
    #[clap(
        short = 'f',
        long,
        value_name = "UUID_FILE",
        env = "EDUMDNS_PROBE_UUID_FILE"
    )]
    uuid_file: Option<String>,

    /// Local IP to bind to.
    #[clap(
        short = 'b',
        long = "bind_ip",
        value_name = "BIND_IP",
        env = "EDUMDNS_PROBE_BIND_IP"
    )]
    bind_ip: IpAddr,

    /// Local port to bind to.
    #[clap(
        long = "bind_port",
        value_name = "BIND_PORT",
        env = "EDUMDNS_PROBE_BIND_PORT",
        default_value = "0"
    )]
    bind_port: u16,

    /// Do not use TLS connection
    #[clap(
        short = 'n',
        long = "no-tls",
        value_name = "SECURE",
        env = "EDUMDNS_PROBE_NO_TLS",
        action = clap::ArgAction::SetTrue,
    )]
    no_tls: bool,

    /// Optional domain name for TLS connections.
    #[clap(
        short = 'h',
        long = "host",
        value_name = "SERVER_HOST",
        env = "EDUMDNS_PROBE_SERVER_HOST"
    )]
    server_host: String,

    /// Server port to connect to.
    #[clap(
        short = 'p',
        long = "server_port",
        value_name = "SERVER_PORT",
        env = "EDUMDNS_PROBE_SERVER_PORT",
        default_value = "5000"
    )]
    server_port: u16,

    /// Retry interval in seconds before attempting reconnection.
    #[clap(
        long = "retry_interval",
        value_name = "RETRY_INTERVAL",
        env = "EDUMDNS_PROBE_RETRY_INTERVAL",
        default_value = "1"
    )]
    retry_interval: u64,

    /// Global timeout in seconds for probe execution.
    #[clap(
        long = "global_timeout",
        value_name = "GLOBAL_TIMEOUT",
        env = "EDUMDNS_PROBE_GLOBAL_TIMOUT",
        default_value = "10"
    )]
    global_timeout: u64,

    /// Maximum number of retries before failing.
    #[clap(
        long = "max_retries",
        value_name = "MAX_RETRIES",
        env = "EDUMDNS_PROBE_MAX_RETRIES",
        default_value = "5"
    )]
    max_retries: usize,

    /// Optional pre-shared key for authentication.
    #[clap(
        short = 'k',
        long = "psk",
        value_name = "PRE_SHARED_KEY",
        env = "EDUMDNS_PROBE_PRE_SHARED_KEY"
    )]
    pre_shared_key: Option<String>,

    /// Optional log level.
    #[clap(
        short = 'l',
        long,
        value_name = "LOG_LEVEL",
        env = "EDUMDNS_PROBE_LOG_LEVEL",
        default_value = "info"
    )]
    log_level: String,
}

#[tokio::main]
async fn main() -> Result<(), ProbeError> {
    let pre = PreCli::try_parse().unwrap_or_default();

    if let Some(env_file) = pre.env_file {
        dotenvy::from_filename(env_file).expect("failed to load .env file");
    } else {
        dotenvy::dotenv().ok();
    }

    let cli = Cli::parse();

    let env = EnvFilter::new(cli.log_level);
    let timer = tracing_subscriber::fmt::time::LocalTime::rfc_3339();
    tracing_subscriber::fmt()
        .with_timer(timer)
        .with_target(true)
        .with_env_filter(env)
        .init();
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    let retry_interval = Duration::from_secs(cli.retry_interval);
    let global_timeout = Duration::from_secs(cli.global_timeout);
    let max_retries = cli.max_retries;

    let uuid = Uuid(cli.uuid.unwrap_or(generate_uuid(cli.uuid_file)?));

    info!("Starting probe with id: {}", uuid);
    info!("Binding to IP: {}:{}", cli.bind_ip, cli.bind_port);
    info!(
        "Connecting to server {}:{}",
        cli.server_host, cli.server_port
    );

    let probe_metadata = ProbeMetadata {
        id: uuid,
        ip: cli.bind_ip,
        mac: determine_mac(&cli.bind_ip)?,
    };

    let connection_info = ConnectionInfo {
        server_conn_socket_addr: format!("{}:{}", cli.server_host, cli.server_port),
        host: cli.server_host.clone(),
        bind_socket_addr: format!("{}:{}", cli.bind_ip, cli.bind_port),
        pre_shared_key: cli.pre_shared_key,
        no_tls: cli.no_tls,
    };

    let connection_limits = ConnectionLimits {
        max_retries,
        retry_interval,
        global_timeout,
    };

    let mut connection_manager =
        ConnectionManager::new(probe_metadata.clone(), connection_info, connection_limits).await?;

    let mut config = connection_manager.connection_init_probe().await?;
    let mut session_id = Some(Uuid(uuid::Uuid::nil()));
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
            .start_captures(
                &mut join_set,
                cli.server_host.as_ref(),
                cancellation_token.clone(),
            )
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
            uuid,
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
                            handle
                            .send_message_with_response(|tx|
                                TcpConnectionMessage::send_packet(
                                    tx,
                                    NetworkAppPacket::Status(
                                        NetworkStatusPacket::
                                        ProbeResponse(uuid, session_id, ProbeResponse::new_error(e.to_string()))))).await??;
                        }
                    }
                    else {
                        match res.1 {
                            Ok(_) => {}
                            Err(e) => {
                                error!("{e}");
                                command_transmitter
                    .send(NetworkAppPacket::Command(
                        NetworkCommandPacket::ReconnectThisProbe(None),
                    ))
                    .await?
                            }
                        }
                    }
            }
                Ok::<_, ProbeError>(())
            } => {
                result?;
            },
            Some(NetworkAppPacket::Command(NetworkCommandPacket::ReconnectThisProbe(ses_id))) = command_receiver.recv() => {
                session_id = ses_id;
                warn!("Reconnect signal received. Canceling tasks.");
                cancellation_token.cancel();
                info!("Reconnecting...");
                config = connection_manager.reconnect().await?;
                let _ = connection_manager.handle
                .send_message_with_response(|tx|
                    TcpConnectionMessage::send_packet(
                    tx,
                    NetworkAppPacket::Status(
                        NetworkStatusPacket::
                        ProbeResponse(uuid, ses_id, ProbeResponse::new_ok_with_value("Reconnected"))))).await;
            }
        }
    }
}

fn generate_uuid(uuid_file: Option<String>) -> Result<uuid::Uuid, ProbeError> {
    let mut file = OpenOptions::new()
        .write(true)
        .read(true)
        .create(true)
        .truncate(false)
        .open(uuid_file.unwrap_or("uuid".to_string()))?;
    let mut uuid = String::new();
    file.read_to_string(&mut uuid)?;
    match uuid::Uuid::parse_str(uuid.trim()) {
        Ok(uuid) => {
            info!("UUID found");
            Ok(uuid)
        }
        Err(e) => {
            warn!("UUID file is invalid: {}", e);
            info!("Generating new UUID");
            let ts = Timestamp::now(uuid::NoContext);
            let uuid = uuid::Uuid::new_v7(ts);
            file.set_len(0)?;
            file.seek(SeekFrom::Start(0))?;
            file.write_all(uuid.to_string().as_bytes())?;
            file.flush()?;

            Ok(uuid)
        }
    }
}

fn determine_mac(bind_ip: &IpAddr) -> Result<MacAddr, ProbeError> {
    let probe_ip = bind_ip.to_string().parse::<IpNetwork>()?;
    let interfaces = pnet::datalink::interfaces();
    let Some(interface) = interfaces
        .iter()
        .find(|i| i.is_up() && i.ips.iter().any(|ip| ip.ip() == probe_ip.ip()))
    else {
        return Err(ProbeError::ArgumentError(format!(
            "No interface found for IP: {} or interface is not up",
            bind_ip
        )));
    };

    Ok(MacAddr(interface.mac.unwrap_or_default()))
}
