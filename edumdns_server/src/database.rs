use edumdns_core::app_packet::NetworkAppPacket;
use edumdns_core::connection::TcpConnectionMessage;
use edumdns_core::error::CoreError;
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};

pub enum DatabaseActorMessage {
    FetchPacket {
        respond_to: oneshot::Sender<Result<Option<NetworkAppPacket>, CoreError>>,
        timeout: Option<Duration>,
    },
    CreatePacket {
        respond_to: oneshot::Sender<Result<(), CoreError>>,
        packet: NetworkAppPacket,
    },
}

#[derive(Clone)]
pub struct DatabaseActorHandle {
    pub sender: mpsc::Sender<TcpConnectionMessage>,
}

pub struct DatabaseActor {
    pub receiver: mpsc::Receiver<TcpConnectionMessage>,
}
