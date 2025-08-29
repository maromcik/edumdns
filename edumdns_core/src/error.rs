use crate::app_packet::ProbeConfigElement;
use pnet::datalink::ParseMacAddrErr;
use std::error::Error;
use std::fmt::{Display, Formatter};
use std::net::AddrParseError;
use std::num::ParseIntError;
use std::sync::mpsc;
use thiserror::Error;

#[derive(Debug, Clone, Error)]
pub enum CoreErrorKind {
    #[error("Capture error")]
    CaptureError,
    #[error("Specific capture error")]
    CaptureErrorSpecific(ProbeConfigElement),
    #[error("Network interface error")]
    NetworkInterfaceError,
    #[error("Network channel error")]
    NetworkChannelError,
    #[error("Rust channel error")]
    RustChannelError,
    #[error("Address parse error")]
    ParseAddrError,
    #[error("Packet could not be constructed")]
    PacketConstructionError,
    #[error("Packet could not be rewritten")]
    PacketRewriteError,
    #[error("Encode/Decode error")]
    EncodeDecodeError,
    #[error("Tokio connection error")]
    ConnectionError,
    #[error("I/O error from Tokio")]
    IoError,
    #[error("interface error")]
    InterfaceError,
    #[error("tokio task error")]
    TaskError,
    #[error("Ping Error")]
    PingError,
    #[error("Timeout Error")]
    TimeoutError,
    #[error("Tokio oneshot channel error")]
    TokioOneshotChannelError,
    #[error("Tokio mpsc channel error")]
    TokioMpscChannelError,
    #[error("dns packet manipulation error")]
    DnsPacketManipulationError,
}

#[derive(Debug, Clone)]
pub struct CoreError {
    pub error_kind: CoreErrorKind,
    pub message: String,
}

impl Display for CoreError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "Core Error: {}: {}", self.error_kind, self.message)
    }
}

impl Error for CoreError {}

impl CoreError {
    pub fn new(error_kind: CoreErrorKind, message: &str) -> Self {
        Self {
            error_kind,
            message: message.to_owned(),
        }
    }
}

impl From<pcap::Error> for CoreError {
    fn from(value: pcap::Error) -> Self {
        CoreError::new(CoreErrorKind::CaptureError, &value.to_string())
    }
}

impl<T> From<mpsc::SendError<T>> for CoreError {
    fn from(value: mpsc::SendError<T>) -> Self {
        CoreError::new(CoreErrorKind::RustChannelError, &value.to_string())
    }
}

impl From<mpsc::RecvError> for CoreError {
    fn from(value: mpsc::RecvError) -> Self {
        CoreError::new(CoreErrorKind::RustChannelError, &value.to_string())
    }
}

impl From<ParseMacAddrErr> for CoreError {
    fn from(value: ParseMacAddrErr) -> Self {
        CoreError::new(CoreErrorKind::ParseAddrError, &value.to_string())
    }
}

impl From<AddrParseError> for CoreError {
    fn from(value: AddrParseError) -> Self {
        CoreError::new(CoreErrorKind::ParseAddrError, &value.to_string())
    }
}

impl From<ParseIntError> for CoreError {
    fn from(value: ParseIntError) -> Self {
        CoreError::new(CoreErrorKind::ParseAddrError, &value.to_string())
    }
}

impl From<bincode::error::DecodeError> for CoreError {
    fn from(value: bincode::error::DecodeError) -> Self {
        CoreError::new(CoreErrorKind::EncodeDecodeError, &value.to_string())
    }
}

impl From<std::io::Error> for CoreError {
    fn from(value: std::io::Error) -> Self {
        Self::new(CoreErrorKind::IoError, value.to_string().as_str())
    }
}

impl From<bincode::error::EncodeError> for CoreError {
    fn from(value: bincode::error::EncodeError) -> Self {
        Self::new(CoreErrorKind::EncodeDecodeError, value.to_string().as_str())
    }
}

impl From<tokio::task::JoinError> for CoreError {
    fn from(value: tokio::task::JoinError) -> Self {
        Self::new(CoreErrorKind::TaskError, value.to_string().as_str())
    }
}

impl From<tokio::time::error::Elapsed> for CoreError {
    fn from(value: tokio::time::error::Elapsed) -> Self {
        Self::new(CoreErrorKind::TimeoutError, value.to_string().as_str())
    }
}

impl From<tokio::sync::oneshot::error::RecvError> for CoreError {
    fn from(value: tokio::sync::oneshot::error::RecvError) -> Self {
        Self::new(
            CoreErrorKind::TokioOneshotChannelError,
            value.to_string().as_str(),
        )
    }
}

impl<T> From<tokio::sync::mpsc::error::SendError<T>> for CoreError {
    fn from(value: tokio::sync::mpsc::error::SendError<T>) -> Self {
        Self::new(
            CoreErrorKind::TokioMpscChannelError,
            value.to_string().as_str(),
        )
    }
}

impl From<ipnetwork::IpNetworkError> for CoreError {
    fn from(value: ipnetwork::IpNetworkError) -> Self {
        Self::new(CoreErrorKind::ParseAddrError, value.to_string().as_str())
    }
}

impl From<hickory_proto::ProtoError> for CoreError {
    fn from(value: hickory_proto::ProtoError) -> Self {
        Self::new(CoreErrorKind::DnsPacketManipulationError, value.to_string().as_str())
    }
}