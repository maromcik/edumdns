use edumdns_core::error::CoreError;
use std::fmt::Debug;
use thiserror::Error;

#[derive(Error, Clone)]
pub enum ProbeError {
    #[error("Core Error -> {0}")]
    CoreError(#[from] CoreError),
    #[error("Invalid arguments: {0}")]
    ArgumentError(String),
    #[error("I/O error: {0}")]
    IoError(String),
    #[error("Encode/Decode error: {0}")]
    EncodeDecodeError(String),
    #[error("Tokio task error: {0}")]
    TaskError(String),
    #[error("Connection initiation error: {0}")]
    InvalidConnectionInitiation(String),
    #[error("Tokio oneshot channel error: {0}")]
    TokioOneshotChannelError(String),
    #[error("Tokio mpsc channel error: {0}")]
    TokioMpscChannelError(String),
    #[error("Environment variable error: {0}")]
    EnvError(String),
    #[error("Parse error: {0}")]
    ParseError(String),
    #[error("Capture error: {0}")]
    CaptureError(String),
    #[error("{0}")]
    CaptureFilterError(String),
}

impl Debug for ProbeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{0}", self)
    }
}

impl From<pcap::Error> for ProbeError {
    fn from(value: pcap::Error) -> Self {
        ProbeError::CaptureError(value.to_string())
    }
}

impl From<std::io::Error> for ProbeError {
    fn from(value: std::io::Error) -> Self {
        Self::IoError(value.to_string())
    }
}

impl From<bincode::error::EncodeError> for ProbeError {
    fn from(value: bincode::error::EncodeError) -> Self {
        Self::EncodeDecodeError(value.to_string())
    }
}

impl From<tokio::task::JoinError> for ProbeError {
    fn from(value: tokio::task::JoinError) -> Self {
        Self::TaskError(value.to_string())
    }
}

impl From<std::net::AddrParseError> for ProbeError {
    fn from(value: std::net::AddrParseError) -> Self {
        Self::ArgumentError(value.to_string())
    }
}

impl From<tokio::sync::oneshot::error::RecvError> for ProbeError {
    fn from(value: tokio::sync::oneshot::error::RecvError) -> Self {
        Self::TokioOneshotChannelError(value.to_string())
    }
}

impl<T> From<tokio::sync::mpsc::error::SendError<T>> for ProbeError {
    fn from(value: tokio::sync::mpsc::error::SendError<T>) -> Self {
        Self::TokioMpscChannelError(value.to_string())
    }
}

impl From<uuid::Error> for ProbeError {
    fn from(value: uuid::Error) -> Self {
        Self::ParseError(value.to_string())
    }
}

impl From<std::num::ParseIntError> for ProbeError {
    fn from(value: std::num::ParseIntError) -> Self {
        Self::ParseError(value.to_string())
    }
}

impl From<pnet::ipnetwork::IpNetworkError> for ProbeError {
    fn from(value: pnet::ipnetwork::IpNetworkError) -> Self {
        Self::ParseError(value.to_string())
    }
}
