use edumdns_core::error::CoreError;
use std::fmt::{Debug, Display, Formatter};
use thiserror::Error;

#[derive(Error, Debug, Clone)]
pub enum ProbeErrorKind {
    #[error("{0}")]
    CoreError(#[from] CoreError),
    #[error("Invalid arguments")]
    ArgumentError,
    #[error("I/O error")]
    IoError,
    #[error("Encode/Decode error")]
    EncodeDecodeError,
    #[error("Tokio connection error")]
    ConnectionError,
    #[error("interface error")]
    InterfaceError,
    #[error("tokio task error")]
    TaskError,
    #[error("probe connection initiation error")]
    InvalidConnectionInitiation,
    #[error("Tokio oneshot channel error")]
    TokioOneshotChannelError,
    #[error("Tokio mpsc channel error")]
    TokioMpscChannelError,
    #[error("environment variable error")]
    EnvError,
    #[error("parse error")]
    ParseError,
}

#[derive(Error, Clone)]
pub struct ProbeError {
    pub error_kind: ProbeErrorKind,
    pub message: String,
}

impl Display for ProbeError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match &self.error_kind {
            ProbeErrorKind::CoreError(e) => write!(f, "ProbeError -> {}", e),
            _ => write!(f, "ProbeError: {}: {}", self.error_kind, self.message),
        }
    }
}

impl Debug for ProbeError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match &self.error_kind {
            ProbeErrorKind::CoreError(e) => write!(f, "ProbeError -> {}", e),
            _ => write!(f, "ProbeError: {}: {}", self.error_kind, self.message),
        }
    }
}

impl ProbeError {
    pub fn new(error_kind: ProbeErrorKind, message: &str) -> Self {
        Self {
            error_kind,
            message: message.to_owned(),
        }
    }
}

impl From<CoreError> for ProbeError {
    fn from(value: CoreError) -> Self {
        Self::new(ProbeErrorKind::CoreError(value), "")
    }
}

impl From<std::io::Error> for ProbeError {
    fn from(value: std::io::Error) -> Self {
        Self::new(ProbeErrorKind::IoError, value.to_string().as_str())
    }
}

impl From<bincode::error::EncodeError> for ProbeError {
    fn from(value: bincode::error::EncodeError) -> Self {
        Self::new(
            ProbeErrorKind::EncodeDecodeError,
            value.to_string().as_str(),
        )
    }
}

impl From<tokio::task::JoinError> for ProbeError {
    fn from(value: tokio::task::JoinError) -> Self {
        Self::new(ProbeErrorKind::TaskError, value.to_string().as_str())
    }
}

impl From<std::net::AddrParseError> for ProbeError {
    fn from(value: std::net::AddrParseError) -> Self {
        Self::new(ProbeErrorKind::ArgumentError, value.to_string().as_str())
    }
}

impl From<tokio::sync::oneshot::error::RecvError> for ProbeError {
    fn from(value: tokio::sync::oneshot::error::RecvError) -> Self {
        Self::new(
            ProbeErrorKind::TokioOneshotChannelError,
            value.to_string().as_str(),
        )
    }
}

impl<T> From<tokio::sync::mpsc::error::SendError<T>> for ProbeError {
    fn from(value: tokio::sync::mpsc::error::SendError<T>) -> Self {
        Self::new(
            ProbeErrorKind::TokioMpscChannelError,
            value.to_string().as_str(),
        )
    }
}

impl From<std::env::VarError> for ProbeError {
    fn from(value: std::env::VarError) -> Self {
        Self::new(ProbeErrorKind::EnvError, value.to_string().as_str())
    }
}

impl From<uuid::Error> for ProbeError {
    fn from(value: uuid::Error) -> Self {
        Self::new(ProbeErrorKind::ParseError, value.to_string().as_str())
    }
}

impl From<std::num::ParseIntError> for ProbeError {
    fn from(value: std::num::ParseIntError) -> Self {
        Self::new(ProbeErrorKind::ParseError, value.to_string().as_str())
    }
}

impl From<pnet::ipnetwork::IpNetworkError> for ProbeError {
    fn from(value: pnet::ipnetwork::IpNetworkError) -> Self {
        Self::new(ProbeErrorKind::ParseError, value.to_string().as_str())
    }
}
