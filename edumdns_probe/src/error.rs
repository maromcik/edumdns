use edumdns_core::error::CoreError;
use std::fmt::{Debug, Display, Formatter};
use thiserror::Error;

#[derive(Error, Debug, Clone)]
pub enum ProbeErrorKind {
    #[error("{0}")]
    CoreError(#[from] CoreError),
    #[error("Invalid arguments")]
    ArgumentError,
    #[error("I/O error from Tokio")]
    IoError,
    #[error("Encode/Decode error")]
    EncodeDecodeError,
    #[error("Tokio connection error")]
    ConnectionError,
    #[error("interface error")]
    InterfaceError,
    #[error("tokio task error")]
    TaskError,
    #[error("probe not adopted error")]
    ProbeNotAdopted,
    #[error("probe connection initiation error")]
    InvalidConnectionInitiation,
}

#[derive(Error, Debug, Clone)]
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
        Self::new(
            ProbeErrorKind::CoreError(value),
            ""
        )
    }
}

impl From<std::io::Error> for ProbeError {
    fn from(value: std::io::Error) -> Self {
        Self::new(
            ProbeErrorKind::IoError,
            value.to_string().as_str(),
        )
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
        Self::new(
            ProbeErrorKind::TaskError,
            value.to_string().as_str(),
        )   
    }
}

impl From<std::net::AddrParseError> for ProbeError {
    fn from(value: std::net::AddrParseError) -> Self {
        Self::new(
            ProbeErrorKind::ArgumentError,
            value.to_string().as_str(),
        )   
    }
}