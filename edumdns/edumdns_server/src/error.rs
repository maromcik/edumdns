use edumdns_core::error::CoreError;
use edumdns_db::error::DbError;
use std::fmt::Debug;
use std::net::AddrParseError;
use std::str::ParseBoolError;
use thiserror::Error;

#[derive(Error, Clone)]
pub enum ServerError {
    #[error("CoreError -> {0}")]
    CoreError(CoreError),
    #[error("DbError -> {0}")]
    DbError(DbError),
    #[error("tokio oneshot channel error: {0}")]
    TokioOneshotChannelError(String),
    #[error("tokio mpsc channel error: {0}")]
    TokioMpscChannelError(String),
    #[error("I/O error: {0}")]
    IoError(String),
    #[error("Invalid connection initiation: {0}")]
    InvalidConnectionInitiation(String),
    #[error("Probe not adopted; adopt it in the web interface first")]
    ProbeNotAdopted,
    #[error("Probe not found; possibly not connected")]
    ProbeNotFound,
    #[error("Parse error: {0}")]
    ParseError(String),
    #[error("eBPF map error: {0}")]
    EbpfMapError(String),
    #[error("An error occurred while processing your request: {0}")]
    DiscoveryRequestProcessingError(String),
}

impl Debug for ServerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{0}", self)
    }
}

impl From<CoreError> for ServerError {
    fn from(value: CoreError) -> Self {
        Self::CoreError(value)
    }
}

impl From<DbError> for ServerError {
    fn from(value: DbError) -> Self {
        Self::DbError(value)
    }
}

impl From<std::io::Error> for ServerError {
    fn from(value: std::io::Error) -> Self {
        Self::IoError(value.to_string())
    }
}

impl From<std::num::ParseIntError> for ServerError {
    fn from(value: std::num::ParseIntError) -> Self {
        Self::ParseError(value.to_string())
    }
}

impl From<tokio::sync::oneshot::error::RecvError> for ServerError {
    fn from(value: tokio::sync::oneshot::error::RecvError) -> Self {
        ServerError::TokioOneshotChannelError(value.to_string())
    }
}

impl<T> From<tokio::sync::mpsc::error::SendError<T>> for ServerError {
    fn from(value: tokio::sync::mpsc::error::SendError<T>) -> Self {
        ServerError::TokioMpscChannelError(value.to_string())
    }
}

impl From<aya::maps::MapError> for ServerError {
    fn from(value: aya::maps::MapError) -> Self {
        Self::EbpfMapError(value.to_string())
    }
}

impl From<AddrParseError> for ServerError {
    fn from(value: AddrParseError) -> Self {
        ServerError::ParseError(value.to_string())
    }
}

impl From<ParseBoolError> for ServerError {
    fn from(value: ParseBoolError) -> Self {
        ServerError::ParseError(value.to_string())
    }
}
