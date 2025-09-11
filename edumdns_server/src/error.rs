use edumdns_core::error::{CoreError, CoreErrorKind};
use edumdns_db::error::DbError;
use std::fmt::{Debug, Display, Formatter};
use std::net::AddrParseError;
use thiserror::Error;

#[derive(Error, Debug, Clone)]
pub enum ServerErrorKind {
    #[error("{0}")]
    CoreError(CoreError),
    #[error("{0}")]
    DbError(DbError),
    #[error("Invalid arguments")]
    ArgumentError,
    #[error("I/O error from Tokio")]
    IoError,
    #[error("Invalid connection initiation")]
    InvalidConnectionInitiation,
    #[error("probe not adopted error")]
    ProbeNotAdopted,
    #[error("probe not found")]
    ProbeNotFound,
    #[error("parse error")]
    ParseError,
    #[error("ebpf map error")]
    EbpfMapError,
}

#[derive(Error, Debug, Clone)]
pub struct ServerError {
    pub error_kind: ServerErrorKind,
    pub message: String,
}

impl Display for ServerError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match &self.error_kind {
            ServerErrorKind::CoreError(e) => write!(f, "ServerError -> {}", e),
            ServerErrorKind::DbError(e) => write!(f, "ServerError -> {}", e),
            _ => write!(f, "ServerError: {}: {}", self.error_kind, self.message),
        }
    }
}

impl ServerError {
    pub fn new(error_kind: ServerErrorKind, message: &str) -> Self {
        Self {
            error_kind,
            message: message.to_owned(),
        }
    }
}

impl From<CoreError> for ServerError {
    fn from(value: CoreError) -> Self {
        Self::new(ServerErrorKind::CoreError(value), "")
    }
}

impl From<std::io::Error> for ServerError {
    fn from(value: std::io::Error) -> Self {
        Self::new(ServerErrorKind::IoError, value.to_string().as_str())
    }
}

impl From<DbError> for ServerError {
    fn from(value: DbError) -> Self {
        Self::new(ServerErrorKind::DbError(value), "")
    }
}

impl From<std::num::ParseIntError> for ServerError {
    fn from(value: std::num::ParseIntError) -> Self {
        Self::new(ServerErrorKind::ParseError, value.to_string().as_str())
    }
}

impl From<aya::maps::MapError> for ServerError {
    fn from(value: aya::maps::MapError) -> Self {
        Self::new(ServerErrorKind::EbpfMapError, value.to_string().as_str())
    }
}

impl From<AddrParseError> for ServerError {
    fn from(value: AddrParseError) -> Self {
        ServerError::new(ServerErrorKind::ParseError, &value.to_string())
    }
}
