use edumdns_core::error::CoreError;
use edumdns_db::error::DbError;
use std::fmt::{Debug, Display, Formatter};
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
    #[error("Tokio oneshot channel error")]
    TokioOneshotChannelError,
    #[error("Tokio mpsc channel error")]
    TokioMpscChannelError,
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

impl From<tokio::sync::oneshot::error::RecvError> for ServerError {
    fn from(value: tokio::sync::oneshot::error::RecvError) -> Self {
        Self::new(ServerErrorKind::TokioOneshotChannelError, value.to_string().as_str())
    }
}

impl<T> From<tokio::sync::mpsc::error::SendError<T>> for ServerError {
    fn from(value: tokio::sync::mpsc::error::SendError<T>) -> Self {
        Self::new(ServerErrorKind::TokioMpscChannelError, value.to_string().as_str())
    }
}