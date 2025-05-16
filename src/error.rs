use edumdns_probe::error::ProbeError;
use edumdns_server::error::ServerError;
use std::fmt::{Debug, Display, Formatter};
use thiserror::Error;
use edumdns_db::error::DbError;

#[derive(Error, Debug, Clone)]
pub enum AppErrorKind {
    #[error("{0}")]
    DbError(#[from] DbError),
    #[error("{0}")]
    ProbeError(#[from] ProbeError),
    #[error("{0}")]
    ServerError(#[from] ServerError),
    #[error("Tokio error")]
    TokioError,
}

#[derive(Error, Clone)]
pub struct AppError {
    pub error_kind: AppErrorKind,
    pub message: String,
}

impl Debug for AppError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match &self.error_kind {
            AppErrorKind::DbError(e) => write!(f, "AppError -> {}", e),
            AppErrorKind::ProbeError(e) => write!(f, "AppError -> {}", e),
            AppErrorKind::ServerError(e) => write!(f, "AppError -> {}", e),
            _ => write!(f, "AppError: {}: {}", self.error_kind, self.message),
        }
    }
}

impl Display for AppError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match &self.error_kind {
            AppErrorKind::ProbeError(e) => write!(f, "AppError -> {}", e),
            AppErrorKind::ServerError(e) => write!(f, "AppError -> {}", e),
            _ => write!(f, "AppError: {}: {}", self.error_kind, self.message),
        }
    }
}

impl AppError {
    pub fn new(error_kind: AppErrorKind, message: &str) -> Self {
        Self {
            error_kind,
            message: message.to_owned(),
        }
    }
}

impl From<DbError> for AppError {
    fn from(value: DbError) -> Self {
        Self::new(AppErrorKind::DbError(value), "")
    }
}

impl From<ProbeError> for AppError {
    fn from(value: ProbeError) -> Self {
        Self::new(AppErrorKind::ProbeError(value), "")
    }
}

impl From<ServerError> for AppError {
    fn from(value: ServerError) -> Self {
        Self::new(AppErrorKind::ServerError(value), "")
    }
}

impl From<tokio::task::JoinError> for AppError {
    fn from(value: tokio::task::JoinError) -> Self {
        Self::new(AppErrorKind::TokioError, value.to_string().as_str())
    }
}
