use edumdns_probe::error::ProbeError;
use edumdns_server::error::ServerError;
use std::fmt::{Debug, Display, Formatter};
use thiserror::Error;

#[derive(Error, Debug, Clone)]
pub enum AppErrorKind {
    ProbeError(ProbeError),
    ServerError(ServerError),
    TokioError,
}

impl Display for AppErrorKind {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            AppErrorKind::ProbeError(err) => std::fmt::Display::fmt(&err, f),
            AppErrorKind::ServerError(err) => std::fmt::Display::fmt(&err, f),
            AppErrorKind::TokioError => write!(f, "Tokio error"),
        }
    }
}

#[derive(Error, Debug, Clone)]
pub struct AppError {
    pub error_kind: AppErrorKind,
    pub message: String,
}

impl Display for AppError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "AppError: {}: {}", self.error_kind, self.message)
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
