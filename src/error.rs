use std::fmt::{Debug, Display, Formatter};
use thiserror::Error;
use edumdns_probe::error::ProbeError;

#[derive(Error, Debug, Clone)]
pub enum AppErrorKind {
    ProbeError(ProbeError),
}

impl Display for AppErrorKind {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            AppErrorKind::ProbeError(err) => std::fmt::Display::fmt(&err, f),
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
        Self::new(
            AppErrorKind::ProbeError(value),
            "",
        )
    }
}
