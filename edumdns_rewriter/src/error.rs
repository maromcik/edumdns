use crate::network::error::{NetworkError, NetworkErrorKind};
use std::fmt::{Debug, Display, Formatter};
use thiserror::Error;

#[derive(Error, Debug, Clone)]
pub enum RewriterErrorKind {
    NetworkError(NetworkErrorKind),
    ArgumentError,
}

impl Display for RewriterErrorKind {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            RewriterErrorKind::NetworkError(err) => std::fmt::Display::fmt(&err, f),
            RewriterErrorKind::ArgumentError => write!(f, "Invalid arguments"),
        }
    }
}

#[derive(Error, Debug, Clone)]
pub struct AppError {
    pub error_kind: RewriterErrorKind,
    pub message: String,
}

impl Display for AppError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "AppError: {}: {}", self.error_kind, self.message)
    }
}

impl AppError {
    pub fn new(error_kind: RewriterErrorKind, message: &str) -> Self {
        Self {
            error_kind,
            message: message.to_owned(),
        }
    }
}

impl From<NetworkError> for AppError {
    fn from(value: NetworkError) -> Self {
        Self::new(
            RewriterErrorKind::NetworkError(value.error_kind),
            value.message.as_str(),
        )
    }
}
