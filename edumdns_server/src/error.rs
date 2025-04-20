use edumdns_core::error::CoreError;
use std::fmt::{Debug, Display, Formatter};
use thiserror::Error;

#[derive(Error, Debug, Clone)]
pub enum ServerErrorKind {
    CoreError(CoreError),
    ArgumentError,
    IoError,
}

impl Display for ServerErrorKind {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            ServerErrorKind::CoreError(err) => std::fmt::Display::fmt(&err, f),
            ServerErrorKind::ArgumentError => write!(f, "Invalid arguments"),
            ServerErrorKind::IoError => write!(f, "I/O error from Tokio"),
        }
    }
}

#[derive(Error, Debug, Clone)]
pub struct ServerError {
    pub error_kind: ServerErrorKind,
    pub message: String,
}

impl Display for ServerError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "ServerError: {}: {}", self.error_kind, self.message)
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
        Self::new(
            ServerErrorKind::CoreError(value),
            ""
        )
    }
}

impl From<std::io::Error> for ServerError {
    fn from(value: std::io::Error) -> Self {
        Self::new(
            ServerErrorKind::IoError,
            value.to_string().as_str(),
        )
    }
}

