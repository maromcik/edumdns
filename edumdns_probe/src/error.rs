use std::fmt::{Debug, Display, Formatter};
use thiserror::Error;
use edumdns_core::error::{CoreError, CoreErrorKind};

#[derive(Error, Debug, Clone)]
pub enum ProbeErrorKind {
    CoreError(CoreError),
    ArgumentError,
    IoError,
}

impl Display for ProbeErrorKind {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            ProbeErrorKind::CoreError(err) => std::fmt::Display::fmt(&err, f),
            ProbeErrorKind::ArgumentError => write!(f, "Invalid arguments"),
            ProbeErrorKind::IoError => write!(f, "I/O error from Tokio"),
        }
    }
}

#[derive(Error, Debug, Clone)]
pub struct ProbeError {
    pub error_kind: ProbeErrorKind,
    pub message: String,
}

impl Display for ProbeError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "ProbeError: {}: {}", self.error_kind, self.message)
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