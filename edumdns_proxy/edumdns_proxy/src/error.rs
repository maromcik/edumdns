use std::fmt::{Debug, Display, Formatter};
use thiserror::Error;

#[derive(Error, Debug, Clone)]
pub enum ProxyErrorKind {
    #[error("Invalid arguments")]
    ArgumentError,
    #[error("I/O error")]
    IoError,
    #[error("Encode/Decode error")]
    EnvError,
    #[error("Parse error")]
    ParseError,
    #[error("eBPF error")]
    EbpfError,
    #[error("eBPF map error")]
    EbpfMapError,
    #[error("eBPF pin error")]
    EbpfPinError,
    #[error("Anyhow any error")]
    AnyError,
    #[error("eBPF config missing")]
    MapMissing,
}

#[derive(Error, Clone)]
pub struct ProxyError {
    pub error_kind: ProxyErrorKind,
    pub message: String,
}

impl Display for ProxyError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "ProxyError: {}: {}", self.error_kind, self.message)
    }
}

impl Debug for ProxyError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "ProxyError: {}: {}", self.error_kind, self.message)
    }
}

impl ProxyError {
    pub fn new(error_kind: ProxyErrorKind, message: &str) -> Self {
        Self {
            error_kind,
            message: message.to_owned(),
        }
    }
}

impl From<std::io::Error> for ProxyError {
    fn from(value: std::io::Error) -> Self {
        Self::new(ProxyErrorKind::IoError, value.to_string().as_str())
    }
}

impl From<std::net::AddrParseError> for ProxyError {
    fn from(value: std::net::AddrParseError) -> Self {
        Self::new(ProxyErrorKind::ArgumentError, value.to_string().as_str())
    }
}

impl From<std::env::VarError> for ProxyError {
    fn from(value: std::env::VarError) -> Self {
        Self::new(ProxyErrorKind::EnvError, value.to_string().as_str())
    }
}

impl From<uuid::Error> for ProxyError {
    fn from(value: uuid::Error) -> Self {
        Self::new(ProxyErrorKind::ParseError, value.to_string().as_str())
    }
}

impl From<std::num::ParseIntError> for ProxyError {
    fn from(value: std::num::ParseIntError) -> Self {
        Self::new(ProxyErrorKind::ParseError, value.to_string().as_str())
    }
}

impl From<aya::EbpfError> for ProxyError {
    fn from(value: aya::EbpfError) -> Self {
        Self::new(ProxyErrorKind::EbpfError, value.to_string().as_str())
    }
}

impl From<aya::programs::ProgramError> for ProxyError {
    fn from(value: aya::programs::ProgramError) -> Self {
        Self::new(ProxyErrorKind::EbpfError, value.to_string().as_str())
    }
}

impl From<anyhow::Error> for ProxyError {
    fn from(value: anyhow::Error) -> Self {
        Self::new(ProxyErrorKind::AnyError, value.to_string().as_str())
    }
}

impl From<aya::maps::MapError> for ProxyError {
    fn from(value: aya::maps::MapError) -> Self {
        Self::new(ProxyErrorKind::EbpfMapError, value.to_string().as_str())
    }
}

impl From<aya::pin::PinError> for ProxyError {
    fn from(value: aya::pin::PinError) -> Self {
        Self::new(ProxyErrorKind::EbpfPinError, value.to_string().as_str())
    }
}
