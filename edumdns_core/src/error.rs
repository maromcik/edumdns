use pnet::datalink::ParseMacAddrErr;
use std::error::Error;
use std::fmt::{Display, Formatter};
use std::net::AddrParseError;
use std::num::ParseIntError;
use std::sync::mpsc;
use thiserror::Error;

#[derive(Debug, Clone, Error)]
pub enum CoreErrorKind {
    #[error("Capture error")]
    CaptureError,
    #[error("Network interface error")]
    NetworkInterfaceError,
    #[error("Network channel error")]
    NetworkChannelError,
    #[error("Rust channel error")]
    RustChannelError,
    #[error("Address parse error")]
    ParseAddrError,
    #[error("Packet could not be constructed")]
    PacketConstructionError,
    #[error("Packet could not be rewritten")]
    PacketRewriteError,
    #[error("Encode/Decode error")]
    EncodeDecodeError,
}

#[derive(Debug, Clone)]
pub struct CoreError {
    pub error_kind: CoreErrorKind,
    pub message: String,
}

impl Display for CoreError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "Core Error: {}: {}", self.error_kind, self.message)
    }
}

impl Error for CoreError {}

impl CoreError {
    pub fn new(error_kind: CoreErrorKind, message: &str) -> Self {
        Self {
            error_kind,
            message: message.to_owned(),
        }
    }
}

impl From<pcap::Error> for CoreError {
    fn from(value: pcap::Error) -> Self {
        CoreError::new(CoreErrorKind::CaptureError, &value.to_string())
    }
}

impl<T> From<mpsc::SendError<T>> for CoreError {
    fn from(value: mpsc::SendError<T>) -> Self {
        CoreError::new(CoreErrorKind::RustChannelError, &value.to_string())
    }
}

impl From<mpsc::RecvError> for CoreError {
    fn from(value: mpsc::RecvError) -> Self {
        CoreError::new(CoreErrorKind::RustChannelError, &value.to_string())
    }
}

impl From<ParseMacAddrErr> for CoreError {
    fn from(value: ParseMacAddrErr) -> Self {
        CoreError::new(CoreErrorKind::ParseAddrError, &value.to_string())
    }
}

impl From<AddrParseError> for CoreError {
    fn from(value: AddrParseError) -> Self {
        CoreError::new(CoreErrorKind::ParseAddrError, &value.to_string())
    }
}

impl From<ParseIntError> for CoreError {
    fn from(value: ParseIntError) -> Self {
        CoreError::new(CoreErrorKind::ParseAddrError, &value.to_string())
    }
}

impl From<bincode::error::DecodeError> for CoreError {
    fn from(value: bincode::error::DecodeError) -> Self {
        CoreError::new(CoreErrorKind::EncodeDecodeError, &value.to_string())
    }
}