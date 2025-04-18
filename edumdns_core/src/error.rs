use pnet::datalink::ParseMacAddrErr;
use std::error::Error;
use std::fmt::{Display, Formatter};
use std::net::AddrParseError;
use std::num::ParseIntError;
use std::sync::mpsc;

#[derive(Debug, Clone)]
pub enum CoreErrorKind {
    CaptureError,
    NetworkInterfaceError,
    NetworkChannelError,
    RustChannelError,
    ParseAddrError,
    PacketConstructionError,
    PacketRewriteError,
}

impl Display for CoreErrorKind {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            CoreErrorKind::CaptureError => f.write_str("Capture error"),
            CoreErrorKind::NetworkInterfaceError => f.write_str("Network interface error"),
            CoreErrorKind::NetworkChannelError => f.write_str("Network channel error"),
            CoreErrorKind::RustChannelError => f.write_str("Rust channel error"),
            CoreErrorKind::ParseAddrError => f.write_str("Address parse error"),
            CoreErrorKind::PacketConstructionError => f.write_str("Packet could not be constructed"),
            CoreErrorKind::PacketRewriteError=> f.write_str("Packet could not be rewritten"),
        }
    }
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
