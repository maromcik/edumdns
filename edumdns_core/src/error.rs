use pnet::datalink::ParseMacAddrErr;
use std::net::AddrParseError;
use std::num::ParseIntError;
use std::sync::mpsc;
use thiserror::Error;

#[derive(Debug, Clone, Error, Eq, PartialEq)]
pub enum CoreError {
    #[error("network interface error: {0}")]
    NetworkInterfaceError(String),
    #[error("network channel error: {0}")]
    NetworkChannelError(String),
    #[error("rust channel error: {0}")]
    RustChannelError(String),
    #[error("address parse error: {0}")]
    ParseAddrError(String),
    #[error("packet could not be constructed: {0}")]
    PacketConstructionError(String),
    #[error("encode/decode error: {0}")]
    EncodeDecodeError(String),
    #[error("I/O error: {0}")]
    IoError(String),
    #[error("interface error: {0}")]
    InterfaceError(String),
    #[error("tokio task error: {0}")]
    TaskError(String),
    #[error("timeout Error: {0}")]
    TimeoutError(String),
    #[error("tokio oneshot channel error: {0}")]
    TokioOneshotChannelError(String),
    #[error("tokio mpsc channel error: {0}")]
    TokioMpscChannelError(String),
    #[error("DNS packet manipulation error: {0}")]
    DnsPacketManipulationError(String),
    #[error("DNS error: {0}")]
    DnsError(String),
}


impl<T> From<mpsc::SendError<T>> for CoreError {
    fn from(value: mpsc::SendError<T>) -> Self {
        CoreError::RustChannelError(value.to_string())
    }
}

impl From<mpsc::RecvError> for CoreError {
    fn from(value: mpsc::RecvError) -> Self {
        CoreError::RustChannelError(value.to_string())
    }
}

impl From<ParseMacAddrErr> for CoreError {
    fn from(value: ParseMacAddrErr) -> Self {
        CoreError::ParseAddrError(value.to_string())
    }
}

impl From<AddrParseError> for CoreError {
    fn from(value: AddrParseError) -> Self {
        CoreError::ParseAddrError(value.to_string())
    }
}

impl From<ParseIntError> for CoreError {
    fn from(value: ParseIntError) -> Self {
        CoreError::ParseAddrError(value.to_string())
    }
}

impl From<bincode::error::DecodeError> for CoreError {
    fn from(value: bincode::error::DecodeError) -> Self {
        CoreError::EncodeDecodeError(value.to_string())
    }
}

impl From<std::io::Error> for CoreError {
    fn from(value: std::io::Error) -> Self {
        CoreError::IoError(value.to_string())
    }
}

impl From<bincode::error::EncodeError> for CoreError {
    fn from(value: bincode::error::EncodeError) -> Self {
        CoreError::EncodeDecodeError(value.to_string())
    }
}

impl From<tokio::task::JoinError> for CoreError {
    fn from(value: tokio::task::JoinError) -> Self {
        CoreError::TaskError(value.to_string())
    }
}

impl From<tokio::time::error::Elapsed> for CoreError {
    fn from(value: tokio::time::error::Elapsed) -> Self {
        CoreError::TimeoutError(value.to_string())
    }
}

impl From<tokio::sync::oneshot::error::RecvError> for CoreError {
    fn from(value: tokio::sync::oneshot::error::RecvError) -> Self {
        CoreError::TokioOneshotChannelError(value.to_string())
    }
}

impl<T> From<tokio::sync::mpsc::error::SendError<T>> for CoreError {
    fn from(value: tokio::sync::mpsc::error::SendError<T>) -> Self {
        CoreError::TokioMpscChannelError(value.to_string())
    }
}

impl From<ipnetwork::IpNetworkError> for CoreError {
    fn from(value: ipnetwork::IpNetworkError) -> Self {
        CoreError::ParseAddrError(value.to_string())
    }
}

impl From<hickory_proto::ProtoError> for CoreError {
    fn from(value: hickory_proto::ProtoError) -> Self {
        CoreError::DnsPacketManipulationError(value.to_string())
    }
}

impl From<rustls_pki_types::InvalidDnsNameError> for CoreError {
    fn from(value: rustls_pki_types::InvalidDnsNameError) -> Self {
        CoreError::DnsError(value.to_string())
    }
}
