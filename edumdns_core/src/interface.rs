//! Low-level interface helpers using pnet (alternative capture path).
//!
//! This module exposes a thin wrapper over `pnet` for opening datalink and
//! transport channels directly. It is currently not used in the main data path,
//! but can be useful for experiments or custom capture setups.
//!
//! - `NetworkConfig` describes the selected output device and timing options.
//! - `get_datalink_channel` opens an Ethernet/VLAN channel for raw frames.
//! - `get_transport_channel` opens a Layer4 IPv4 TCP transport channel.
use crate::error::CoreError;
use pnet::datalink::Channel::Ethernet;
use pnet::datalink::{DataLinkReceiver, DataLinkSender};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::transport::TransportChannelType::Layer4;
use pnet::transport::TransportProtocol::Ipv4;
use pnet::transport::{TransportReceiver, TransportSender};
use pnet::{datalink, transport};
use std::time::Duration;

/// Configuration for opening low-level `pnet` channels.
///
/// This struct is used by the helper functions in this module to decide which
/// OS network interface to open and how to pace packet emission when crafting or
/// replaying frames.
///
/// Fields:
/// - `output_device`: name of the interface to open (e.g., `eth0`). Must match
///   one of the names returned by `pnet::datalink::interfaces()`.
/// - `interval`: optional delay between consecutive sends; useful for throttling
///   replays. When `None`, no artificial delay is introduced by these helpers.
/// - `straight`: when `true`, send packets without additional processing; when
///   `false`, higher layers may choose to apply rewrites/adjustments before send.
pub struct NetworkConfig {
    pub output_device: String,
    pub interval: Option<Duration>,
    pub straight: bool,
}

/// Pair of receive/send halves returned by `pnet` channel constructors.
///
/// The concrete types are boxed trait objects to avoid exposing `pnet` types at
/// the API boundary of this crate (except in the transport variant where the
/// concrete types are stable). This makes it easier to stub or replace in tests.
///
/// Type parameters:
/// - `R`: receiver trait object type (`DataLinkReceiver` or `TransportReceiver`).
/// - `T`: transmitter trait object type (`DataLinkSender` or `TransportSender`).
pub struct NetworkChannel<R, T>
where
    T: ?Sized,
    R: ?Sized,
{
    pub rx: Box<R>,
    pub tx: Box<T>,
}

pub fn get_datalink_channel(
    capture: &NetworkConfig,
) -> Result<NetworkChannel<dyn DataLinkReceiver, dyn DataLinkSender>, CoreError> {
    let interfaces = datalink::interfaces();
    let interface = interfaces
        .iter()
        .find(|i| i.name == capture.output_device)
        .ok_or(CoreError::NetworkInterfaceError(format!(
            "Output device {} not found",
            capture.output_device
        )))?;
    let (tx, rx) = match datalink::channel(interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => Ok((tx, rx)),
        Ok(_) => Err(CoreError::NetworkChannelError(
            "Unknown channel type".to_string(),
        )),
        Err(e) => Err(CoreError::NetworkChannelError(e.to_string())),
    }?;

    Ok(NetworkChannel { rx, tx })
}

pub fn get_transport_channel()
-> Result<NetworkChannel<TransportReceiver, TransportSender>, CoreError> {
    let (tx, rx) =
        match transport::transport_channel(4096, Layer4(Ipv4(IpNextHeaderProtocols::Tcp))) {
            Ok((tx, rx)) => Ok((tx, rx)),
            Err(e) => Err(CoreError::NetworkChannelError(e.to_string())),
        }?;

    Ok(NetworkChannel {
        rx: Box::new(rx),
        tx: Box::new(tx),
    })
}
