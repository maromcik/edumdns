use crate::error::CoreError;
use pnet::datalink::Channel::Ethernet;
use pnet::datalink::{DataLinkReceiver, DataLinkSender};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::transport::TransportChannelType::Layer4;
use pnet::transport::TransportProtocol::Ipv4;
use pnet::transport::{TransportReceiver, TransportSender};
use pnet::{datalink, transport};
use std::time::Duration;

/// Alternative approach, use low-level pnet to capture packets, currently not used
pub struct NetworkConfig {
    pub output_device: String,
    pub interval: Option<Duration>,
    pub straight: bool,
}

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
