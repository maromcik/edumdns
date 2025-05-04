use std::net::{AddrParseError, Ipv4Addr, Ipv6Addr};
use bincode::{Decode, Encode};
use bincode::enc::Encoder;
use bincode::error::EncodeError;
use pnet::datalink::ParseMacAddrErr;
use crate::error::CoreError;

#[derive(Default, Encode, Decode, Debug)]
pub struct PacketMetadata {
    pub datalink_rewrite: Option<DataLinkMetadata>,
    pub ip_rewrite: Option<IpMetadata>,
    pub transport_rewrite: Option<PortMetadata>,
}

impl PacketMetadata {
    pub fn new(
        datalink_rewrite: Option<DataLinkMetadata>,
        ip_rewrite: Option<IpMetadata>,
        transport_rewrite: Option<PortMetadata>,
    ) -> Self {
        Self {
            datalink_rewrite,
            ip_rewrite,
            transport_rewrite,
        }
    }
}

#[derive(Default, Encode, Decode, Debug)]
pub struct IpMetadata {
    pub ipv4_rewrite: Option<Ipv4Metadata>,
    pub ipv6_rewrite: Option<Ipv6Metadata>,
}

impl IpMetadata {
    pub fn parse_ipv4_rewrite(
        src_ipv4: Option<&str>,
        dst_ipv4: Option<&str>,
    ) -> Result<IpMetadata, CoreError> {
        Ok(Self {
            ipv4_rewrite: Some(Ipv4Metadata::parse(src_ipv4, dst_ipv4)?),
            ipv6_rewrite: None,
        })
    }

    pub fn parse_ipv6_rewrite(
        src_ipv6: Option<&str>,
        dst_ipv6: Option<&str>,
    ) -> Result<IpMetadata, CoreError> {
        Ok(Self {
            ipv4_rewrite: None,
            ipv6_rewrite: Some(Ipv6Metadata::parse(src_ipv6, dst_ipv6)?),
        })
    }
}

#[derive(Default, Encode, Decode, Debug)]
pub struct DataLinkMetadata {
    pub mac_rewrite: Option<MacMetadata>,
    pub vlan_rewrite: Option<VlanMetadata>,
}

impl DataLinkMetadata {
    pub fn new(mac_rewrite: Option<MacMetadata>, vlan_rewrite: Option<VlanMetadata>) -> Self {
        Self {
            mac_rewrite,
            vlan_rewrite,
        }
    }
    pub fn parse_mac_rewrite(
        src_mac: Option<&str>,
        dst_mac: Option<&str>,
    ) -> Result<Self, CoreError> {
        Ok(Self::new(Some(MacMetadata::parse(src_mac, dst_mac)?), None))
    }
    pub fn new_vlan_rewrite(vlan: u16) -> Self {
        Self::new(None, Some(VlanMetadata::new(vlan)))
    }
}

#[derive(Default, Encode, Decode, Debug)]
pub struct PortMetadata {
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
}

impl PortMetadata {
    pub fn new(src_port: Option<u16>, dst_port: Option<u16>) -> Self {
        Self { src_port, dst_port }
    }
}

#[derive(Default, Encode, Decode, Debug)]
pub struct Ipv4Metadata {
    pub src_ip: Option<Ipv4Addr>,
    pub dst_ip: Option<Ipv4Addr>,
}

impl Ipv4Metadata {
    pub fn parse(src_ipv4: Option<&str>, dst_ipv4: Option<&str>) -> Result<Self, CoreError> {
        Ok(Self {
            src_ip: Self::parse_ipv4(src_ipv4.as_ref())?,
            dst_ip: Self::parse_ipv4(dst_ipv4.as_ref())?,
        })
    }
    fn parse_ipv4(ipv4: Option<&&str>) -> Result<Option<Ipv4Addr>, AddrParseError> {
        ipv4.map(|ip| ip.parse::<Ipv4Addr>()).transpose()
    }
}

#[derive(Default, Encode, Decode, Debug)]
pub struct Ipv6Metadata {
    pub src_ip: Option<Ipv6Addr>,
    pub dst_ip: Option<Ipv6Addr>,
}

impl Ipv6Metadata {
    pub fn parse(src_ipv6: Option<&str>, dst_ipv6: Option<&str>) -> Result<Self, CoreError> {
        Ok(Self {
            src_ip: Self::parse_ipv6(src_ipv6.as_ref())?,
            dst_ip: Self::parse_ipv6(dst_ipv6.as_ref())?,
        })
    }

    fn parse_ipv6(ipv6: Option<&&str>) -> Result<Option<Ipv6Addr>, AddrParseError> {
        ipv6.map(|ip| ip.parse::<Ipv6Addr>()).transpose()
    }
}

#[derive(Default, Encode, Decode, Debug)]
pub struct MacMetadata {
    pub src_mac: Option<MacAddr>,
    pub dst_mac: Option<MacAddr>,
}

#[derive(Default, Debug)]
pub struct MacAddr(pub pnet::datalink::MacAddr);

impl Encode for MacAddr {
    fn encode<E: Encoder>(&self, encoder: &mut E) -> Result<(), EncodeError> {
        bincode::Encode::encode(&self.0.0, encoder)?;
        bincode::Encode::encode(&self.0.1, encoder)?;
        bincode::Encode::encode(&self.0.2, encoder)?;
        bincode::Encode::encode(&self.0.3, encoder)?;
        bincode::Encode::encode(&self.0.4, encoder)?;
        bincode::Encode::encode(&self.0.5, encoder)?;
        Ok(())
    }
}

impl<__Context> bincode::Decode<__Context> for MacAddr {
    fn decode<__D: bincode::de::Decoder<Context = __Context>>(
        decoder: &mut __D,
    ) -> Result<Self, bincode::error::DecodeError> {
        let mac_addr = pnet::datalink::MacAddr::new(
            bincode::Decode::decode(decoder)?,
            bincode::Decode::decode(decoder)?,
            bincode::Decode::decode(decoder)?,
            bincode::Decode::decode(decoder)?,
            bincode::Decode::decode(decoder)?,
            bincode::Decode::decode(decoder)?,
        );
        Ok(Self(mac_addr))
    }
}

impl<'__de, __Context> ::bincode::BorrowDecode<'__de, __Context> for MacAddr {
    fn borrow_decode<__D: ::bincode::de::BorrowDecoder<'__de, Context = __Context>>(
        decoder: &mut __D,
    ) -> Result<Self, ::bincode::error::DecodeError> {
        let mac_addr = pnet::datalink::MacAddr::new(
            bincode::BorrowDecode::<'_, __Context>::borrow_decode(decoder)?,
            bincode::BorrowDecode::<'_, __Context>::borrow_decode(decoder)?,
            bincode::BorrowDecode::<'_, __Context>::borrow_decode(decoder)?,
            bincode::BorrowDecode::<'_, __Context>::borrow_decode(decoder)?,
            bincode::BorrowDecode::<'_, __Context>::borrow_decode(decoder)?,
            bincode::BorrowDecode::<'_, __Context>::borrow_decode(decoder)?,
        );
        Ok(Self(mac_addr))
    }
}

impl MacMetadata {
    pub fn parse(src_mac: Option<&str>, dst_mac: Option<&str>) -> Result<Self, CoreError> {
        Ok(Self {
            src_mac: Self::parse_mac(src_mac.as_ref())?,
            dst_mac: Self::parse_mac(dst_mac.as_ref())?,
        })
    }
    fn parse_mac(mac: Option<&&str>) -> Result<Option<MacAddr>, ParseMacAddrErr> {
        mac.map(|mac| mac.parse::<pnet::datalink::MacAddr>())
            .map(|parsed_mac| parsed_mac.map(MacAddr))
            .transpose()
    }
}

#[derive(Default, Encode, Decode, Debug)]
pub struct VlanMetadata {
    pub vlan_id: u16,
}

impl VlanMetadata {
    pub fn new(vlan_id: u16) -> Self {
        Self { vlan_id }
    }
}
