use bincode::enc::Encoder;
use serde::de::Visitor;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt::{Display, Formatter};
use std::hash::Hash;

#[derive(Default, Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MacAddr(pub pnet::datalink::MacAddr);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct IpNetwork(pub ipnetwork::IpNetwork);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Uuid(pub uuid::Uuid);

impl bincode::Encode for MacAddr {
    fn encode<E: Encoder>(&self, encoder: &mut E) -> Result<(), bincode::error::EncodeError> {
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

impl Display for MacAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl MacAddr {
    pub fn to_octets(&self) -> [u8; 6] {
        self.0.octets()
    }

    pub fn from_octets(octets: [u8; 6]) -> Self {
        Self(pnet::datalink::MacAddr::new(
            octets[0], octets[1], octets[2], octets[3], octets[4], octets[5],
        ))
    }
}

impl Serialize for MacAddr {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.to_string().to_uppercase().as_str())
    }
}

struct MacAddrVisitor;

impl<'de> Visitor<'de> for MacAddrVisitor {
    type Value = MacAddr;

    fn expecting(&self, formatter: &mut Formatter) -> std::fmt::Result {
        formatter.write_str("a string representation of a valid MAC address")
    }

    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        let pnet_mac = v
            .parse::<pnet::datalink::MacAddr>()
            .map_err(|e| serde::de::Error::custom(e.to_string()))?;
        Ok(MacAddr(pnet_mac))
    }
    fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        self.visit_str(&v)
    }
}

impl<'de> Deserialize<'de> for MacAddr {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_string(MacAddrVisitor)
    }
}
impl From<String> for MacAddr {
    fn from(value: String) -> Self {
        match value.parse::<pnet::datalink::MacAddr>() {
            Ok(mac) => MacAddr(mac),
            Err(_) => MacAddr::default(),
        }
    }
}

impl Display for IpNetwork {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl bincode::Encode for IpNetwork {
    fn encode<E: Encoder>(&self, encoder: &mut E) -> Result<(), bincode::error::EncodeError> {
        self.0.ip().encode(encoder)?;
        self.0.prefix().encode(encoder)?;
        Ok(())
    }
}

impl<__Context> bincode::Decode<__Context> for IpNetwork {
    fn decode<__D: bincode::de::Decoder<Context = __Context>>(
        decoder: &mut __D,
    ) -> Result<Self, bincode::error::DecodeError> {
        let ip = ipnetwork::IpNetwork::new(
            bincode::Decode::decode(decoder)?,
            bincode::Decode::decode(decoder)?,
        )
        .map_err(|_| bincode::error::DecodeError::Other("Invalid IPNetwork"))?;
        Ok(Self(ip))
    }
}

impl<'__de, __Context> ::bincode::BorrowDecode<'__de, __Context> for IpNetwork {
    fn borrow_decode<__D: ::bincode::de::BorrowDecoder<'__de, Context = __Context>>(
        decoder: &mut __D,
    ) -> Result<Self, ::bincode::error::DecodeError> {
        let ip = ipnetwork::IpNetwork::new(
            bincode::BorrowDecode::<'_, __Context>::borrow_decode(decoder)?,
            bincode::BorrowDecode::<'_, __Context>::borrow_decode(decoder)?,
        )
        .map_err(|_| bincode::error::DecodeError::Other("Invalid IPNetwork"))?;
        Ok(Self(ip))
    }
}

impl Display for Uuid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl bincode::Encode for Uuid {
    fn encode<E: Encoder>(&self, encoder: &mut E) -> Result<(), bincode::error::EncodeError> {
        self.0.as_bytes().encode(encoder)?;
        Ok(())
    }
}

impl<__Context> bincode::Decode<__Context> for Uuid {
    fn decode<__D: bincode::de::Decoder<Context = __Context>>(
        decoder: &mut __D,
    ) -> Result<Self, bincode::error::DecodeError> {
        let uuid = uuid::Uuid::from_bytes(bincode::Decode::decode(decoder)?);
        Ok(Self(uuid))
    }
}

impl<'__de, __Context> ::bincode::BorrowDecode<'__de, __Context> for Uuid {
    fn borrow_decode<__D: ::bincode::de::BorrowDecoder<'__de, Context = __Context>>(
        decoder: &mut __D,
    ) -> Result<Self, ::bincode::error::DecodeError> {
        let uuid = uuid::Uuid::from_bytes(bincode::BorrowDecode::<'_, __Context>::borrow_decode(
            decoder,
        )?);
        Ok(Self(uuid))
    }
}
