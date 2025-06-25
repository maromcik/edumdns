use std::error::Error;
use bincode::enc::Encoder;
use bincode::error::EncodeError;
use std::fmt::Display;
use std::hash::Hash;

#[derive(Default, Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MacAddr(pub pnet::datalink::MacAddr);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct IpNetwork(pub ipnetwork::IpNetwork);

impl bincode::Encode for MacAddr {
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
        Self(pnet::datalink::MacAddr::new(octets[0], octets[1], octets[2], octets[3], octets[4], octets[5]))   
    }
}

impl bincode::Encode for IpNetwork {
    fn encode<E: Encoder>(&self, encoder: &mut E) -> Result<(), EncodeError> {
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
        ).map_err(|_| bincode::error::DecodeError::Other("Invalid IPNetwork"))?;
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
        ).map_err(|_| bincode::error::DecodeError::Other("Invalid IPNetwork"))?;
        Ok(Self(ip))
    }
}