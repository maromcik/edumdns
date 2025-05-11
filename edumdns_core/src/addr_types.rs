use bincode::enc::Encoder;
use bincode::error::EncodeError;
use std::hash::Hash;

#[derive(Default, Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MacAddr(pub pnet::datalink::MacAddr);

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
