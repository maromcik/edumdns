//! Code in this module was taken over and modified.
//! Original source: https://github.com/firezone/firezone/blob/21ee0a52a840b03b6c214fb332ec18d46c0c1e35/rust/relay/ebpf-turn-router/src/try_handle_turn/checksum.rs
//! Incremental updates to Internet checksums.
//!
//! The Internet checksum is the one's complement of the one's complement sum of certain 16-bit words.
//! The use of one's complement arithmetic allows us to make incremental updates to a checksum without requiring a full re-computation.
//!
//! That is what we are implementing in this module.
//! There are three things you need to know:
//!
//! 1. The one's complement of a number `x` is `!x`.
//! 2. Addition in one's complement arithmetic is the same as regular addition, except that upon overflow, we add an additional bit.
//! 3. Subtraction in one's complement arithmetic is implemented as the addition of the one's complement of the number to be subtracted.
//!
//! This allows us to e.g. take an existing IP header checksum and update it to account for just the destination address changing.

#[derive(Default)]
#[repr(transparent)]
pub struct ChecksumUpdate {
    inner: u16,
}

impl ChecksumUpdate {
    pub fn new(checksum: u16) -> Self {
        Self { inner: !checksum }
    }

    pub fn remove_u16(self, val: u16) -> Self {
        self.ones_complement_add(!val)
    }

    pub fn remove_u32(self, val: u32) -> Self {
        self.remove_u16(fold_u32_into_u16(val))
    }

    pub fn remove_u128(self, val: u128) -> Self {
        self.remove_u16(fold_u128_into_u16(val))
    }

    pub fn add_u16(self, val: u16) -> Self {
        self.ones_complement_add(val)
    }

    pub fn add_u32(self, val: u32) -> Self {
        self.add_u16(fold_u32_into_u16(val))
    }

    pub fn add_u128(self, val: u128) -> Self {
        self.add_u16(fold_u128_into_u16(val))
    }

    #[inline(always)]
    fn ones_complement_add(self, val: u16) -> Self {
        let (res, carry) = self.inner.overflowing_add(val);

        Self {
            inner: res + (carry as u16),
        }
    }

    pub fn into_ip_checksum(self) -> u16 {
        !self.inner
    }

    pub fn into_tcp_checksum(self) -> u16 {
        !self.inner
    }

    pub fn into_udp_checksum(self) -> u16 {
        // RFC 768, Section 3.1 states that we must invert the final computed checksum if it came
        // out to be zero.
        let check = !self.inner;

        if check == 0 { 0xFFFF } else { check }
    }
}

#[inline(always)]
fn fold_u32_into_u16(mut csum: u32) -> u16 {
    csum = (csum & 0xffff) + (csum >> 16);
    csum = (csum & 0xffff) + (csum >> 16);

    csum as u16
}

#[inline(never)]
fn fold_u128_into_u16(mut csum: u128) -> u16 {
    csum = (csum & 0xffff) + (csum >> 16);
    csum = (csum & 0xffff) + (csum >> 16);
    csum = (csum & 0xffff) + (csum >> 16);
    csum = (csum & 0xffff) + (csum >> 16);
    csum = (csum & 0xffff) + (csum >> 16);
    csum = (csum & 0xffff) + (csum >> 16);
    csum = (csum & 0xffff) + (csum >> 16);
    csum = (csum & 0xffff) + (csum >> 16);

    csum as u16
}
