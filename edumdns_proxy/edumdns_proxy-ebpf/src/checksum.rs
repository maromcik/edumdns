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

use network_types::ip::Ipv4Hdr;

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

/// Calculate a fresh IPv4 header checksum
#[inline(always)]
pub fn new_ipv4(ipv4: &mut Ipv4Hdr) -> u16 {
    // Zero the checksum field before calculation
    ipv4.set_checksum(0);

    // Cast the IPv4 header to bytes and process as u16 words
    let header_bytes =
        unsafe { core::slice::from_raw_parts(ipv4 as *const _ as *const u8, Ipv4Hdr::LEN) };

    let mut sum = 0u32;
    let mut i = 0;
    while i < Ipv4Hdr::LEN {
        // Read two bytes as a u16 in network byte order
        let word = ((header_bytes[i] as u16) << 8) | (header_bytes[i + 1] as u16);
        sum += word as u32;
        i += 2;
    }

    // Fold carries
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    // One's complement
    !(sum as u16)
}

