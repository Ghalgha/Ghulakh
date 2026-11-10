//! Bounded STUN message codec used by the TURN control plane.
//!
//! This module deliberately handles framing and address attributes only.
//! MESSAGE-INTEGRITY, credential derivation and TURN state transitions are
//! separate concerns and must be implemented with audited cryptographic APIs.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

pub const HEADER_LEN: usize = 20;
pub const MAGIC_COOKIE: u32 = 0x2112_A442;
pub const MAX_MESSAGE_LEN: usize = HEADER_LEN + u16::MAX as usize;

pub const ATTR_USERNAME: u16 = 0x0006;
pub const ATTR_MESSAGE_INTEGRITY: u16 = 0x0008;
pub const ATTR_ERROR_CODE: u16 = 0x0009;
pub const ATTR_CHANNEL_NUMBER: u16 = 0x000C;
pub const ATTR_LIFETIME: u16 = 0x000D;
pub const ATTR_XOR_PEER_ADDRESS: u16 = 0x0012;
pub const ATTR_DATA: u16 = 0x0013;
pub const ATTR_REALM: u16 = 0x0014;
pub const ATTR_NONCE: u16 = 0x0015;
pub const ATTR_XOR_RELAYED_ADDRESS: u16 = 0x0016;
pub const ATTR_REQUESTED_TRANSPORT: u16 = 0x0019;
pub const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;
pub const ATTR_CHANNEL_BINDING: u16 = 0x000C;
pub const ATTR_FINGERPRINT: u16 = 0x8028;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StunError {
    Truncated,
    InvalidType,
    InvalidCookie,
    InvalidLength,
    MessageTooLarge,
    AttributeTooLarge,
    InvalidAddress,
    UnsupportedAddressFamily,
}

impl std::fmt::Display for StunError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "STUN codec error: {self:?}")
    }
}
impl std::error::Error for StunError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StunClass { Request, Indication, SuccessResponse, ErrorResponse }

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StunAttribute {
    pub kind: u16,
    pub value: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StunMessage {
    pub method: u16,
    pub class: StunClass,
    pub transaction_id: [u8; 12],
    pub attributes: Vec<StunAttribute>,
}

impl StunMessage {
    pub fn decode(input: &[u8]) -> Result<Self, StunError> {
        if input.len() < HEADER_LEN { return Err(StunError::Truncated); }
        if input.len() > MAX_MESSAGE_LEN { return Err(StunError::MessageTooLarge); }
        let ty = u16::from_be_bytes([input[0], input[1]]);
        if ty & 0xC000 != 0 { return Err(StunError::InvalidType); }
        let body_len = usize::from(u16::from_be_bytes([input[2], input[3]]));
        if body_len % 4 != 0 || body_len + HEADER_LEN != input.len() {
            return Err(StunError::InvalidLength);
        }
        if u32::from_be_bytes(input[4..8].try_into().unwrap()) != MAGIC_COOKIE {
            return Err(StunError::InvalidCookie);
        }
        let mut transaction_id = [0u8; 12];
        transaction_id.copy_from_slice(&input[8..20]);
        let mut attributes = Vec::new();
        let mut offset = HEADER_LEN;
        while offset < input.len() {
            if input.len() - offset < 4 { return Err(StunError::Truncated); }
            let kind = u16::from_be_bytes([input[offset], input[offset + 1]]);
            let len = usize::from(u16::from_be_bytes([input[offset + 2], input[offset + 3]]));
            let value_start = offset + 4;
            let value_end = value_start.checked_add(len).ok_or(StunError::InvalidLength)?;
            let padded_end = value_start.checked_add((len + 3) & !3).ok_or(StunError::InvalidLength)?;
            if padded_end > input.len() || value_end > input.len() { return Err(StunError::Truncated); }
            attributes.push(StunAttribute { kind, value: input[value_start..value_end].to_vec() });
            offset = padded_end;
        }
        let method = ((ty & 0x000F) | ((ty & 0x00E0) >> 1) | ((ty & 0x3E00) >> 2)) as u16;
        let class = match ((ty >> 4) & 1) | ((ty >> 7) & 2) {
            0 => StunClass::Request,
            1 => StunClass::Indication,
            2 => StunClass::SuccessResponse,
            _ => StunClass::ErrorResponse,
        };
        Ok(Self { method, class, transaction_id, attributes })
    }

    pub fn encode(&self) -> Result<Vec<u8>, StunError> {
        if self.method > 0x0FFF { return Err(StunError::InvalidType); }
        let mut body = Vec::new();
        for attr in &self.attributes {
            if attr.value.len() > u16::MAX as usize { return Err(StunError::AttributeTooLarge); }
            body.extend_from_slice(&attr.kind.to_be_bytes());
            body.extend_from_slice(&(attr.value.len() as u16).to_be_bytes());
            body.extend_from_slice(&attr.value);
            body.resize(body.len() + ((4 - attr.value.len() % 4) % 4), 0);
        }
        if body.len() > u16::MAX as usize { return Err(StunError::MessageTooLarge); }
        let method = self.method;
        let class = match self.class { StunClass::Request => 0, StunClass::Indication => 1, StunClass::SuccessResponse => 2, StunClass::ErrorResponse => 3 };
        let ty = (method & 0x000F) | ((method & 0x0070) << 1) | ((method & 0x0F80) << 2)
            | ((class & 1) << 4) | ((class & 2) << 7);
        let mut out = Vec::with_capacity(HEADER_LEN + body.len());
        out.extend_from_slice(&ty.to_be_bytes());
        out.extend_from_slice(&(body.len() as u16).to_be_bytes());
        out.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        out.extend_from_slice(&self.transaction_id);
        out.extend_from_slice(&body);
        Ok(out)
    }

    pub fn attribute(&self, kind: u16) -> Option<&[u8]> {
        self.attributes.iter().find(|a| a.kind == kind).map(|a| a.value.as_slice())
    }
}

pub fn encode_xor_address(kind: u16, address: SocketAddr, transaction_id: &[u8; 12]) -> Vec<u8> {
    let mut out = Vec::with_capacity(20);
    out.push(0);
    match address.ip() {
        IpAddr::V4(ip) => {
            out.push(1);
            out.extend_from_slice(&(address.port() ^ (MAGIC_COOKIE >> 16) as u16).to_be_bytes());
            let masked = u32::from(ip) ^ MAGIC_COOKIE;
            out.extend_from_slice(&masked.to_be_bytes());
        }
        IpAddr::V6(ip) => {
            out.push(2);
            out.extend_from_slice(&(address.port() ^ (MAGIC_COOKIE >> 16) as u16).to_be_bytes());
            let mut mask = [0u8; 16];
            mask[..4].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
            mask[4..].copy_from_slice(transaction_id);
            for (dst, src) in out.iter_mut().skip(4).zip(ip.octets().iter()) { let _ = (dst, src); }
            out.extend(ip.octets().iter().zip(mask.iter()).map(|(a,b)| a ^ b));
        }
    }
    let _ = kind;
    out
}

pub fn decode_xor_address(value: &[u8], transaction_id: &[u8; 12]) -> Result<SocketAddr, StunError> {
    if value.len() < 4 || value[0] != 0 { return Err(StunError::InvalidAddress); }
    let port = u16::from_be_bytes([value[2], value[3]]) ^ (MAGIC_COOKIE >> 16) as u16;
    match value[1] {
        1 if value.len() == 8 => {
            let raw = u32::from_be_bytes(value[4..8].try_into().unwrap()) ^ MAGIC_COOKIE;
            Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(raw)), port))
        }
        2 if value.len() == 20 => {
            let mut mask = [0u8; 16];
            mask[..4].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
            mask[4..].copy_from_slice(transaction_id);
            let mut raw = [0u8; 16];
            for i in 0..16 { raw[i] = value[4+i] ^ mask[i]; }
            Ok(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(raw)), port))
        }
        1 | 2 => Err(StunError::InvalidAddress),
        _ => Err(StunError::UnsupportedAddressFamily),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn sample(class: StunClass) -> StunMessage {
        StunMessage { method: 0x003, class, transaction_id: [0x42;12], attributes: vec![
            StunAttribute { kind: ATTR_LIFETIME, value: 600u32.to_be_bytes().to_vec() },
            StunAttribute { kind: 0xC001, value: vec![1,2,3] },
        ]}
    }
    #[test] fn message_round_trip_all_classes() {
        for class in [StunClass::Request,StunClass::Indication,StunClass::SuccessResponse,StunClass::ErrorResponse] {
            let m=sample(class); assert_eq!(StunMessage::decode(&m.encode().unwrap()).unwrap(),m);
        }
    }
    #[test] fn rejects_trailing_or_short_body() {
        let mut b=sample(StunClass::Request).encode().unwrap(); b.push(0);
        assert_eq!(StunMessage::decode(&b),Err(StunError::InvalidLength));
    }
    #[test] fn rejects_bad_cookie() {
        let mut b=sample(StunClass::Request).encode().unwrap(); b[4]=0;
        assert_eq!(StunMessage::decode(&b),Err(StunError::InvalidCookie));
    }
    #[test] fn xor_ipv4_round_trip() {
        let id=[7u8;12]; let a="192.0.2.10:3478".parse().unwrap();
        let v=encode_xor_address(ATTR_XOR_MAPPED_ADDRESS,a,&id);
        assert_eq!(decode_xor_address(&v,&id).unwrap(),a);
    }
    #[test] fn xor_ipv6_round_trip() {
        let id=[9u8;12]; let a="[2001:db8::1]:5349".parse().unwrap();
        let v=encode_xor_address(ATTR_XOR_MAPPED_ADDRESS,a,&id);
        assert_eq!(decode_xor_address(&v,&id).unwrap(),a);
    }
}
