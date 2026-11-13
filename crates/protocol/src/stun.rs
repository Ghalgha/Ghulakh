//! Bounded STUN message codec used by the TURN control plane.
//!
//! This module deliberately handles framing and address attributes only.
//! STUN framing, address attributes, integrity and fingerprint primitives.
//! TURN authentication-key derivation and allocation state remain separate.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use zeroize::{Zeroize, Zeroizing};

pub const HEADER_LEN: usize = 20;
pub const MAGIC_COOKIE: u32 = 0x2112_A442;
pub const MAX_MESSAGE_LEN: usize = HEADER_LEN + u16::MAX as usize;

pub const ATTR_USERNAME: u16 = 0x0006;
pub const ATTR_MESSAGE_INTEGRITY: u16 = 0x0008;
pub const ATTR_MESSAGE_INTEGRITY_SHA256: u16 = 0x001C;
pub const ATTR_PASSWORD_ALGORITHM: u16 = 0x001D;
pub const ATTR_PASSWORD_ALGORITHMS: u16 = 0x8002;
pub const ATTR_ERROR_CODE: u16 = 0x0009;
pub const ATTR_CHANNEL_NUMBER: u16 = 0x000C;
pub const ATTR_LIFETIME: u16 = 0x000D;
pub const ATTR_XOR_PEER_ADDRESS: u16 = 0x0012;
pub const ATTR_DATA: u16 = 0x0013;
pub const ATTR_REALM: u16 = 0x0014;
pub const ATTR_NONCE: u16 = 0x0015;
pub const ATTR_XOR_RELAYED_ADDRESS: u16 = 0x0016;
pub const ATTR_REQUESTED_ADDRESS_FAMILY: u16 = 0x0017;
pub const ATTR_REQUESTED_TRANSPORT: u16 = 0x0019;
pub const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;
pub const ATTR_FINGERPRINT: u16 = 0x8028;

pub const METHOD_ALLOCATE: u16 = 0x003;
pub const METHOD_REFRESH: u16 = 0x004;
pub const METHOD_SEND: u16 = 0x006;
pub const METHOD_DATA: u16 = 0x007;
pub const METHOD_CREATE_PERMISSION: u16 = 0x008;
pub const METHOD_CHANNEL_BIND: u16 = 0x009;

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
    InvalidIntegrityLayout,
    InvalidIntegrityKey,
    IntegrityMismatch,
    InvalidSha256IntegrityLayout,
    Sha256IntegrityMismatch,
    InvalidFingerprintLayout,
    FingerprintMismatch,
}

impl std::fmt::Display for StunError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "STUN codec error: {self:?}")
    }
}
impl std::error::Error for StunError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StunClass {
    Request,
    Indication,
    SuccessResponse,
    ErrorResponse,
}

#[derive(Clone, PartialEq, Eq)]
pub struct StunAttribute {
    pub kind: u16,
    pub value: Vec<u8>,
}

impl std::fmt::Debug for StunAttribute {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("StunAttribute")
            .field("kind", &self.kind)
            .field("value_len", &self.value.len())
            .field("value", &"<redacted>")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct StunMessage {
    pub method: u16,
    pub class: StunClass,
    pub transaction_id: [u8; 12],
    pub attributes: Vec<StunAttribute>,
}

impl std::fmt::Debug for StunMessage {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("StunMessage")
            .field("method", &self.method)
            .field("class", &self.class)
            .field("transaction_id", &self.transaction_id)
            .field("attributes", &self.attributes)
            .finish()
    }
}

struct SensitiveAttributes(Vec<StunAttribute>);

impl Drop for SensitiveAttributes {
    fn drop(&mut self) {
        for attribute in &mut self.0 {
            attribute.value.zeroize();
        }
    }
}

impl Drop for StunMessage {
    fn drop(&mut self) {
        for attribute in &mut self.attributes {
            attribute.value.zeroize();
        }
        self.transaction_id.zeroize();
    }
}

impl StunMessage {
    pub fn decode(input: &[u8]) -> Result<Self, StunError> {
        if input.len() < HEADER_LEN {
            return Err(StunError::Truncated);
        }
        if input.len() > MAX_MESSAGE_LEN {
            return Err(StunError::MessageTooLarge);
        }
        let ty = u16::from_be_bytes([input[0], input[1]]);
        if ty & 0xC000 != 0 {
            return Err(StunError::InvalidType);
        }
        let body_len = usize::from(u16::from_be_bytes([input[2], input[3]]));
        if body_len % 4 != 0 || body_len + HEADER_LEN != input.len() {
            return Err(StunError::InvalidLength);
        }
        if u32::from_be_bytes(input[4..8].try_into().unwrap()) != MAGIC_COOKIE {
            return Err(StunError::InvalidCookie);
        }
        let mut transaction_id = [0u8; 12];
        transaction_id.copy_from_slice(&input[8..20]);
        let mut attributes = SensitiveAttributes(Vec::new());
        let mut offset = HEADER_LEN;
        while offset < input.len() {
            if input.len() - offset < 4 {
                return Err(StunError::Truncated);
            }
            let kind = u16::from_be_bytes([input[offset], input[offset + 1]]);
            let len = usize::from(u16::from_be_bytes([input[offset + 2], input[offset + 3]]));
            let value_start = offset + 4;
            let value_end = value_start
                .checked_add(len)
                .ok_or(StunError::InvalidLength)?;
            let padded_end = value_start
                .checked_add((len + 3) & !3)
                .ok_or(StunError::InvalidLength)?;
            if padded_end > input.len() || value_end > input.len() {
                return Err(StunError::Truncated);
            }
            attributes.0.push(StunAttribute {
                kind,
                value: input[value_start..value_end].to_vec(),
            });
            offset = padded_end;
        }
        let method = (ty & 0x000F) | ((ty & 0x00E0) >> 1) | ((ty & 0x3E00) >> 2);
        let class = match ((ty >> 4) & 1) | ((ty >> 7) & 2) {
            0 => StunClass::Request,
            1 => StunClass::Indication,
            2 => StunClass::SuccessResponse,
            _ => StunClass::ErrorResponse,
        };
        Ok(Self {
            method,
            class,
            transaction_id,
            attributes: std::mem::take(&mut attributes.0),
        })
    }

    pub fn encode(&self) -> Result<Vec<u8>, StunError> {
        if self.method > 0x0FFF {
            return Err(StunError::InvalidType);
        }
        let mut body = Zeroizing::new(Vec::new());
        for attr in &self.attributes {
            if attr.value.len() > u16::MAX as usize {
                return Err(StunError::AttributeTooLarge);
            }
            body.extend_from_slice(&attr.kind.to_be_bytes());
            body.extend_from_slice(&(attr.value.len() as u16).to_be_bytes());
            body.extend_from_slice(&attr.value);
            let padding = (4 - attr.value.len() % 4) % 4;
            let new_len = body.len() + padding;
            body.resize(new_len, 0);
        }
        if body.len() > u16::MAX as usize {
            return Err(StunError::MessageTooLarge);
        }
        let method = self.method;
        let class = match self.class {
            StunClass::Request => 0,
            StunClass::Indication => 1,
            StunClass::SuccessResponse => 2,
            StunClass::ErrorResponse => 3,
        };
        let ty = (method & 0x000F)
            | ((method & 0x0070) << 1)
            | ((method & 0x0F80) << 2)
            | ((class & 1) << 4)
            | ((class & 2) << 7);
        let mut out = Vec::with_capacity(HEADER_LEN + body.len());
        out.extend_from_slice(&ty.to_be_bytes());
        out.extend_from_slice(&(body.len() as u16).to_be_bytes());
        out.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        out.extend_from_slice(&self.transaction_id);
        out.extend_from_slice(&body);
        Ok(out)
    }

    pub fn attribute(&self, kind: u16) -> Option<&[u8]> {
        self.attributes
            .iter()
            .find(|a| a.kind == kind)
            .map(|a| a.value.as_slice())
    }
}

/// Append RFC 5389 MESSAGE-INTEGRITY (HMAC-SHA1) as the final attribute.
/// The caller supplies the already-derived long-term key; credential derivation
/// is intentionally kept outside this codec.
pub fn append_message_integrity(message: &StunMessage, key: &[u8]) -> Result<Vec<u8>, StunError> {
    use hmac::{Hmac, Mac};
    use sha1::Sha1;

    if key.is_empty()
        || message
            .attributes
            .iter()
            .any(|a| a.kind == ATTR_MESSAGE_INTEGRITY || a.kind == ATTR_FINGERPRINT)
    {
        return Err(StunError::InvalidIntegrityLayout);
    }
    let mut signed = message.clone();
    signed.attributes.push(StunAttribute {
        kind: ATTR_MESSAGE_INTEGRITY,
        value: vec![0; 20],
    });
    let mut encoded = Zeroizing::new(signed.encode()?);
    let attr_offset = encoded.len() - 24;
    let mut mac = Hmac::<Sha1>::new_from_slice(key).map_err(|_| StunError::InvalidIntegrityKey)?;
    mac.update(&encoded[..attr_offset]);
    let tag = mac.finalize().into_bytes();
    encoded[attr_offset + 4..attr_offset + 24].copy_from_slice(&tag);
    Ok(std::mem::take(&mut *encoded))
}

/// Verify MESSAGE-INTEGRITY before any received request can mutate TURN state.
pub fn verify_message_integrity(input: &[u8], key: &[u8]) -> Result<(), StunError> {
    use hmac::{Hmac, Mac};
    use sha1::Sha1;

    let message = StunMessage::decode(input)?;
    let positions: Vec<usize> = message
        .attributes
        .iter()
        .enumerate()
        .filter_map(|(i, a)| (a.kind == ATTR_MESSAGE_INTEGRITY).then_some(i))
        .collect();
    if positions.len() != 1 || key.is_empty() {
        return Err(StunError::InvalidIntegrityLayout);
    }
    let attr_index = positions[0];
    let trailing = &message.attributes[attr_index + 1..];
    let trailing_len = match trailing {
        [] => 0,
        [fingerprint] if fingerprint.kind == ATTR_FINGERPRINT => 8,
        [sha256] if sha256.kind == ATTR_MESSAGE_INTEGRITY_SHA256 && sha256.value.len() == 32 => 36,
        [sha256, fingerprint]
            if sha256.kind == ATTR_MESSAGE_INTEGRITY_SHA256
                && sha256.value.len() == 32
                && fingerprint.kind == ATTR_FINGERPRINT =>
        {
            44
        }
        _ => return Err(StunError::InvalidIntegrityLayout),
    };
    let offset = HEADER_LEN
        + message.attributes[..attr_index]
            .iter()
            .map(|a| 4 + ((a.value.len() + 3) & !3))
            .sum::<usize>();
    let expected_len = offset + 24 + trailing_len;
    if input.len() != expected_len {
        return Err(StunError::InvalidIntegrityLayout);
    }
    // RFC 5389 requires the header length used for HMAC to end at MESSAGE-INTEGRITY,
    // even when a FINGERPRINT attribute follows it in the wire message.
    let mut signed_prefix = Zeroizing::new(input[..offset].to_vec());
    let integrity_end_body_len =
        u16::try_from(offset + 24 - HEADER_LEN).map_err(|_| StunError::InvalidLength)?;
    signed_prefix[2..4].copy_from_slice(&integrity_end_body_len.to_be_bytes());
    let mut mac = Hmac::<Sha1>::new_from_slice(key).map_err(|_| StunError::InvalidIntegrityKey)?;
    mac.update(&signed_prefix);
    mac.verify_slice(&input[offset + 4..offset + 24])
        .map_err(|_| StunError::IntegrityMismatch)
}

/// Append RFC 8489 MESSAGE-INTEGRITY-SHA256 using a caller-supplied key.
/// The full 32-byte HMAC is emitted; password/key derivation is external.
pub fn append_message_integrity_sha256(
    message: &StunMessage,
    key: &[u8],
) -> Result<Vec<u8>, StunError> {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    if key.is_empty()
        || message
            .attributes
            .iter()
            .any(|a| a.kind == ATTR_MESSAGE_INTEGRITY_SHA256 || a.kind == ATTR_FINGERPRINT)
    {
        return Err(StunError::InvalidSha256IntegrityLayout);
    }
    let mut signed = message.clone();
    signed.attributes.push(StunAttribute {
        kind: ATTR_MESSAGE_INTEGRITY_SHA256,
        value: vec![0; 32],
    });
    let mut encoded = Zeroizing::new(signed.encode()?);
    let attr_offset = encoded.len() - 36;
    let mut mac =
        Hmac::<Sha256>::new_from_slice(key).map_err(|_| StunError::InvalidIntegrityKey)?;
    mac.update(&encoded[..attr_offset]);
    let tag = mac.finalize().into_bytes();
    encoded[attr_offset + 4..attr_offset + 36].copy_from_slice(&tag);
    Ok(std::mem::take(&mut *encoded))
}

/// Verify a full-length RFC 8489 MESSAGE-INTEGRITY-SHA256 attribute.
/// A final FINGERPRINT is permitted; this is authentication only when the
/// caller has independently selected the correct credential and key profile.
pub fn verify_message_integrity_sha256(input: &[u8], key: &[u8]) -> Result<(), StunError> {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    let message = StunMessage::decode(input)?;
    let positions: Vec<usize> = message
        .attributes
        .iter()
        .enumerate()
        .filter_map(|(i, a)| (a.kind == ATTR_MESSAGE_INTEGRITY_SHA256).then_some(i))
        .collect();
    if positions.len() != 1 || key.is_empty() {
        return Err(StunError::InvalidSha256IntegrityLayout);
    }
    let index = positions[0];
    if message.attributes[index].value.len() != 32 {
        return Err(StunError::InvalidSha256IntegrityLayout);
    }
    let trailing = &message.attributes[index + 1..];
    if !(trailing.is_empty() || (trailing.len() == 1 && trailing[0].kind == ATTR_FINGERPRINT)) {
        return Err(StunError::InvalidSha256IntegrityLayout);
    }
    let offset = HEADER_LEN
        + message.attributes[..index]
            .iter()
            .map(|a| 4 + ((a.value.len() + 3) & !3))
            .sum::<usize>();
    let expected_len = offset + 36 + if trailing.is_empty() { 0 } else { 8 };
    if input.len() != expected_len {
        return Err(StunError::InvalidSha256IntegrityLayout);
    }
    let mut signed_prefix = Zeroizing::new(input[..offset].to_vec());
    let adjusted_len =
        u16::try_from(offset + 36 - HEADER_LEN).map_err(|_| StunError::InvalidLength)?;
    signed_prefix[2..4].copy_from_slice(&adjusted_len.to_be_bytes());
    let mut mac =
        Hmac::<Sha256>::new_from_slice(key).map_err(|_| StunError::InvalidIntegrityKey)?;
    mac.update(&signed_prefix);
    mac.verify_slice(&input[offset + 4..offset + 36])
        .map_err(|_| StunError::Sha256IntegrityMismatch)
}

/// Append the STUN FINGERPRINT attribute (CRC-32 XOR 0x5354554e).
pub fn append_fingerprint(input: &[u8]) -> Result<Vec<u8>, StunError> {
    let message = StunMessage::decode(input)?;
    if message
        .attributes
        .iter()
        .any(|a| a.kind == ATTR_FINGERPRINT)
    {
        return Err(StunError::InvalidFingerprintLayout);
    }
    let mut out = Zeroizing::new(input.to_vec());
    let new_len = out.len().checked_add(8).ok_or(StunError::MessageTooLarge)?;
    if new_len > MAX_MESSAGE_LEN {
        return Err(StunError::MessageTooLarge);
    }
    let body_len = u16::try_from(new_len - HEADER_LEN).map_err(|_| StunError::MessageTooLarge)?;
    out[2..4].copy_from_slice(&body_len.to_be_bytes());
    let crc = crc32fast::hash(&out) ^ 0x5354_554e;
    out.extend_from_slice(&ATTR_FINGERPRINT.to_be_bytes());
    out.extend_from_slice(&4u16.to_be_bytes());
    out.extend_from_slice(&crc.to_be_bytes());
    Ok(std::mem::take(&mut *out))
}

/// Verify a final FINGERPRINT attribute. This is corruption detection, not authentication.
pub fn verify_fingerprint(input: &[u8]) -> Result<(), StunError> {
    let message = StunMessage::decode(input)?;
    if message.attributes.last().map(|a| a.kind) != Some(ATTR_FINGERPRINT) {
        return Err(StunError::InvalidFingerprintLayout);
    }
    let offset = input
        .len()
        .checked_sub(8)
        .ok_or(StunError::InvalidFingerprintLayout)?;
    if input[offset + 2..offset + 4] != [0, 4] {
        return Err(StunError::InvalidFingerprintLayout);
    }
    let expected = u32::from_be_bytes(input[offset + 4..offset + 8].try_into().unwrap());
    let actual = crc32fast::hash(&input[..offset]) ^ 0x5354_554e;
    if actual != expected {
        return Err(StunError::FingerprintMismatch);
    }
    Ok(())
}
pub fn encode_xor_address(address: SocketAddr, transaction_id: &[u8; 12]) -> Vec<u8> {
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
            out.extend(ip.octets().iter().zip(mask.iter()).map(|(a, b)| a ^ b));
        }
    }
    out
}

pub fn decode_xor_address(
    value: &[u8],
    transaction_id: &[u8; 12],
) -> Result<SocketAddr, StunError> {
    if value.len() < 4 || value[0] != 0 {
        return Err(StunError::InvalidAddress);
    }
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
            for i in 0..16 {
                raw[i] = value[4 + i] ^ mask[i];
            }
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
        StunMessage {
            method: 0x003,
            class,
            transaction_id: [0x42; 12],
            attributes: vec![
                StunAttribute {
                    kind: ATTR_LIFETIME,
                    value: 600u32.to_be_bytes().to_vec(),
                },
                StunAttribute {
                    kind: 0xC001,
                    value: vec![1, 2, 3],
                },
            ],
        }
    }
    #[test]
    fn debug_output_redacts_attribute_values() {
        let mut message = sample(StunClass::Request);
        message.attributes.push(StunAttribute {
            kind: ATTR_USERNAME,
            value: b"credential-secret-marker".to_vec(),
        });
        let rendered = format!("{message:?}");
        assert!(!rendered.contains("credential-secret-marker"));
        assert!(rendered.contains("<redacted>"));
    }

    #[test]
    fn message_integrity_round_trip_and_tamper_detection() {
        let m = sample(StunClass::Request);
        let encoded = append_message_integrity(&m, b"test-key").unwrap();
        verify_message_integrity(&encoded, b"test-key").unwrap();
        let with_fingerprint = append_fingerprint(&encoded).unwrap();
        verify_message_integrity(&with_fingerprint, b"test-key").unwrap();
        verify_fingerprint(&with_fingerprint).unwrap();
        let mut tampered = encoded;
        tampered[HEADER_LEN] ^= 1;
        assert_eq!(
            verify_message_integrity(&tampered, b"test-key"),
            Err(StunError::IntegrityMismatch)
        );
    }
    #[test]
    fn message_integrity_sha256_round_trip_and_tamper_detection() {
        let m = sample(StunClass::Request);
        let sha1_then_sha256 = append_message_integrity(&m, b"test-key").unwrap();
        let encoded = append_message_integrity_sha256(
            &StunMessage::decode(&sha1_then_sha256).unwrap(),
            b"test-key",
        )
        .unwrap();
        verify_message_integrity(&encoded, b"test-key").unwrap();
        verify_message_integrity_sha256(&encoded, b"test-key").unwrap();
        let with_fingerprint = append_fingerprint(&encoded).unwrap();
        verify_message_integrity_sha256(&with_fingerprint, b"test-key").unwrap();
        verify_fingerprint(&with_fingerprint).unwrap();
        let mut tampered = encoded;
        tampered[HEADER_LEN] ^= 1;
        assert_eq!(
            verify_message_integrity_sha256(&tampered, b"test-key"),
            Err(StunError::Sha256IntegrityMismatch)
        );
    }

    #[test]
    fn rejects_truncated_sha256_integrity() {
        let mut message = sample(StunClass::Request);
        message.attributes.push(StunAttribute {
            kind: ATTR_MESSAGE_INTEGRITY_SHA256,
            value: vec![0; 16],
        });
        let encoded = message.encode().unwrap();
        assert_eq!(
            verify_message_integrity_sha256(&encoded, b"test-key"),
            Err(StunError::InvalidSha256IntegrityLayout)
        );
    }

    #[test]
    fn fingerprint_round_trip_and_tamper_detection() {
        let encoded = sample(StunClass::Request).encode().unwrap();
        let encoded = append_fingerprint(&encoded).unwrap();
        verify_fingerprint(&encoded).unwrap();
        let mut tampered = encoded;
        tampered[HEADER_LEN] ^= 1;
        assert_eq!(
            verify_fingerprint(&tampered),
            Err(StunError::FingerprintMismatch)
        );
    }
    #[test]
    fn message_round_trip_all_classes() {
        for class in [
            StunClass::Request,
            StunClass::Indication,
            StunClass::SuccessResponse,
            StunClass::ErrorResponse,
        ] {
            let m = sample(class);
            assert_eq!(StunMessage::decode(&m.encode().unwrap()).unwrap(), m);
        }
    }
    #[test]
    fn method_high_bits_round_trip() {
        let mut m = sample(StunClass::Request);
        m.method = METHOD_CHANNEL_BIND;
        assert_eq!(StunMessage::decode(&m.encode().unwrap()).unwrap(), m);
    }
    #[test]
    fn rejects_truncated_attribute_value() {
        let mut b = sample(StunClass::Request).encode().unwrap();
        let last = b.len() - 1;
        b[last] = 0;
        b[HEADER_LEN + 2..HEADER_LEN + 4].copy_from_slice(&u16::MAX.to_be_bytes());
        assert_eq!(StunMessage::decode(&b), Err(StunError::Truncated));
    }
    #[test]
    fn rejects_trailing_or_short_body() {
        let mut b = sample(StunClass::Request).encode().unwrap();
        b.push(0);
        assert_eq!(StunMessage::decode(&b), Err(StunError::InvalidLength));
    }
    #[test]
    fn rejects_bad_cookie() {
        let mut b = sample(StunClass::Request).encode().unwrap();
        b[4] = 0;
        assert_eq!(StunMessage::decode(&b), Err(StunError::InvalidCookie));
    }
    #[test]
    fn xor_ipv4_round_trip() {
        let id = [7u8; 12];
        let a = "192.0.2.10:3478".parse().unwrap();
        let v = encode_xor_address(a, &id);
        assert_eq!(decode_xor_address(&v, &id).unwrap(), a);
    }
    #[test]
    fn xor_ipv6_round_trip() {
        let id = [9u8; 12];
        let a = "[2001:db8::1]:5349".parse().unwrap();
        let v = encode_xor_address(a, &id);
        assert_eq!(decode_xor_address(&v, &id).unwrap(), a);
    }
}

#[cfg(test)]
mod deterministic_property_tests {
    use super::*;

    #[test]
    fn xor_address_round_trips_for_ipv4_ipv6_and_boundary_ports() {
        let ids = [
            [0u8; 12],
            [0x5a; 12],
            core::array::from_fn(|i| (i * 17) as u8),
        ];
        let addresses: Vec<SocketAddr> = [
            "0.0.0.0:0",
            "255.255.255.255:65535",
            "192.0.2.1:3478",
            "198.51.100.255:5349",
            "[::]:0",
            "[ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff]:65535",
            "[2001:db8::1]:3478",
            "[2001:db8:ffff::abcd]:5349",
        ]
        .into_iter()
        .map(|value| value.parse().unwrap())
        .collect();

        for address in addresses {
            for transaction_id in &ids {
                let encoded = encode_xor_address(address, transaction_id);
                assert_eq!(
                    decode_xor_address(&encoded, transaction_id).unwrap(),
                    address
                );
            }
        }
    }

    #[test]
    fn stun_attribute_payload_lengths_round_trip_with_alignment_padding() {
        for length in 0usize..=1024 {
            let payload: Vec<u8> = (0..length)
                .map(|index| (index.wrapping_mul(31) & 0xff) as u8)
                .collect();
            let message = StunMessage {
                method: METHOD_ALLOCATE,
                class: StunClass::Request,
                transaction_id: [length as u8; 12],
                attributes: vec![StunAttribute {
                    kind: 0xC123,
                    value: payload,
                }],
            };
            let encoded = message.encode().unwrap();
            let decoded = StunMessage::decode(&encoded).unwrap();
            assert_eq!(decoded, message, "attribute payload length {length}");
        }
    }

    #[test]
    fn message_decoder_rejects_every_truncation_of_a_valid_encoded_message() {
        let message = StunMessage {
            method: METHOD_CHANNEL_BIND,
            class: StunClass::Request,
            transaction_id: [0xA7; 12],
            attributes: vec![
                StunAttribute {
                    kind: ATTR_LIFETIME,
                    value: 600u32.to_be_bytes().to_vec(),
                },
                StunAttribute {
                    kind: 0xC123,
                    value: vec![0x5a; 17],
                },
            ],
        };
        let encoded = message.encode().unwrap();
        for end in 0..encoded.len() {
            assert!(
                StunMessage::decode(&encoded[..end]).is_err(),
                "truncated message unexpectedly decoded at length {end}"
            );
        }
        assert_eq!(StunMessage::decode(&encoded).unwrap(), message);
    }
}

#[cfg(test)]
mod arbitrary_input_property_tests {
    use super::*;

    proptest::proptest! {
        #[test]
        fn arbitrary_input_never_panics(raw in proptest::collection::vec(
            proptest::prelude::any::<u8>(),
            0..=2048
        )) {
            let _ = StunMessage::decode(&raw);
        }
    }
}
