//! Bounded, replay-safe envelope primitives for carrying the Noise handshake
//! over TURN datagrams. This module does not schedule retransmissions or own
//! Noise state; the driver must resend the exact encoded message on timeout.

use sha2::{Digest, Sha256};
use std::collections::VecDeque;
use thiserror::Error;

const MAGIC: &[u8; 4] = b"GHHS";
pub const HANDSHAKE_ENVELOPE_VERSION: u8 = 1;
pub const HANDSHAKE_HEADER_LEN: usize = 26;
pub const MAX_HANDSHAKE_PAYLOAD: usize = 1024;
pub const MAX_HANDSHAKE_DATAGRAM: usize = HANDSHAKE_HEADER_LEN + MAX_HANDSHAKE_PAYLOAD;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum HandshakePhase {
    ClientInit = 1,
    ServerResponse = 2,
    ClientFinish = 3,
    ServerAck = 4,
}

impl TryFrom<u8> for HandshakePhase {
    type Error = HandshakeEnvelopeError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::ClientInit),
            2 => Ok(Self::ServerResponse),
            3 => Ok(Self::ClientFinish),
            4 => Ok(Self::ServerAck),
            _ => Err(HandshakeEnvelopeError::InvalidPhase),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandshakeEnvelope {
    pub phase: HandshakePhase,
    pub handshake_id: [u8; 16],
    pub payload: Vec<u8>,
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeEnvelopeError {
    #[error("handshake datagram is too short or has an invalid length")]
    InvalidLength,
    #[error("handshake datagram exceeds the configured limit")]
    TooLarge,
    #[error("handshake datagram magic is invalid")]
    InvalidMagic,
    #[error("handshake envelope version is unsupported")]
    UnsupportedVersion,
    #[error("handshake phase is invalid")]
    InvalidPhase,
    #[error("reserved handshake envelope flags are non-zero")]
    ReservedFlags,
    #[error("handshake identifier must not be all zeroes")]
    InvalidHandshakeId,
    #[error("handshake payload must not be empty")]
    EmptyPayload,
}

impl HandshakeEnvelope {
    pub fn encode(&self) -> Result<Vec<u8>, HandshakeEnvelopeError> {
        if self.handshake_id.iter().all(|byte| *byte == 0) {
            return Err(HandshakeEnvelopeError::InvalidHandshakeId);
        }
        if self.payload.is_empty() {
            return Err(HandshakeEnvelopeError::EmptyPayload);
        }
        if self.payload.len() > MAX_HANDSHAKE_PAYLOAD {
            return Err(HandshakeEnvelopeError::TooLarge);
        }
        let payload_len = u16::try_from(self.payload.len())
            .map_err(|_| HandshakeEnvelopeError::TooLarge)?;
        let mut encoded = Vec::with_capacity(HANDSHAKE_HEADER_LEN + self.payload.len());
        encoded.extend_from_slice(MAGIC);
        encoded.push(HANDSHAKE_ENVELOPE_VERSION);
        encoded.push(self.phase as u8);
        encoded.extend_from_slice(&0u16.to_be_bytes());
        encoded.extend_from_slice(&self.handshake_id);
        encoded.extend_from_slice(&payload_len.to_be_bytes());
        encoded.extend_from_slice(&self.payload);
        Ok(encoded)
    }

    pub fn decode(encoded: &[u8]) -> Result<Self, HandshakeEnvelopeError> {
        if encoded.len() > MAX_HANDSHAKE_DATAGRAM {
            return Err(HandshakeEnvelopeError::TooLarge);
        }
        if encoded.len() < HANDSHAKE_HEADER_LEN {
            return Err(HandshakeEnvelopeError::InvalidLength);
        }
        if &encoded[..4] != MAGIC {
            return Err(HandshakeEnvelopeError::InvalidMagic);
        }
        if encoded[4] != HANDSHAKE_ENVELOPE_VERSION {
            return Err(HandshakeEnvelopeError::UnsupportedVersion);
        }
        let phase = HandshakePhase::try_from(encoded[5])?;
        if encoded[6] != 0 || encoded[7] != 0 {
            return Err(HandshakeEnvelopeError::ReservedFlags);
        }
        let mut handshake_id = [0u8; 16];
        handshake_id.copy_from_slice(&encoded[8..24]);
        if handshake_id.iter().all(|byte| *byte == 0) {
            return Err(HandshakeEnvelopeError::InvalidHandshakeId);
        }
        let payload_len = usize::from(u16::from_be_bytes([encoded[24], encoded[25]]));
        if payload_len == 0 {
            return Err(HandshakeEnvelopeError::EmptyPayload);
        }
        if payload_len > MAX_HANDSHAKE_PAYLOAD {
            return Err(HandshakeEnvelopeError::TooLarge);
        }
        if encoded.len() != HANDSHAKE_HEADER_LEN + payload_len {
            return Err(HandshakeEnvelopeError::InvalidLength);
        }
        Ok(Self {
            phase,
            handshake_id,
            payload: encoded[HANDSHAKE_HEADER_LEN..].to_vec(),
        })
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeReplayCacheError {
    #[error("handshake transaction identifier and phase were reused with different bytes")]
    TransactionConflict,
    #[error("handshake replay cache capacity must be non-zero")]
    ZeroCapacity,
}

struct CacheEntry {
    handshake_id: [u8; 16],
    phase: HandshakePhase,
    request_digest: [u8; 32],
    response: Vec<u8>,
}

/// Bounded exact-response cache. A duplicate request receives the original
/// response bytes; a different request reusing the same transaction key fails.
/// Expiration and per-source admission limits belong to the network driver.
pub struct HandshakeResponseCache {
    capacity: usize,
    entries: VecDeque<CacheEntry>,
}

impl HandshakeResponseCache {
    pub fn new(capacity: usize) -> Result<Self, HandshakeReplayCacheError> {
        if capacity == 0 {
            return Err(HandshakeReplayCacheError::ZeroCapacity);
        }
        Ok(Self {
            capacity,
            entries: VecDeque::with_capacity(capacity),
        })
    }

    pub fn get(
        &self,
        handshake_id: &[u8; 16],
        phase: HandshakePhase,
        request: &[u8],
    ) -> Result<Option<&[u8]>, HandshakeReplayCacheError> {
        let digest: [u8; 32] = Sha256::digest(request).into();
        let Some(entry) = self.entries.iter().find(|entry| {
            entry.handshake_id == *handshake_id && entry.phase == phase
        }) else {
            return Ok(None);
        };
        if entry.request_digest != digest {
            return Err(HandshakeReplayCacheError::TransactionConflict);
        }
        Ok(Some(entry.response.as_slice()))
    }

    pub fn insert(
        &mut self,
        handshake_id: [u8; 16],
        phase: HandshakePhase,
        request: &[u8],
        response: &[u8],
    ) -> Result<(), HandshakeReplayCacheError> {
        let digest: [u8; 32] = Sha256::digest(request).into();
        if let Some(entry) = self.entries.iter().find(|entry| {
            entry.handshake_id == handshake_id && entry.phase == phase
        }) {
            if entry.request_digest == digest && entry.response == response {
                return Ok(());
            }
            return Err(HandshakeReplayCacheError::TransactionConflict);
        }
        if self.entries.len() == self.capacity {
            self.entries.pop_front();
        }
        self.entries.push_back(CacheEntry {
            handshake_id,
            phase,
            request_digest: digest,
            response: response.to_vec(),
        });
        Ok(())
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> HandshakeEnvelope {
        HandshakeEnvelope {
            phase: HandshakePhase::ClientFinish,
            handshake_id: [7; 16],
            payload: vec![1, 2, 3, 4, 5],
        }
    }

    #[test]
    fn envelope_round_trip() {
        let message = sample();
        assert_eq!(HandshakeEnvelope::decode(&message.encode().unwrap()).unwrap(), message);
    }

    #[test]
    fn rejects_trailing_and_truncated_bytes() {
        let mut encoded = sample().encode().unwrap();
        encoded.push(0);
        assert_eq!(HandshakeEnvelope::decode(&encoded), Err(HandshakeEnvelopeError::InvalidLength));
        encoded.pop();
        encoded.pop();
        assert_eq!(HandshakeEnvelope::decode(&encoded), Err(HandshakeEnvelopeError::InvalidLength));
    }

    #[test]
    fn rejects_reserved_flags_and_zero_identifier() {
        let mut encoded = sample().encode().unwrap();
        encoded[7] = 1;
        assert_eq!(HandshakeEnvelope::decode(&encoded), Err(HandshakeEnvelopeError::ReservedFlags));
        let mut encoded = sample().encode().unwrap();
        encoded[8..24].fill(0);
        assert_eq!(HandshakeEnvelope::decode(&encoded), Err(HandshakeEnvelopeError::InvalidHandshakeId));
    }

    #[test]
    fn rejects_oversized_payload_before_allocation() {
        let mut encoded = vec![0; HANDSHAKE_HEADER_LEN];
        encoded[..4].copy_from_slice(MAGIC);
        encoded[4] = HANDSHAKE_ENVELOPE_VERSION;
        encoded[5] = HandshakePhase::ClientInit as u8;
        encoded[8..24].fill(1);
        encoded[24..26].copy_from_slice(&((MAX_HANDSHAKE_PAYLOAD + 1) as u16).to_be_bytes());
        assert_eq!(HandshakeEnvelope::decode(&encoded), Err(HandshakeEnvelopeError::TooLarge));
    }

    #[test]
    fn duplicate_request_returns_exact_cached_response() {
        let mut cache = HandshakeResponseCache::new(2).unwrap();
        let id = [3; 16];
        cache.insert(id, HandshakePhase::ClientInit, b"hello", b"server-response").unwrap();
        assert_eq!(
            cache.get(&id, HandshakePhase::ClientInit, b"hello").unwrap(),
            Some(b"server-response".as_slice())
        );
        assert_eq!(
            cache.insert(id, HandshakePhase::ClientInit, b"hello", b"server-response"),
            Ok(())
        );
    }

    #[test]
    fn reused_transaction_key_with_different_request_is_rejected() {
        let mut cache = HandshakeResponseCache::new(2).unwrap();
        let id = [4; 16];
        cache.insert(id, HandshakePhase::ClientInit, b"first", b"response").unwrap();
        assert_eq!(
            cache.get(&id, HandshakePhase::ClientInit, b"second"),
            Err(HandshakeReplayCacheError::TransactionConflict)
        );
        assert_eq!(
            cache.insert(id, HandshakePhase::ClientInit, b"second", b"other"),
            Err(HandshakeReplayCacheError::TransactionConflict)
        );
    }

    #[test]
    fn cache_evicts_oldest_entry_at_capacity() {
        let mut cache = HandshakeResponseCache::new(1).unwrap();
        cache.insert([1; 16], HandshakePhase::ClientInit, b"a", b"ra").unwrap();
        cache.insert([2; 16], HandshakePhase::ClientInit, b"b", b"rb").unwrap();
        assert_eq!(cache.len(), 1);
        assert_eq!(cache.get(&[1; 16], HandshakePhase::ClientInit, b"a").unwrap(), None);
        assert_eq!(cache.get(&[2; 16], HandshakePhase::ClientInit, b"b").unwrap(), Some(b"rb".as_slice()));
    }

    #[test]
    fn rejects_zero_capacity() {
        assert_eq!(HandshakeResponseCache::new(0).err(), Some(HandshakeReplayCacheError::ZeroCapacity));
    }
}
