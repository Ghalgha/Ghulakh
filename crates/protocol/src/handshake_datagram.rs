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


use std::{
    collections::BTreeMap,
    net::SocketAddr,
    time::{Duration, Instant},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HandshakeRetryPolicy {
    pub initial_rto: Duration,
    pub max_rto: Duration,
    /// Includes the initial transmission.
    pub max_transmissions: u8,
}

impl Default for HandshakeRetryPolicy {
    fn default() -> Self {
        Self {
            initial_rto: Duration::from_millis(500),
            max_rto: Duration::from_secs(4),
            max_transmissions: 5,
        }
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeDriverError {
    #[error("handshake retry policy is invalid")]
    InvalidPolicy,
    #[error("maximum pending handshake count reached")]
    CapacityReached,
    #[error("per-peer pending handshake limit reached")]
    PeerLimitReached,
    #[error("handshake transaction already exists")]
    DuplicateTransaction,
    #[error("request and response phases do not form a valid pair")]
    InvalidPhasePair,
    #[error("response cache capacity or lifetime is invalid")]
    InvalidCachePolicy,
    #[error("cached transaction key conflicts with different bytes")]
    CacheConflict,
    #[error("handshake envelope is invalid")]
    InvalidEnvelope,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HandshakeDriverEvent {
    Retransmit {
        handshake_id: [u8; 16],
        phase: HandshakePhase,
        datagram: Vec<u8>,
        attempt: u8,
        destination: SocketAddr,
    },
    TimedOut {
        handshake_id: [u8; 16],
        phase: HandshakePhase,
        destination: SocketAddr,
    },
}

struct PendingHandshake {
    request_phase: HandshakePhase,
    response_phase: HandshakePhase,
    datagram: Vec<u8>,
    destination: SocketAddr,
    transmissions: u8,
    retry_interval: Duration,
    next_deadline: Instant,
}

struct CachedHandshakeResponse {
    source: SocketAddr,
    handshake_id: [u8; 16],
    request_phase: HandshakePhase,
    request_digest: [u8; 32],
    response_datagram: Vec<u8>,
    expires_at: Instant,
}

/// Deterministic stop-and-wait handshake delivery primitives. The caller owns
/// the socket and timer loop. Retransmissions are byte-for-byte copies of the
/// original envelope; no Noise state is advanced by this type.
pub struct HandshakeDatagramDriver {
    pending: BTreeMap<([u8; 16], u8, SocketAddr), PendingHandshake>,
    responses: VecDeque<CachedHandshakeResponse>,
    max_pending: usize,
    max_pending_per_peer: usize,
    max_cached_responses: usize,
    max_cached_per_peer: usize,
    response_ttl: Duration,
    retry_policy: HandshakeRetryPolicy,
}

impl HandshakeDatagramDriver {
    pub fn new(
        max_pending: usize,
        max_pending_per_peer: usize,
        max_cached_responses: usize,
        max_cached_per_peer: usize,
        response_ttl: Duration,
        retry_policy: HandshakeRetryPolicy,
    ) -> Result<Self, HandshakeDriverError> {
        if max_pending == 0
            || max_pending_per_peer == 0
            || max_pending_per_peer > max_pending
            || max_cached_responses == 0
            || max_cached_per_peer == 0
            || max_cached_per_peer > max_cached_responses
            || response_ttl.is_zero()
        {
            return Err(HandshakeDriverError::InvalidCachePolicy);
        }
        if retry_policy.initial_rto.is_zero()
            || retry_policy.max_rto < retry_policy.initial_rto
            || retry_policy.max_transmissions == 0
        {
            return Err(HandshakeDriverError::InvalidPolicy);
        }
        Ok(Self {
            pending: BTreeMap::new(),
            responses: VecDeque::with_capacity(max_cached_responses),
            max_pending,
            max_pending_per_peer,
            max_cached_responses,
            max_cached_per_peer,
            response_ttl,
            retry_policy,
        })
    }

    pub fn register_request(
        &mut self,
        datagram: Vec<u8>,
        destination: SocketAddr,
        expected_response: HandshakePhase,
        now: Instant,
    ) -> Result<[u8; 16], HandshakeDriverError> {
        let envelope = HandshakeEnvelope::decode(&datagram)
            .map_err(|_| HandshakeDriverError::InvalidEnvelope)?;
        let valid_pair = matches!(
            (envelope.phase, expected_response),
            (HandshakePhase::ClientInit, HandshakePhase::ServerResponse)
                | (HandshakePhase::ClientFinish, HandshakePhase::ServerAck)
        );
        if !valid_pair {
            return Err(HandshakeDriverError::InvalidPhasePair);
        }
        let key = (envelope.handshake_id, envelope.phase as u8, destination);
        if self.pending.contains_key(&key) {
            return Err(HandshakeDriverError::DuplicateTransaction);
        }
        if self.pending.len() >= self.max_pending {
            return Err(HandshakeDriverError::CapacityReached);
        }
        if self.pending.keys().filter(|(_, _, peer)| *peer == destination).count()
            >= self.max_pending_per_peer
        {
            return Err(HandshakeDriverError::PeerLimitReached);
        }
        self.pending.insert(key, PendingHandshake {
            request_phase: envelope.phase,
            response_phase: expected_response,
            datagram,
            destination,
            transmissions: 1,
            retry_interval: self.retry_policy.initial_rto,
            next_deadline: now + self.retry_policy.initial_rto,
        });
        Ok(envelope.handshake_id)
    }

    /// Returns only responses matching the exact peer, identifier and expected
    /// phase. The caller must still authenticate the Noise payload.
    pub fn accept_response(
        &mut self,
        datagram: &[u8],
        source: SocketAddr,
    ) -> Result<bool, HandshakeDriverError> {
        let envelope = HandshakeEnvelope::decode(datagram)
            .map_err(|_| HandshakeDriverError::InvalidEnvelope)?;
        let key = self.pending.iter().find_map(|(key, pending)| {
            (key.0 == envelope.handshake_id
                && pending.destination == source
                && pending.response_phase == envelope.phase)
                .then_some(*key)
        });
        Ok(key.is_some_and(|key| self.pending.remove(&key).is_some()))
    }

    pub fn poll(&mut self, now: Instant) -> Vec<HandshakeDriverEvent> {
        let due: Vec<_> = self.pending.iter()
            .filter_map(|(key, pending)| (now >= pending.next_deadline).then_some(*key))
            .collect();
        let mut events = Vec::with_capacity(due.len());
        for key in due {
            let Some(pending) = self.pending.get_mut(&key) else { continue };
            if pending.transmissions < self.retry_policy.max_transmissions {
                pending.transmissions += 1;
                events.push(HandshakeDriverEvent::Retransmit {
                    handshake_id: key.0,
                    phase: pending.request_phase,
                    datagram: pending.datagram.clone(),
                    attempt: pending.transmissions,
                    destination: pending.destination,
                });
                pending.retry_interval = pending.retry_interval.saturating_mul(2)
                    .min(self.retry_policy.max_rto);
                pending.next_deadline = now + pending.retry_interval;
            } else {
                events.push(HandshakeDriverEvent::TimedOut {
                    handshake_id: key.0,
                    phase: pending.request_phase,
                    destination: pending.destination,
                });
                self.pending.remove(&key);
            }
        }
        events
    }

    /// Store an exact response before sending it. Duplicate requests can then
    /// be answered without advancing a Noise handshake state a second time.
    pub fn cache_response(
        &mut self,
        request_datagram: &[u8],
        response_datagram: Vec<u8>,
        source: SocketAddr,
        now: Instant,
    ) -> Result<(), HandshakeDriverError> {
        self.prune_expired(now);
        let request = HandshakeEnvelope::decode(request_datagram)
            .map_err(|_| HandshakeDriverError::InvalidEnvelope)?;
        let response = HandshakeEnvelope::decode(&response_datagram)
            .map_err(|_| HandshakeDriverError::InvalidEnvelope)?;
        if request.handshake_id != response.handshake_id {
            return Err(HandshakeDriverError::InvalidPhasePair);
        }
        let expected_response = match request.phase {
            HandshakePhase::ClientInit => HandshakePhase::ServerResponse,
            HandshakePhase::ClientFinish => HandshakePhase::ServerAck,
            _ => return Err(HandshakeDriverError::InvalidPhasePair),
        };
        if response.phase != expected_response {
            return Err(HandshakeDriverError::InvalidPhasePair);
        }
        let digest: [u8; 32] = Sha256::digest(request_datagram).into();
        if let Some(entry) = self.responses.iter().find(|entry| {
            entry.source == source
                && entry.handshake_id == request.handshake_id
                && entry.request_phase == request.phase
        }) {
            if entry.request_digest == digest && entry.response_datagram == response_datagram {
                return Ok(());
            }
            return Err(HandshakeDriverError::CacheConflict);
        }
        if self.responses.len() >= self.max_cached_responses {
            self.responses.pop_front();
        }
        if self.responses.iter().filter(|entry| entry.source == source).count()
            >= self.max_cached_per_peer
        {
            if let Some(index) = self.responses.iter().position(|entry| entry.source == source) {
                self.responses.remove(index);
            }
        }
        self.responses.push_back(CachedHandshakeResponse {
            source,
            handshake_id: request.handshake_id,
            request_phase: request.phase,
            request_digest: digest,
            response_datagram,
            expires_at: now + self.response_ttl,
        });
        Ok(())
    }

    pub fn cached_response(
        &mut self,
        request_datagram: &[u8],
        source: SocketAddr,
        now: Instant,
    ) -> Result<Option<&[u8]>, HandshakeDriverError> {
        self.prune_expired(now);
        let request = HandshakeEnvelope::decode(request_datagram)
            .map_err(|_| HandshakeDriverError::InvalidEnvelope)?;
        let digest: [u8; 32] = Sha256::digest(request_datagram).into();
        let Some(entry) = self.responses.iter().find(|entry| {
            entry.source == source
                && entry.handshake_id == request.handshake_id
                && entry.request_phase == request.phase
        }) else {
            return Ok(None);
        };
        if entry.request_digest != digest {
            return Err(HandshakeDriverError::CacheConflict);
        }
        Ok(Some(entry.response_datagram.as_slice()))
    }

    pub fn prune_expired(&mut self, now: Instant) -> usize {
        let before = self.responses.len();
        self.responses.retain(|entry| entry.expires_at > now);
        before - self.responses.len()
    }

    pub fn pending_len(&self) -> usize {
        self.pending.len()
    }

    pub fn cached_response_len(&self) -> usize {
        self.responses.len()
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

    fn peer() -> SocketAddr {
        "192.0.2.44:50000".parse().unwrap()
    }

    fn envelope(phase: HandshakePhase, id: [u8; 16], payload: &[u8]) -> Vec<u8> {
        HandshakeEnvelope {
            phase,
            handshake_id: id,
            payload: payload.to_vec(),
        }.encode().unwrap()
    }

    fn driver() -> HandshakeDatagramDriver {
        HandshakeDatagramDriver::new(
            8, 2, 8, 2, Duration::from_secs(10),
            HandshakeRetryPolicy {
                initial_rto: Duration::from_millis(100),
                max_rto: Duration::from_millis(250),
                max_transmissions: 3,
            },
        ).unwrap()
    }

    #[test]
    fn retry_driver_resends_exact_bytes_with_bounded_backoff() {
        let now = Instant::now();
        let request = envelope(HandshakePhase::ClientInit, [9; 16], b"noise-msg-1");
        let mut driver = driver();
        driver.register_request(
            request.clone(), peer(), HandshakePhase::ServerResponse, now,
        ).unwrap();

        assert!(driver.poll(now + Duration::from_millis(99)).is_empty());
        assert!(matches!(
            driver.poll(now + Duration::from_millis(100)).as_slice(),
            [HandshakeDriverEvent::Retransmit { datagram, attempt: 2, .. }]
                if datagram == &request
        ));
        assert!(matches!(
            driver.poll(now + Duration::from_millis(300)).as_slice(),
            [HandshakeDriverEvent::Retransmit { datagram, attempt: 3, .. }]
                if datagram == &request
        ));
        assert!(matches!(
            driver.poll(now + Duration::from_millis(550)).as_slice(),
            [HandshakeDriverEvent::TimedOut { .. }]
        ));
        assert_eq!(driver.pending_len(), 0);
    }

    #[test]
    fn response_requires_matching_peer_identifier_and_phase() {
        let now = Instant::now();
        let request = envelope(HandshakePhase::ClientInit, [8; 16], b"m1");
        let valid = envelope(HandshakePhase::ServerResponse, [8; 16], b"m2");
        let mut driver = driver();
        driver.register_request(
            request, peer(), HandshakePhase::ServerResponse, now,
        ).unwrap();
        assert!(!driver.accept_response(
            &valid, "192.0.2.45:50000".parse().unwrap(),
        ).unwrap());
        let wrong_phase = envelope(HandshakePhase::ServerAck, [8; 16], b"bad");
        assert!(!driver.accept_response(&wrong_phase, peer()).unwrap());
        assert!(driver.accept_response(&valid, peer()).unwrap());
        assert_eq!(driver.pending_len(), 0);
    }

    #[test]
    fn response_cache_replays_exact_response_and_expires() {
        let now = Instant::now();
        let request = envelope(HandshakePhase::ClientInit, [6; 16], b"m1");
        let response = envelope(HandshakePhase::ServerResponse, [6; 16], b"m2");
        let mut driver = driver();
        driver.cache_response(&request, response.clone(), peer(), now).unwrap();
        assert_eq!(
            driver.cached_response(&request, peer(), now).unwrap(),
            Some(response.as_slice())
        );
        assert_eq!(driver.prune_expired(now + Duration::from_secs(10)), 1);
        assert_eq!(driver.cached_response(&request, peer(), now + Duration::from_secs(10)).unwrap(), None);
    }

    #[test]
    fn response_cache_rejects_transaction_reuse_with_different_request() {
        let now = Instant::now();
        let request = envelope(HandshakePhase::ClientInit, [5; 16], b"first");
        let altered = envelope(HandshakePhase::ClientInit, [5; 16], b"other");
        let response = envelope(HandshakePhase::ServerResponse, [5; 16], b"reply");
        let mut driver = driver();
        driver.cache_response(&request, response, peer(), now).unwrap();
        assert_eq!(
            driver.cached_response(&altered, peer(), now),
            Err(HandshakeDriverError::CacheConflict)
        );
    }

    #[test]
    fn driver_enforces_global_and_per_peer_pending_limits() {
        let now = Instant::now();
        let mut driver = HandshakeDatagramDriver::new(
            2, 1, 2, 1, Duration::from_secs(1), HandshakeRetryPolicy::default(),
        ).unwrap();
        driver.register_request(
            envelope(HandshakePhase::ClientInit, [1; 16], b"a"),
            peer(), HandshakePhase::ServerResponse, now,
        ).unwrap();
        assert_eq!(
            driver.register_request(
                envelope(HandshakePhase::ClientInit, [2; 16], b"b"),
                peer(), HandshakePhase::ServerResponse, now,
            ),
            Err(HandshakeDriverError::PeerLimitReached)
        );
        driver.register_request(
            envelope(HandshakePhase::ClientInit, [3; 16], b"c"),
            "192.0.2.45:50000".parse().unwrap(),
            HandshakePhase::ServerResponse, now,
        ).unwrap();
        assert_eq!(driver.pending_len(), 2);
    }
}
