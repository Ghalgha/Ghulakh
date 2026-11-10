//! Bounded server-side Noise handshake admission and replay handling.
//!
//! The caller supplies datagrams only after TURN ChannelData decoding and
//! binds the observed relay source tuple to the handshake. Responses are cached
//! before being returned to the socket layer; duplicate requests never advance
//! Noise state a second time.

use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{bail, ensure, Context, Result};
use ghulakh_protocol::{
    handshake_datagram::{
        HandshakeDatagramDriver, HandshakePhase, HandshakeRetryPolicy,
    },
    session_handshake::{NoiseServerKeyPair, SessionFrameKeys},
    turn_handshake::TurnHandshakeServer,
};

const MAX_ACTIVE_HANDSHAKES: usize = 1024;
const MAX_RATE_PEERS: usize = 1024;
const RATE_WINDOW: Duration = Duration::from_secs(10);
const MAX_REQUESTS_PER_WINDOW: u32 = 12;
const HANDSHAKE_TTL: Duration = Duration::from_secs(30);
const CACHE_CAPACITY: usize = 4096;
const CACHE_PER_PEER: usize = 16;

type CredentialVerifier = dyn Fn(&[u8]) -> bool + Send + Sync + 'static;

struct PendingHandshake {
    server: TurnHandshakeServer,
    expires_at: Instant,
}

struct PeerRate {
    window_started: Instant,
    requests: u32,
}

#[derive(Debug)]
pub enum TurnHandshakeOutcome {
    /// Exact cached response for a retransmitted request.
    Cached {
        response: Vec<u8>,
    },
    /// New response; keys exist only after ClientFinish credential verification.
    Response {
        response: Vec<u8>,
        established: Option<EstablishedTurnSession>,
    },
}

pub struct EstablishedTurnSession {
    pub handshake_id: [u8; 16],
    pub relay_peer: SocketAddr,
    pub frame_keys: SessionFrameKeys,
}

pub struct TurnHandshakeService {
    keypair: Arc<NoiseServerKeyPair>,
    verify_credential: Arc<CredentialVerifier>,
    delivery: HandshakeDatagramDriver,
    pending: HashMap<(SocketAddr, [u8; 16]), PendingHandshake>,
    peer_rates: HashMap<SocketAddr, PeerRate>,
}

impl TurnHandshakeService {
    pub fn new(
        keypair: Arc<NoiseServerKeyPair>,
        verify_credential: Arc<CredentialVerifier>,
    ) -> Result<Self> {
        Ok(Self {
            keypair,
            verify_credential,
            delivery: HandshakeDatagramDriver::new(
                MAX_ACTIVE_HANDSHAKES,
                8,
                CACHE_CAPACITY,
                CACHE_PER_PEER,
                HANDSHAKE_TTL,
                HandshakeRetryPolicy::default(),
            ).context("initialize bounded handshake delivery cache")?,
            pending: HashMap::with_capacity(MAX_ACTIVE_HANDSHAKES),
            peer_rates: HashMap::with_capacity(MAX_RATE_PEERS),
        })
    }

    /// Process one already-decapsulated handshake envelope. `relay_peer` must
    /// be the source tuple observed on the server's TURN-facing UDP socket,
    /// never an address supplied by the client.
    pub fn process(
        &mut self,
        datagram: &[u8],
        relay_peer: SocketAddr,
        now: Instant,
    ) -> Result<TurnHandshakeOutcome> {
        self.prune(now);
        self.admit(relay_peer, now)?;

        // Replay lookup precedes all Noise state transitions.
        if let Some(response) = self.delivery
            .cached_response(datagram, relay_peer, now)
            .context("lookup cached handshake response")?
        {
            return Ok(TurnHandshakeOutcome::Cached {
                response: response.to_vec(),
            });
        }

        let envelope = ghulakh_protocol::handshake_datagram::HandshakeEnvelope::decode(datagram)
            .context("decode client handshake envelope")?;
        let key = (relay_peer, envelope.handshake_id);

        match envelope.phase {
            HandshakePhase::ClientInit => {
                ensure!(
                    self.pending.len() < MAX_ACTIVE_HANDSHAKES,
                    "server handshake capacity reached"
                );
                ensure!(
                    !self.pending.contains_key(&key),
                    "uncached duplicate ClientInit cannot advance handshake state"
                );
                let mut server = TurnHandshakeServer::new(&self.keypair)
                    .context("initialize server Noise handshake")?;
                let response = server.receive_client_init(datagram)
                    .context("process client Noise first message")?;
                self.delivery.cache_response(
                    datagram,
                    response.clone(),
                    relay_peer,
                    now,
                ).context("cache ServerResponse before sending")?;
                self.pending.insert(key, PendingHandshake {
                    server,
                    expires_at: now + HANDSHAKE_TTL,
                });
                Ok(TurnHandshakeOutcome::Response {
                    response,
                    established: None,
                })
            }
            HandshakePhase::ClientFinish => {
                let pending = self.pending.get_mut(&key)
                    .context("no active handshake for ClientFinish")?;
                ensure!(pending.expires_at > now, "client handshake expired");
                let (response, frame_keys) = pending.server.receive_client_finish(
                    datagram,
                    |credential| (self.verify_credential)(credential),
                ).context("authenticate client Noise finish")?;

                // Cache exact ServerAck before exposing response or session keys.
                self.delivery.cache_response(
                    datagram,
                    response.clone(),
                    relay_peer,
                    now,
                ).context("cache ServerAck before sending")?;
                self.pending.remove(&key);

                Ok(TurnHandshakeOutcome::Response {
                    response,
                    established: Some(EstablishedTurnSession {
                        handshake_id: envelope.handshake_id,
                        relay_peer,
                        frame_keys,
                    }),
                })
            }
            _ => bail!("unexpected client handshake phase"),
        }
    }

    fn admit(&mut self, peer: SocketAddr, now: Instant) -> Result<()> {
        if let Some(rate) = self.peer_rates.get_mut(&peer) {
            if now.saturating_duration_since(rate.window_started) >= RATE_WINDOW {
                rate.window_started = now;
                rate.requests = 0;
            }
            ensure!(
                rate.requests < MAX_REQUESTS_PER_WINDOW,
                "handshake rate limit exceeded for relay peer"
            );
            rate.requests += 1;
            return Ok(());
        }

        ensure!(
            self.peer_rates.len() < MAX_RATE_PEERS,
            "handshake rate-limit peer table is full"
        );
        self.peer_rates.insert(peer, PeerRate {
            window_started: now,
            requests: 1,
        });
        Ok(())
    }

    fn prune(&mut self, now: Instant) {
        self.delivery.prune_expired(now);
        self.pending.retain(|_, handshake| handshake.expires_at > now);
        self.peer_rates.retain(|_, rate| {
            now.saturating_duration_since(rate.window_started) < RATE_WINDOW
        });
    }

    pub fn active_handshakes(&self) -> usize {
        self.pending.len()
    }

    pub fn cached_responses(&self) -> usize {
        self.delivery.cached_response_len()
    }
}
