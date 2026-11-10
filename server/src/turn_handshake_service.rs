//! Bounded server-side Noise handshake admission and replay handling.
//!
//! The caller supplies datagrams only after TURN ChannelData decoding and
//! binds the observed relay source tuple to the handshake. Responses are cached
//! before being returned to the socket layer; duplicate requests never advance
//! Noise state a second time.

use std::{
    collections::{HashMap, HashSet},
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{bail, ensure, Context, Result};
use ghulakh_protocol::{
    handshake_datagram::{
        HandshakeDatagramDriver, HandshakePhase, HandshakeRetryPolicy,
    },
    session_handshake::{NoiseServerKeyPair, SessionFrameKeys, TurnSessionConfig},
    turn_handshake::TurnHandshakeServer,
};

const MAX_ACTIVE_HANDSHAKES: usize = 1024;
const MAX_RATE_PEERS: usize = 1024;
const RATE_WINDOW: Duration = Duration::from_secs(10);
const MAX_REQUESTS_PER_WINDOW: u32 = 12;
const HANDSHAKE_TTL: Duration = Duration::from_secs(30);
const CACHE_CAPACITY: usize = 4096;
const CACHE_PER_PEER: usize = 16;
const SERVER_TUN_MTU: u16 = 1100;

pub type CredentialVerifier = dyn Fn(&[u8]) -> bool + Send + Sync + 'static;

struct PendingHandshake {
    server: TurnHandshakeServer,
    expires_at: Instant,
}

struct PeerRate {
    window_started: Instant,
    requests: u32,
}

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
    pub config: TurnSessionConfig,
    pub frame_keys: SessionFrameKeys,
}

pub struct TurnHandshakeService {
    keypair: Arc<NoiseServerKeyPair>,
    verify_credential: Arc<CredentialVerifier>,
    delivery: HandshakeDatagramDriver,
    pending: HashMap<(SocketAddr, [u8; 16]), PendingHandshake>,
    peer_rates: HashMap<SocketAddr, PeerRate>,
    next_client_host: u32,
    allocated_ips: HashSet<Ipv4Addr>,
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
            next_client_host: 2,
            allocated_ips: HashSet::new(),
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
                if self.pending.get(&key).is_some_and(|pending| pending.expires_at <= now) {
                    self.pending.remove(&key);
                    bail!("client handshake expired");
                }
                let config = TurnSessionConfig {
                    virtual_ipv4: self.allocate_virtual_ipv4()?,
                    mtu: SERVER_TUN_MTU,
                };
                let config_payload = config.encode()
                    .context("encode authenticated server session configuration")?;
                let finish_result = {
                    let pending = self.pending.get_mut(&key)
                        .context("no active handshake for ClientFinish")?;
                    pending.server.receive_client_finish_with_payload(
                        datagram,
                        |credential| (self.verify_credential)(credential),
                        &config_payload,
                    )
                };
                let (response, frame_keys) = match finish_result {
                    Ok(result) => result,
                    Err(error) => {
                        // A failed credential consumes this Noise state; discard it
                        // immediately instead of retaining an unusable pending entry.
                        self.pending.remove(&key);
                        return Err(error).context("authenticate client Noise finish");
                    }
                };

                // Cache exact ServerAck before exposing response or session keys.
                self.delivery.cache_response(
                    datagram,
                    response.clone(),
                    relay_peer,
                    now,
                ).context("cache ServerAck before sending")?;
                self.pending.remove(&key);
                self.allocated_ips.insert(config.virtual_ipv4);

                Ok(TurnHandshakeOutcome::Response {
                    response,
                    established: Some(EstablishedTurnSession {
                        handshake_id: envelope.handshake_id,
                        relay_peer,
                        config,
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

    fn allocate_virtual_ipv4(&mut self) -> Result<Ipv4Addr> {
        for _ in 0..65_532 {
            let host = self.next_client_host;
            self.next_client_host = if host >= 65_533 { 2 } else { host + 1 };
            let address = Ipv4Addr::new(10, 77, (host >> 8) as u8, host as u8);
            if !self.allocated_ips.contains(&address) {
                return Ok(address);
            }
        }
        bail!("server virtual IPv4 pool exhausted");
    }

    pub fn release_virtual_ipv4(&mut self, address: Ipv4Addr) -> bool {
        self.allocated_ips.remove(&address)
    }

    pub fn allocated_virtual_ipv4_count(&self) -> usize {
        self.allocated_ips.len()
    }

    pub fn active_handshakes(&self) -> usize {
        self.pending.len()
    }

    pub fn cached_responses(&self) -> usize {
        self.delivery.cached_response_len()
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use ghulakh_protocol::turn_handshake::TurnHandshakeClient;

    fn service(credential: &'static [u8]) -> (TurnHandshakeService, Arc<NoiseServerKeyPair>) {
        let keypair = Arc::new(NoiseServerKeyPair::generate().unwrap());
        let verifier: Arc<CredentialVerifier> =
            Arc::new(move |candidate| candidate == credential);
        (TurnHandshakeService::new(Arc::clone(&keypair), verifier).unwrap(), keypair)
    }

    fn relay_peer() -> SocketAddr {
        "192.0.2.10:49152".parse().unwrap()
    }

    #[test]
    fn full_handshake_caches_before_returning_and_replays_without_noise_transition() {
        let credential = b"device-secret";
        let (mut service, keypair) = service(credential);
        let now = Instant::now();
        let peer = relay_peer();
        let handshake_id = [0x42; 16];
        let (mut client, init) =
            TurnHandshakeClient::new(keypair.public_key(), credential, handshake_id).unwrap();

        let first = service.process(&init, peer, now).unwrap();
        let server_response = match first {
            TurnHandshakeOutcome::Response { response, established: None } => response,
            _ => panic!("expected initial server response"),
        };
        assert_eq!(service.cached_responses(), 1);
        assert_eq!(service.active_handshakes(), 1);

        let duplicate = service.process(&init, peer, now).unwrap();
        assert!(matches!(duplicate, TurnHandshakeOutcome::Cached { response } if response == server_response));

        let finish = client.receive_server_response(&server_response).unwrap();
        let completed = service.process(&finish, peer, now).unwrap();
        let (server_ack, established) = match completed {
            TurnHandshakeOutcome::Response { response, established: Some(session) } => (response, session),
            _ => panic!("expected authenticated session"),
        };
        assert_eq!(established.handshake_id, handshake_id);
        assert_eq!(established.relay_peer, peer);
        assert_eq!(service.active_handshakes(), 0);
        assert_eq!(service.cached_responses(), 2);
        let (client_keys, client_config_payload) =
            client.receive_server_ack_with_payload(&server_ack).unwrap();
        let client_config = TurnSessionConfig::decode(&client_config_payload).unwrap();
        assert_eq!(client_config, established.config);
        assert_eq!(client_config.virtual_ipv4, Ipv4Addr::new(10, 77, 0, 2));
        assert_eq!(client_keys.session_id(), established.frame_keys.session_id());

        let duplicate_finish = service.process(&finish, peer, now).unwrap();
        assert!(matches!(duplicate_finish, TurnHandshakeOutcome::Cached { response } if response == server_ack));
    }

    #[test]
    fn rejected_credential_discards_pending_noise_state() {
        let (mut service, keypair) = service(b"expected");
        let now = Instant::now();
        let (mut client, init) =
            TurnHandshakeClient::new(keypair.public_key(), b"wrong", [0x33; 16]).unwrap();
        let response = match service.process(&init, relay_peer(), now).unwrap() {
            TurnHandshakeOutcome::Response { response, .. } => response,
            _ => panic!("expected ServerResponse"),
        };
        let finish = client.receive_server_response(&response).unwrap();
        assert!(service.process(&finish, relay_peer(), now).is_err());
        assert_eq!(service.active_handshakes(), 0);
    }

    #[test]
    fn per_peer_rate_limit_is_bounded() {
        let (mut service, _) = service(b"secret");
        let now = Instant::now();
        let peer = relay_peer();
        for _ in 0..MAX_REQUESTS_PER_WINDOW {
            service.admit(peer, now).unwrap();
        }
        assert!(service.admit(peer, now).is_err());
        service.admit(peer, now + RATE_WINDOW).unwrap();
    }
}
