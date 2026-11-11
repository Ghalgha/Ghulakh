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
    session_handshake::{NoiseServerKeyPair, SessionFrameKeys, SessionHandshakeError, TurnSessionConfig},
    turn_handshake::TurnHandshakeServer,
    turn_path_context::TurnPathContext,
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
    pub path_context: Option<TurnPathContext>,
    /// Generation displaced while reserving this path, if this handshake replaces it.
    pub replaced_generation: Option<[u8; 16]>,
}

struct PathGroupLease {
    virtual_ipv4: Ipv4Addr,
    path_count: u16,
    active_paths: HashMap<u16, [u8; 16]>,
}

pub struct TurnHandshakeService {
    keypair: Arc<NoiseServerKeyPair>,
    verify_credential: Arc<CredentialVerifier>,
    delivery: HandshakeDatagramDriver,
    pending: HashMap<(SocketAddr, [u8; 16]), PendingHandshake>,
    peer_rates: HashMap<SocketAddr, PeerRate>,
    next_client_host: u32,
    allocated_ips: HashSet<Ipv4Addr>,
    path_groups: HashMap<[u8; 16], PathGroupLease>,
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
            path_groups: HashMap::new(),
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
                let mut pending = self.pending.remove(&key)
                    .context("no active handshake for ClientFinish")?;
                let verifier = Arc::clone(&self.verify_credential);
                let mut reserved_path = None;
                let mut replaced_generation = None;
                let mut reserved_legacy_ip = None;
                let finish_result = pending.server.receive_client_finish_with_path_context_builder(
                    datagram,
                    |credential| verifier(credential),
                    |path_context| {
                        let virtual_ipv4 = if let Some(context) = path_context {
                            reserved_path = Some(context);
                            let (address, previous) = self.reserve_path_transactional(context, envelope.handshake_id)
                                .map_err(|_| SessionHandshakeError::InvalidSessionConfig)?;
                            replaced_generation = previous;
                            address
                        } else {
                            let address = self.allocate_virtual_ipv4()
                                .map_err(|_| SessionHandshakeError::InvalidSessionConfig)?;
                            self.allocated_ips.insert(address);
                            reserved_legacy_ip = Some(address);
                            address
                        };
                        let config = TurnSessionConfig {
                            virtual_ipv4,
                            mtu: SERVER_TUN_MTU,
                        };
                        Ok(config.encode()?.to_vec())
                    },
                );
                let (response, frame_keys, path_context) = match finish_result {
                    Ok(result) => result,
                    Err(error) => {
                        if let Some(context) = reserved_path {
                            self.rollback_path_replacement(context, envelope.handshake_id, replaced_generation);
                        }
                        if let Some(address) = reserved_legacy_ip {
                            self.allocated_ips.remove(&address);
                        }
                        return Err(error).context("authenticate client Noise finish");
                    }
                };
                // The same configuration was encoded by the authenticated
                // acknowledgement builder immediately before Noise encrypted it.
                let virtual_ipv4 = if let Some(context) = path_context {
                    self.path_groups.get(&context.group_id)
                        .map(|group| group.virtual_ipv4)
                        .context("reserved path group disappeared before acknowledgement")?
                } else {
                    reserved_legacy_ip.context("legacy virtual IPv4 reservation missing")?
                };
                let config = TurnSessionConfig {
                    virtual_ipv4,
                    mtu: SERVER_TUN_MTU,
                };

                // Cache exact ServerAck before exposing response or session keys.
                if let Err(error) = self.delivery.cache_response(
                    datagram,
                    response.clone(),
                    relay_peer,
                    now,
                ) {
                    if let Some(context) = reserved_path {
                        self.rollback_path_replacement(context, envelope.handshake_id, replaced_generation);
                    }
                    if let Some(address) = reserved_legacy_ip {
                        self.allocated_ips.remove(&address);
                    }
                    return Err(error).context("cache ServerAck before sending");
                }
 
                Ok(TurnHandshakeOutcome::Response {
                    response,
                    established: Some(EstablishedTurnSession {
                        handshake_id: envelope.handshake_id,
                        relay_peer,
                        config,
                        frame_keys,
                        path_context,
                        replaced_generation,
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

    fn reserve_path(&mut self, context: TurnPathContext, generation: [u8; 16]) -> Result<Ipv4Addr> {
        context.validate().context("validate authenticated TURN path context")?;
        if let Some(group) = self.path_groups.get_mut(&context.group_id) {
            ensure!(group.path_count == context.path_count, "TURN path group count mismatch");
            ensure!(
                group.active_paths.contains_key(&context.path_id)
                    || group.active_paths.len() < usize::from(group.path_count),
                "TURN path group is already full"
            );
            group.active_paths.insert(context.path_id, generation);
            return Ok(group.virtual_ipv4);
        }

        let virtual_ipv4 = self.allocate_virtual_ipv4()?;
        self.allocated_ips.insert(virtual_ipv4);
        let mut active_paths = HashMap::new();
        active_paths.insert(context.path_id, generation);
        self.path_groups.insert(context.group_id, PathGroupLease {
            virtual_ipv4,
            path_count: context.path_count,
            active_paths,
        });
        Ok(virtual_ipv4)
    }

    fn reserve_path_transactional(
        &mut self,
        context: TurnPathContext,
        generation: [u8; 16],
    ) -> Result<(Ipv4Addr, Option<[u8; 16]>)> {
        context.validate().context("validate authenticated TURN path context")?;
        if let Some(group) = self.path_groups.get_mut(&context.group_id) {
            ensure!(group.path_count == context.path_count, "TURN path group count mismatch");
            ensure!(
                group.active_paths.contains_key(&context.path_id)
                    || group.active_paths.len() < usize::from(group.path_count),
                "TURN path group is already full"
            );
            let previous = group.active_paths.insert(context.path_id, generation);
            return Ok((group.virtual_ipv4, previous));
        }

        let virtual_ipv4 = self.allocate_virtual_ipv4()?;
        self.allocated_ips.insert(virtual_ipv4);
        let mut active_paths = HashMap::new();
        active_paths.insert(context.path_id, generation);
        self.path_groups.insert(context.group_id, PathGroupLease {
            virtual_ipv4,
            path_count: context.path_count,
            active_paths,
        });
        Ok((virtual_ipv4, None))
    }

    /// Undo a reservation if gateway registration fails, restoring the displaced
    /// generation so the still-registered old gateway session remains valid.
    pub fn rollback_path_replacement(
        &mut self,
        context: TurnPathContext,
        generation: [u8; 16],
        previous: Option<[u8; 16]>,
    ) -> bool {
        let Some(group) = self.path_groups.get_mut(&context.group_id) else {
            return false;
        };
        if group.active_paths.get(&context.path_id) != Some(&generation) {
            return false;
        }
        if let Some(previous_generation) = previous {
            group.active_paths.insert(context.path_id, previous_generation);
            true
        } else {
            group.active_paths.remove(&context.path_id);
            if group.active_paths.is_empty() {
                let address = group.virtual_ipv4;
                self.path_groups.remove(&context.group_id);
                self.allocated_ips.remove(&address);
            }
            true
        }
    }

    fn rollback_path(&mut self, context: TurnPathContext, generation: [u8; 16]) -> bool {
        let Some(group) = self.path_groups.get_mut(&context.group_id) else {
            return false;
        };
        if group.active_paths.get(&context.path_id) != Some(&generation) {
            return false;
        }
        group.active_paths.remove(&context.path_id);
        if group.active_paths.is_empty() {
            let address = group.virtual_ipv4;
            self.path_groups.remove(&context.group_id);
            self.allocated_ips.remove(&address);
        }
        true
    }

    pub fn release_path(&mut self, context: TurnPathContext, generation: [u8; 16]) -> bool {
        self.rollback_path(context, generation)
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
        // Multipath addresses are owned by generation-bound path leases and
        // may only be released after the final path is removed.
        if self.path_groups.values().any(|group| group.virtual_ipv4 == address) {
            return false;
        }
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
    fn path_group_reserves_one_address_until_its_last_path_is_released() {
        let (mut service, _) = service(b"device-secret");
        let first = TurnPathContext {
            group_id: [0x71; 16],
            path_id: 0,
            path_count: 2,
        };
        let second = TurnPathContext {
            path_id: 1,
            ..first
        };
        let address_a = service.reserve_path(first, [1; 16]).unwrap();
        let address_b = service.reserve_path(second, [2; 16]).unwrap();
        assert_eq!(address_a, address_b);
        assert_eq!(service.allocated_virtual_ipv4_count(), 1);
        assert_eq!(service.reserve_path(first, [3; 16]).unwrap(), address_a);
        assert!(!service.release_path(first, [1; 16]));
        assert!(service.release_path(first, [3; 16]));

        assert!(!service.release_path(first, [1; 16]));
        assert_eq!(service.allocated_virtual_ipv4_count(), 1);
        assert!(service.release_path(second, [2; 16]));
        assert_eq!(service.allocated_virtual_ipv4_count(), 0);
    }


    #[test]
    fn failed_path_replacement_restores_previous_generation_and_address_lease() {
        let (mut service, _) = service(b"device-secret");
        let context = TurnPathContext {
            group_id: [0x75; 16],
            path_id: 0,
            path_count: 2,
        };
        let original_generation = [0x11; 16];
        let replacement_generation = [0x22; 16];
        let (address, previous) = service
            .reserve_path_transactional(context, original_generation)
            .unwrap();
        assert_eq!(previous, None);

        let (replacement_address, displaced) = service
            .reserve_path_transactional(context, replacement_generation)
            .unwrap();
        assert_eq!(replacement_address, address);
        assert_eq!(displaced, Some(original_generation));

        assert!(service.rollback_path_replacement(
            context,
            replacement_generation,
            displaced,
        ));
        assert!(!service.release_path(context, replacement_generation));
        assert!(service.release_path(context, original_generation));
        assert_eq!(service.allocated_virtual_ipv4_count(), 0);
    }

    #[test]
    fn legacy_address_release_cannot_bypass_active_path_leases() {
        let (mut service, _) = service(b"device-secret");
        let context = TurnPathContext {
            group_id: [0x73; 16],
            path_id: 0,
            path_count: 2,
        };
        let address = service.reserve_path(context, [0x31; 16]).unwrap();
        assert!(!service.release_virtual_ipv4(address));
        assert_eq!(service.allocated_virtual_ipv4_count(), 1);
        assert!(service.release_path(context, [0x31; 16]));
        assert_eq!(service.allocated_virtual_ipv4_count(), 0);
    }

    #[test]
    fn authenticated_paths_in_one_group_receive_the_same_virtual_address() {
        let credential = b"device-secret";
        let (mut service, keypair) = service(credential);
        let group_id = [0x72; 16];
        let now = Instant::now();
        let mut assigned = Vec::new();

        for path_id in 0..2 {
            let context = TurnPathContext {
                group_id,
                path_id,
                path_count: 2,
            };
            let (mut client, init) = TurnHandshakeClient::new_with_path_context(
                keypair.public_key(),
                credential,
                context,
                [0x40 + path_id as u8; 16],
            ).unwrap();
            let peer: SocketAddr = format!("192.0.2.{}:{}", 20 + path_id, 49152 + path_id)
                .parse().unwrap();
            let server_response = match service.process(&init, peer, now).unwrap() {
                TurnHandshakeOutcome::Response { response, established: None } => response,
                _ => panic!("expected server response"),
            };
            let finish = client.receive_server_response(&server_response).unwrap();
            let (server_ack, established) = match service.process(&finish, peer, now).unwrap() {
                TurnHandshakeOutcome::Response { response, established: Some(session) } => (response, session),
                _ => panic!("expected established path"),
            };
            assert_eq!(established.path_context, Some(context));
            let (keys, config_payload) = client.receive_server_ack_with_payload(&server_ack).unwrap();
            assert_eq!(keys.session_id(), established.frame_keys.session_id());
            assigned.push(TurnSessionConfig::decode(&config_payload).unwrap().virtual_ipv4);
        }

        assert_eq!(assigned[0], assigned[1]);
        assert_eq!(service.allocated_virtual_ipv4_count(), 1);
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
    fn virtual_ipv4_addresses_can_be_released_and_reused() {
        let (mut service, _) = service(b"secret");
        let first = service.allocate_virtual_ipv4().unwrap();
        service.allocated_ips.insert(first);
        assert_eq!(service.allocated_virtual_ipv4_count(), 1);
        assert!(service.release_virtual_ipv4(first));
        assert_eq!(service.allocated_virtual_ipv4_count(), 0);
        service.next_client_host = u32::from(first.octets()[2]) * 256
            + u32::from(first.octets()[3]);
        assert_eq!(service.allocate_virtual_ipv4().unwrap(), first);
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
