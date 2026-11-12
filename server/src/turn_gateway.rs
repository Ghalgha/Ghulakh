//! Authenticated UDP gateway for TURN-relayed IP packets.
//!
//! Sessions must be registered only after an independent authenticated control
//! exchange has verified the client identity, virtual address, TURN relayed
//! address and directional frame keys. The gateway never trusts source
//! or destination addresses carried only inside an unauthenticated payload.

use std::{
    collections::HashMap,
    net::{Ipv4Addr, SocketAddr},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};

use anyhow::{ensure, Context, Result};
use ghulakh_protocol::{
    secure_frame::{protected_frame_session_id, FrameOpener, FrameSealer},
    DataDatagram, IpPacketKind,
    turn_path_context::TurnPathContext,
};
use tokio::{
    net::UdpSocket,
    sync::{mpsc, Mutex as AsyncMutex, RwLock},
};

const TUN_INGRESS_CAPACITY: usize = 512;
const UDP_BUFFER_SIZE: usize = 65_507;
// Sharding keeps packets from one session FIFO while allowing independent
// sessions to be authenticated and decrypted concurrently.
const DATAGRAM_DISPATCH_SHARDS: usize = 8;
const DATAGRAM_DISPATCH_CAPACITY: usize = 256;
const SESSION_IDLE_TIMEOUT: Duration = Duration::from_secs(600);
const SESSION_MAINTENANCE_INTERVAL: Duration = Duration::from_secs(30);
const DOWNLINK_RATE_BYTES_PER_SEC: f64 = 247_000.0;
const DOWNLINK_BUCKET_CAPACITY: f64 = 10_500.0;
const DOWNLINK_MAX_DEFICIT: f64 = -4_500.0;
const FLOW_TABLE_MAX: usize = 1024;
const FLOW_IDLE_TTL: Duration = Duration::from_secs(30);
const FLOW_EVICT_EVERY: u32 = 1024;
// Keep latency-sensitive UDP flows on one relay path, but let sustained bulk
// flows use bounded flowlet bursts across independent TURN allocations.
const FLOW_BURST_BYTES: usize = 16 * 1024;
const SMALL_UDP_MAX_LEN: usize = 300;
const SMALL_UDP_STICKY: Duration = Duration::from_secs(1);
const PIN_WINDOW: Duration = Duration::from_millis(250);
const PIN_WINDOW_MAX_BYTES: usize = (DOWNLINK_RATE_BYTES_PER_SEC as usize) * 3 / 4 / 4;
const BULK_HOLD: Duration = Duration::from_secs(2);

#[derive(Clone, Copy)]
struct DownlinkFlowState {
    session_id: [u8; 8],
    last_seen: Instant,
    burst_left: usize,
    sticky_until: Option<Instant>,
    window_start: Instant,
    window_bytes: usize,
    bulk_until: Option<Instant>,
}

struct DownlinkScheduler {
    tokens: HashMap<[u8; 8], f64>,
    last_update: HashMap<[u8; 8], Instant>,
    flows: HashMap<(Ipv4Addr, ghulakh_protocol::ip_flow::Ipv4FlowKey), DownlinkFlowState>,
    cursor: usize,
    evict_counter: u32,
}

impl DownlinkScheduler {
    fn new() -> Self {
        Self { tokens: HashMap::new(), last_update: HashMap::new(), flows: HashMap::new(), cursor: 0, evict_counter: 0 }
    }

    fn remove_session(&mut self, session_id: [u8; 8]) {
        self.tokens.remove(&session_id);
        self.last_update.remove(&session_id);
    }

    fn refill(&mut self, id: [u8; 8], now: Instant) {
        let previous = self.last_update.insert(id, now).unwrap_or(now);
        let elapsed = now.saturating_duration_since(previous).as_secs_f64();
        let tokens = self.tokens.entry(id).or_insert(DOWNLINK_BUCKET_CAPACITY);
        *tokens = (*tokens + elapsed * DOWNLINK_RATE_BYTES_PER_SEC).min(DOWNLINK_BUCKET_CAPACITY);
    }

    fn choose(&mut self, active: &[[u8; 8]], now: Instant, len: usize) -> [u8; 8] {
        let start = self.cursor % active.len();
        for offset in 0..active.len() {
            let index = (start + offset) % active.len();
            self.refill(active[index], now);
            if self.tokens.get(&active[index]).copied().unwrap_or(0.0) >= len as f64 {
                self.cursor = (index + 1) % active.len();
                return active[index];
            }
        }
        let mut best = active[start];
        for offset in 1..active.len() {
            let id = active[(start + offset) % active.len()];
            if self.tokens.get(&id).copied().unwrap_or(0.0) > self.tokens.get(&best).copied().unwrap_or(0.0) {
                best = id;
            }
        }
        self.cursor = (active.iter().position(|id| *id == best).unwrap_or(start) + 1) % active.len();
        best
    }

    fn select(&mut self, active: &[[u8; 8]], client_ipv4: Ipv4Addr, packet: &[u8], now: Instant) -> [u8; 8] {
        debug_assert!(!active.is_empty());
        self.evict_counter = self.evict_counter.wrapping_add(1);
        if self.evict_counter.is_multiple_of(FLOW_EVICT_EVERY) || self.flows.len() >= FLOW_TABLE_MAX {
            self.flows.retain(|_, state| now.saturating_duration_since(state.last_seen) < FLOW_IDLE_TTL);
            if self.flows.len() >= FLOW_TABLE_MAX {
                self.flows.clear();
            }
        }

        // Scope collision-safe flow identities to the virtual client so
        // identical tuples from separate tunnel groups cannot share state.
        let Some(flow) = ghulakh_protocol::ip_flow::ipv4_flow_key(packet) else {
            // Malformed/truncated IPv4 packets get no persistent affinity.
            let id = self.choose(active, now, packet.len());
            self.refill(id, now);
            if let Some(tokens) = self.tokens.get_mut(&id) {
                *tokens = (*tokens - packet.len() as f64).max(DOWNLINK_MAX_DEFICIT);
            }
            return id;
        };
        let key = (client_ipv4, flow);
        let small_udp = packet.get(9) == Some(&17) && packet.len() <= SMALL_UDP_MAX_LEN;
        let selected = if let Some(mut state) = self.flows.get(&key).copied() {
            state.last_seen = now;
            if now.saturating_duration_since(state.window_start) >= PIN_WINDOW {
                state.window_start = now;
                state.window_bytes = 0;
            }
            state.window_bytes = state.window_bytes.saturating_add(packet.len());
            if state.window_bytes > PIN_WINDOW_MAX_BYTES {
                state.bulk_until = Some(now + BULK_HOLD);
                state.sticky_until = None;
            }
            let bulk = state.bulk_until.is_some_and(|until| now < until);
            if small_udp && !bulk {
                state.sticky_until = Some(now + SMALL_UDP_STICKY);
            }
            let sticky = state.sticky_until.is_some_and(|until| now < until);
            if active.contains(&state.session_id) && (sticky || state.burst_left >= packet.len()) {
                state.burst_left = state.burst_left.saturating_sub(packet.len());
                let id = state.session_id;
                self.flows.insert(key, state);
                id
            } else {
                // A sustained flow advances as a bounded flowlet. This is the
                // throughput/ordering trade-off of independent TURN paths:
                // packets inside a burst share one path; burst boundaries may
                // still expose cross-path arrival skew.
                let id = self.choose(active, now, packet.len());
                state.session_id = id;
                state.burst_left = FLOW_BURST_BYTES.saturating_sub(packet.len());
                self.flows.insert(key, state);
                id
            }
        } else {
            let id = self.choose(active, now, packet.len());
            self.flows.insert(key, DownlinkFlowState {
                session_id: id,
                last_seen: now,
                burst_left: FLOW_BURST_BYTES.saturating_sub(packet.len()),
                sticky_until: small_udp.then_some(now + SMALL_UDP_STICKY),
                window_start: now,
                window_bytes: packet.len(),
                bulk_until: None,
            });
            id
        };
        self.refill(selected, now);
        if let Some(tokens) = self.tokens.get_mut(&selected) {
            *tokens = (*tokens - packet.len() as f64).max(DOWNLINK_MAX_DEFICIT);
        }
        selected
    }
}



fn datagram_dispatch_shard(datagram: &[u8]) -> usize {
    let Ok(session_id) = protected_frame_session_id(datagram) else {
        // Handshake and malformed traffic share a bounded lane; established
        // sessions never contend with one another unless their shard hashes collide.
        return 0;
    };
    let hash = session_id.iter().fold(0x811c_9dc5u32, |state, byte| {
        (state ^ u32::from(*byte)).wrapping_mul(0x0100_0193)
    });
    hash as usize % DATAGRAM_DISPATCH_SHARDS
}

struct SessionCrypto {
    opener: FrameOpener,
    sealer: FrameSealer,
}

struct GatewaySession {
    client_ipv4: Ipv4Addr,
    relay_peer: SocketAddr,
    path_context: Option<TurnPathContext>,
    lease_generation: Option<[u8; 16]>,
    crypto: Mutex<SessionCrypto>,
    last_activity: Mutex<Instant>,
}

#[derive(Clone)]
struct ClientRoute {
    group_id: Option<[u8; 16]>,
    sessions: Vec<[u8; 8]>,
}

#[derive(Default)]
struct Counters {
    accepted: AtomicU64,
    malformed: AtomicU64,
    rejected_source: AtomicU64,
    rejected_session: AtomicU64,
    rejected_packet: AtomicU64,
    queue_drops: AtomicU64,
    downlink_sent: AtomicU64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TurnGatewayStats {
    pub accepted: u64,
    pub malformed: u64,
    pub rejected_source: u64,
    pub rejected_session: u64,
    pub rejected_packet: u64,
    pub queue_drops: u64,
    pub downlink_sent: u64,
}

/// Gateway UDP endpoint and its authenticated relay-session routing table.
pub struct TurnGateway {
    socket: Arc<UdpSocket>,
    sessions: RwLock<HashMap<[u8; 8], Arc<GatewaySession>>>,
    clients: RwLock<HashMap<Ipv4Addr, ClientRoute>>,
    tun_ingress: mpsc::Sender<DataDatagram>,
    handshake: AsyncMutex<Option<super::turn_handshake_service::TurnHandshakeService>>,
    counters: Counters,
    downlink_scheduler: Mutex<DownlinkScheduler>,
}

impl TurnGateway {
    pub async fn bind(
        address: SocketAddr,
    ) -> Result<(Arc<Self>, mpsc::Receiver<DataDatagram>)> {
        let socket = UdpSocket::bind(address).await.context("bind TURN gateway UDP socket")?;
        let (tun_ingress, tun_receiver) = mpsc::channel(TUN_INGRESS_CAPACITY);
        Ok((
            Arc::new(Self {
                socket: Arc::new(socket),
                sessions: RwLock::new(HashMap::new()),
                clients: RwLock::new(HashMap::new()),
                tun_ingress,
                handshake: AsyncMutex::new(None),
                counters: Counters::default(),
                downlink_scheduler: Mutex::new(DownlinkScheduler::new()),
            }),
            tun_receiver,
        ))
    }

    pub fn local_addr(&self) -> Result<SocketAddr> {
        self.socket.local_addr().context("read TURN gateway address")
    }

    /// Install the bounded Noise handshake processor before starting the UDP
    /// receive loop. The caller supplies persistent server keys and a verifier
    /// for credentials carried inside the encrypted Noise message.
    pub async fn install_handshake_service(
        &self,
        service: super::turn_handshake_service::TurnHandshakeService,
    ) -> Result<()> {
        let mut slot = self.handshake.lock().await;
        ensure!(slot.is_none(), "TURN handshake service is already installed");
        *slot = Some(service);
        Ok(())
    }

    async fn process_handshake(
        &self,
        payload: &[u8],
        relay_peer: SocketAddr,
    ) -> Result<()> {
        use super::turn_handshake_service::TurnHandshakeOutcome;

        // Keep the handshake-service lock through gateway registration and
        // acknowledgement commit. This serializes replacement transactions for
        // a path slot: a newer generation cannot reserve the slot while an older
        // generation is still being installed in the gateway.
        let mut handshake = self.handshake.lock().await;
        let service = handshake.as_mut().context("TURN handshake service is not installed")?;
        let outcome = service.process(payload, relay_peer, std::time::Instant::now())?;

        let (response, established) = match outcome {
            TurnHandshakeOutcome::Cached { response } => (response, None),
            TurnHandshakeOutcome::Response { response, established } => (response, established),
        };
        // Register the authenticated data plane before committing ServerAck.
        // A duplicate ClientFinish during registration is rejected and can retry;
        // after commit it receives the exact cached response.
        if let Some(established) = established {
            let client_ipv4 = established.config.virtual_ipv4;
            let handshake_id = established.handshake_id;
            let session_id = established.frame_keys.session_id();
            let (opener, sealer) = established.frame_keys.into_server_codecs();
            let path_context = established.path_context;
            // Commit replay protection before mutating the gateway route.
            // The handshake-service mutex serializes duplicate ClientFinish
            // processing, so no peer can observe the cached ServerAck until
            // this transaction releases the lock.
            let service = handshake.as_mut().context("TURN handshake service is not installed")?;
            if let Err(error) = service.commit_established_response(
                payload,
                &response,
                relay_peer,
                std::time::Instant::now(),
            ) {
                // Keep the staged authenticated handshake and its address/path lease.
                // A retransmitted ClientFinish can retry gateway registration without
                // attempting to advance the completed Noise state again.
                return Err(error).context("commit ServerAck replay protection before gateway registration");
            }

            if let Err(error) = self.register_session_with_path_generation(
                session_id,
                client_ipv4,
                established.relay_peer,
                opener,
                sealer,
                path_context.map(|context| (context, Some(handshake_id))),
            ).await {
                let service = handshake.as_mut().context("TURN handshake service is not installed")?;
                let cache_rollback = service.remove_cached_response(payload, relay_peer);
                // Keep the staged keys and path lease for a retry of this exact
                // ClientFinish. Only the replay-cache entry is rolled back because
                // the gateway has not installed the route yet.
                cache_rollback.context("rollback ServerAck replay cache after gateway registration failure")?;
                return Err(error).context("register authenticated TURN session after ServerAck cache reservation");
            }
            let service = handshake.as_mut().context("TURN handshake service is not installed")?;
            ensure!(
                service.finalize_established_response(handshake_id, relay_peer),
                "completed handshake staging entry disappeared after gateway registration",
            );
        }

        drop(handshake);
        let sent = self.socket.send_to(&response, relay_peer).await
            .context("send raw handshake response through TURN relay")?;
        ensure!(sent == response.len(), "partial TURN handshake response send");
        Ok(())
    }

    /// Register a session only after its identity, virtual IP, TURN relay tuple,
    /// relay tuple and directional frame keys have been authenticated.
    pub async fn register_session(
        &self,
        session_id: [u8; 8],
        client_ipv4: Ipv4Addr,
        relay_peer: SocketAddr,
        opener: FrameOpener,
        sealer: FrameSealer,
    ) -> Result<()> {
        self.register_session_with_path(
            session_id, client_ipv4, relay_peer, opener, sealer, None,
        ).await
    }

    async fn register_session_with_path(
        &self,
        session_id: [u8; 8],
        client_ipv4: Ipv4Addr,
        relay_peer: SocketAddr,
        opener: FrameOpener,
        sealer: FrameSealer,
        path_context: Option<TurnPathContext>,
    ) -> Result<()> {
        self.register_session_with_path_generation(
            session_id, client_ipv4, relay_peer, opener, sealer, path_context.map(|context| (context, None)),
        ).await
    }

    async fn register_session_with_path_generation(
        &self,
        session_id: [u8; 8],
        client_ipv4: Ipv4Addr,
        relay_peer: SocketAddr,
        opener: FrameOpener,
        sealer: FrameSealer,
        path_lease: Option<(TurnPathContext, Option<[u8; 16]>)>,
    ) -> Result<()> {
        let path_context = path_lease.map(|(context, _)| context);
        let lease_generation = path_lease.and_then(|(_, generation)| generation);
        ensure!(client_ipv4 != Ipv4Addr::UNSPECIFIED, "client IPv4 address is unspecified");
        ensure!(client_ipv4 != Ipv4Addr::BROADCAST, "client IPv4 address is broadcast");
        ensure!(relay_peer.port() != 0, "TURN relay peer port is zero");
        ensure!(opener.session_id() == session_id, "opener session identifier mismatch");
        ensure!(sealer.session_id() == session_id, "sealer session identifier mismatch");
        if let Some(context) = path_context {
            context.validate().context("validate registered TURN path context")?;
        }

        let mut sessions = self.sessions.write().await;
        let mut clients = self.clients.write().await;
        ensure!(!sessions.contains_key(&session_id), "TURN session already exists");
        let group_id = path_context.map(|context| context.group_id);
        let mut replaced_sessions = Vec::new();
        if let Some(route) = clients.get_mut(&client_ipv4) {
            ensure!(group_id.is_some() && route.group_id == group_id,
                "client IPv4 address is already owned by another tunnel group");
            ensure!(!route.sessions.contains(&session_id), "TURN session already routed");
            let context = path_context.context("multipath route requires path context")?;
            let replaced: Vec<[u8; 8]> = route.sessions.iter().copied().filter(|id| {
                sessions.get(id).and_then(|entry| entry.path_context)
                    .is_some_and(|existing| existing.path_id == context.path_id)
            }).collect();
            for old_id in replaced {
                sessions.remove(&old_id);
                route.sessions.retain(|id| *id != old_id);
                replaced_sessions.push(old_id);
            }
            route.sessions.push(session_id);
        } else {
            clients.insert(client_ipv4, ClientRoute {
                group_id,
                sessions: vec![session_id],
            });
        }
        let session = Arc::new(GatewaySession {
            client_ipv4,
            relay_peer,
            path_context,
            lease_generation,
            crypto: Mutex::new(SessionCrypto { opener, sealer }),
            last_activity: Mutex::new(Instant::now()),
        });
        sessions.insert(session_id, session);
        drop(clients);
        drop(sessions);
        if !replaced_sessions.is_empty() {
            if let Ok(mut scheduler) = self.downlink_scheduler.lock() {
                for old_id in replaced_sessions {
                    scheduler.remove_session(old_id);
                }
            }
        }
        Ok(())
    }

    pub async fn unregister_session(&self, session_id: [u8; 8]) -> bool {
        let removed = {
            let mut sessions = self.sessions.write().await;
            let mut clients = self.clients.write().await;
            if let Some(session) = sessions.remove(&session_id) {
                let mut group_empty = false;
                if let Some(route) = clients.get_mut(&session.client_ipv4) {
                    route.sessions.retain(|id| *id != session_id);
                    group_empty = route.sessions.is_empty();
                }
                if group_empty {
                    clients.remove(&session.client_ipv4);
                }
                Some((session.client_ipv4, session.path_context, session.lease_generation, group_empty))
            } else {
                None
            }
        };
        if let Some((address, path_context, generation, group_empty)) = removed {
            if let Ok(mut scheduler) = self.downlink_scheduler.lock() {
                scheduler.remove_session(session_id);
            }
            self.release_session_lease(address, path_context, generation, group_empty).await;
            true
        } else {
            false
        }
    }

    /// Remove sessions that have had no authenticated traffic for the idle
    /// timeout and return their virtual addresses to the handshake allocator.
    pub async fn expire_idle_sessions(&self, now: Instant, idle_timeout: Duration) -> Vec<Ipv4Addr> {
        let expired = {
            let mut sessions = self.sessions.write().await;
            let mut clients = self.clients.write().await;
            let expired_ids: Vec<[u8; 8]> = sessions.iter()
                .filter_map(|(session_id, session)| {
                    let last = session.last_activity.lock().ok().map(|value| *value)?;
                    (now.saturating_duration_since(last) >= idle_timeout).then_some(*session_id)
                })
                .collect();
            let mut leases = Vec::with_capacity(expired_ids.len());
            for session_id in expired_ids {
                if let Some(session) = sessions.remove(&session_id) {
                    let mut group_empty = false;
                    if let Some(route) = clients.get_mut(&session.client_ipv4) {
                        route.sessions.retain(|id| *id != session_id);
                        group_empty = route.sessions.is_empty();
                    }
                    if group_empty {
                        clients.remove(&session.client_ipv4);
                    }
                    leases.push((session_id, session.client_ipv4, session.path_context, session.lease_generation, group_empty));
                }
            }
            leases
        };
        let mut released = Vec::new();
        for (session_id, address, path_context, generation, group_empty) in expired {
            if let Ok(mut scheduler) = self.downlink_scheduler.lock() {
                scheduler.remove_session(session_id);
            }
            self.release_session_lease(address, path_context, generation, group_empty).await;
            if group_empty {
                released.push(address);
            }
        }
        released
    }

    async fn release_session_lease(
        &self,
        address: Ipv4Addr,
        path_context: Option<TurnPathContext>,
        generation: Option<[u8; 16]>,
        group_empty: bool,
    ) {
        if let Some(service) = self.handshake.lock().await.as_mut() {
            if let (Some(context), Some(generation)) = (path_context, generation) {
                service.release_path(context, generation);
            } else if group_empty {
                service.release_virtual_ipv4(address);
            }
        }
    }

    /// Receive relay datagrams continuously. A fixed set of bounded shards
    /// preserves FIFO for each session while processing unrelated sessions in parallel.
    pub async fn run(self: Arc<Self>) -> Result<()> {
        let mut senders = Vec::with_capacity(DATAGRAM_DISPATCH_SHARDS);
        let mut workers = tokio::task::JoinSet::new();
        for _ in 0..DATAGRAM_DISPATCH_SHARDS {
            let (sender, mut receiver) = mpsc::channel::<(Vec<u8>, SocketAddr)>(
                DATAGRAM_DISPATCH_CAPACITY,
            );
            senders.push(sender);
            let gateway = Arc::clone(&self);
            workers.spawn(async move {
                while let Some((datagram, source)) = receiver.recv().await {
                    gateway.process_datagram(&datagram, source).await;
                }
            });
        }

        let mut buffer = vec![0u8; UDP_BUFFER_SIZE];
        let mut maintenance = tokio::time::interval(SESSION_MAINTENANCE_INTERVAL);
        loop {
            tokio::select! {
                received = self.socket.recv_from(&mut buffer) => {
                    let (length, source) = received.context("receive TURN relay datagram")?;
                    let datagram = buffer[..length].to_vec();
                    let shard = datagram_dispatch_shard(&datagram);
                    if senders[shard].try_send((datagram, source)).is_err() {
                        // Drop newest under pressure; never block socket intake or
                        // move a packet to another shard, which could reorder a session.
                        self.counters.queue_drops.fetch_add(1, Ordering::Relaxed);
                    }
                }
                _ = maintenance.tick() => {
                    self.expire_idle_sessions(Instant::now(), SESSION_IDLE_TIMEOUT).await;
                }
                joined = workers.join_next() => {
                    match joined {
                        Some(Ok(())) => anyhow::bail!("TURN datagram dispatcher worker stopped"),
                        Some(Err(error)) => return Err(error).context("TURN datagram dispatcher worker failed"),
                        None => anyhow::bail!("TURN datagram dispatcher has no workers"),
                    }
                }
            }
        }
    }

    async fn process_datagram(&self, datagram: &[u8], source: SocketAddr) {
        // TURN removes ChannelData framing before forwarding a datagram to
        // the peer. The gateway therefore receives raw UDP payloads.
        if datagram.starts_with(b"GHHS") {
            if self.process_handshake(datagram, source).await.is_err() {
                self.counters.rejected_packet.fetch_add(1, Ordering::Relaxed);
            }
            return;
        }
        let session_id = match protected_frame_session_id(datagram) {
            Ok(session_id) => session_id,
            Err(_) => {
                self.counters.malformed.fetch_add(1, Ordering::Relaxed);
                return;
            }
        };
        let session = self.sessions.read().await.get(&session_id).cloned();
        let Some(session) = session else {
            self.counters.rejected_session.fetch_add(1, Ordering::Relaxed);
            return;
        };
        if source != session.relay_peer {
            self.counters.rejected_source.fetch_add(1, Ordering::Relaxed);
            return;
        }
        let decoded = {
            let mut crypto = match session.crypto.lock() {
                Ok(crypto) => crypto,
                Err(_) => {
                    self.counters.rejected_packet.fetch_add(1, Ordering::Relaxed);
                    return;
                }
            };
            crypto.opener.open(datagram)
        };
        let plaintext = match decoded {
            Ok(plaintext) => plaintext,
            Err(_) => {
                self.counters.rejected_packet.fetch_add(1, Ordering::Relaxed);
                return;
            }
        };
        if plaintext.len() == 12
            && plaintext[..4] == *ghulakh_protocol::secure_frame::SESSION_KEEPALIVE_PAYLOAD
        {
            if let Ok(mut last_activity) = session.last_activity.lock() {
                *last_activity = Instant::now();
            }
            let nonce = u64::from_be_bytes(plaintext[4..12].try_into().expect("validated keepalive length"));
            let response = {
                let mut crypto = match session.crypto.lock() {
                    Ok(crypto) => crypto,
                    Err(_) => {
                        self.counters.rejected_packet.fetch_add(1, Ordering::Relaxed);
                        return;
                    }
                };
                match crypto.sealer.seal(&ghulakh_protocol::secure_frame::keepalive_ack(nonce)) {
                    Ok(response) => response,
                    Err(_) => {
                        self.counters.rejected_packet.fetch_add(1, Ordering::Relaxed);
                        return;
                    }
                }
            };
            if self.socket.send_to(&response, source).await.is_err() {
                self.counters.rejected_packet.fetch_add(1, Ordering::Relaxed);
            }
            return;
        }
        let packet = match DataDatagram::decode(&plaintext) {
            Ok(packet) if packet.kind == IpPacketKind::Ipv4 => packet,
            _ => {
                self.counters.rejected_packet.fetch_add(1, Ordering::Relaxed);
                return;
            }
        };
        if let Ok(mut last_activity) = session.last_activity.lock() {
            *last_activity = Instant::now();
        }
        if packet.packet.len() < 20
            || Ipv4Addr::new(packet.packet[12], packet.packet[13], packet.packet[14], packet.packet[15])
                != session.client_ipv4
        {
            self.counters.rejected_packet.fetch_add(1, Ordering::Relaxed);
            return;
        }
        match self.tun_ingress.try_send(packet) {
            Ok(()) => {
                self.counters.accepted.fetch_add(1, Ordering::Relaxed);
            }
            Err(_) => {
                self.counters.queue_drops.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Route a packet read from server TUN to the registered client whose
    /// virtual IPv4 address is the packet destination.
    pub async fn send_downlink(&self, packet: &DataDatagram) -> Result<()> {
        ensure!(packet.kind == IpPacketKind::Ipv4, "TURN gateway currently supports IPv4 only");
        ensure!(packet.packet.len() >= 20, "IPv4 packet is truncated");
        let destination = Ipv4Addr::new(
            packet.packet[16], packet.packet[17], packet.packet[18], packet.packet[19],
        );
        let route = self.clients.read().await.get(&destination).cloned()
            .context("no active TURN session group for packet destination")?;
        let now = Instant::now();
        let sessions = self.sessions.read().await;
        let active_paths: Vec<([u8; 8], Arc<GatewaySession>)> = route.sessions.iter()
            .filter_map(|session_id| {
                let session = sessions.get(session_id)?.clone();
                let last_activity = *session.last_activity.lock().ok()?;
                (now.saturating_duration_since(last_activity) < SESSION_IDLE_TIMEOUT)
                    .then_some((*session_id, session))
            })
            .collect();
        drop(sessions);
        ensure!(!active_paths.is_empty(), "TURN session group has no recently authenticated paths");
        let active_ids: Vec<[u8; 8]> = active_paths.iter().map(|(id, _)| *id).collect();
        let selected_id = self.downlink_scheduler.lock()
            .map_err(|_| anyhow::anyhow!("TURN downlink scheduler lock poisoned"))?
            .select(&active_ids, destination, &packet.packet, now);
        let session = active_paths.iter().find(|(id, _)| *id == selected_id)
            .map(|(_, session)| Arc::clone(session))
            .context("selected TURN downlink path disappeared")?;
        let encoded = {
            let mut crypto = session.crypto.lock().map_err(|_| anyhow::anyhow!("TURN session crypto lock poisoned"))?;
            crypto.sealer.seal(&packet.encode().context("encode downlink IP packet")?)
                .context("protect TURN downlink frame")?
        };
        let sent = self.socket.send_to(&encoded, session.relay_peer).await
            .context("send raw downlink payload to observed TURN relay peer")?;
        ensure!(sent == encoded.len(), "partial TURN gateway UDP datagram send");
        // Only authenticated client traffic refreshes path liveness. A local
        // UDP send succeeding does not prove the TURN allocation is still alive.
        self.counters.downlink_sent.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    pub fn stats(&self) -> TurnGatewayStats {
        TurnGatewayStats {
            accepted: self.counters.accepted.load(Ordering::Relaxed),
            malformed: self.counters.malformed.load(Ordering::Relaxed),
            rejected_source: self.counters.rejected_source.load(Ordering::Relaxed),
            rejected_session: self.counters.rejected_session.load(Ordering::Relaxed),
            rejected_packet: self.counters.rejected_packet.load(Ordering::Relaxed),
            queue_drops: self.counters.queue_drops.load(Ordering::Relaxed),
            downlink_sent: self.counters.downlink_sent.load(Ordering::Relaxed),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ghulakh_protocol::secure_frame::FrameDirection;
    use tokio::{net::UdpSocket, time::{timeout, Duration}};

    const SESSION: [u8; 8] = [0x61; 8];
    const CLIENT_IP: Ipv4Addr = Ipv4Addr::new(10, 77, 0, 2);
    const CLIENT_KEY: [u8; 32] = [0x11; 32];
    const SERVER_KEY: [u8; 32] = [0x22; 32];
    const CLIENT_PREFIX: [u8; 4] = [0x31; 4];
    const SERVER_PREFIX: [u8; 4] = [0x42; 4];

    fn packet(source: Ipv4Addr, destination: Ipv4Addr) -> DataDatagram {
        let mut bytes = vec![0u8; 20];
        bytes[0] = 0x45;
        bytes[2..4].copy_from_slice(&20u16.to_be_bytes());
        bytes[8] = 64;
        bytes[9] = 17;
        bytes[12..16].copy_from_slice(&source.octets());
        bytes[16..20].copy_from_slice(&destination.octets());
        DataDatagram { kind: IpPacketKind::Ipv4, packet: bytes }
    }

    async fn spawn_mock_turn_allocation(
        client_addr: SocketAddr,
        gateway_addr: SocketAddr,
        username: &str,
        password: &str,
    ) -> (SocketAddr, tokio::task::JoinHandle<()>) {
        use std::{collections::{HashMap, HashSet}, net::IpAddr};
        use md5::{Digest, Md5};
        use ghulakh_protocol::stun::{
            append_message_integrity, ATTR_ERROR_CODE, ATTR_NONCE, ATTR_REALM, ATTR_USERNAME,
            decode_xor_address, encode_xor_address, StunAttribute, StunClass, StunMessage,
            ATTR_CHANNEL_NUMBER, ATTR_LIFETIME, ATTR_REQUESTED_TRANSPORT,
            ATTR_XOR_PEER_ADDRESS, ATTR_XOR_RELAYED_ADDRESS,
            METHOD_ALLOCATE, METHOD_CHANNEL_BIND, METHOD_CREATE_PERMISSION, METHOD_REFRESH,
        };
        use ghulakh_protocol::turn_channel_data::{decode_channel_data, encode_channel_data};

        let client_facing = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let relay_addr = client_facing.local_addr().unwrap();
        let peer_facing = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer_addr = peer_facing.local_addr().unwrap();
        let username = username.to_owned();
        let password = password.to_owned();
        let task = tokio::spawn(async move {
            let mut permissions: HashSet<IpAddr> = HashSet::new();
            let mut channels: HashMap<u16, SocketAddr> = HashMap::new();
            let mut client_buffer = [0u8; 4096];
            let mut peer_buffer = [0u8; 4096];
            loop {
                tokio::select! {
                    received = client_facing.recv_from(&mut client_buffer) => {
                        let (length, source) = received.unwrap();
                        assert_eq!(source, client_addr);
                        if client_buffer[0] & 0xc0 == 0x40 {
                            let frame = decode_channel_data(&client_buffer[..length]).unwrap();
                            let peer = *channels.get(&frame.channel_number).unwrap();
                            assert!(permissions.contains(&peer.ip()));
                            peer_facing.send_to(frame.data, peer).await.unwrap();
                        } else {
                            let request = StunMessage::decode(&client_buffer[..length]).unwrap();
                            assert_eq!(request.class, StunClass::Request);
                            if request.attribute(ATTR_USERNAME).is_none() {
                                assert_eq!(request.method, METHOD_ALLOCATE);
                                let challenge = StunMessage {
                                    method: request.method,
                                    class: StunClass::ErrorResponse,
                                    transaction_id: request.transaction_id,
                                    attributes: vec![
                                        StunAttribute { kind: ATTR_ERROR_CODE, value: vec![0, 0, 4, 1] },
                                        StunAttribute { kind: ATTR_REALM, value: b"turn.mock".to_vec() },
                                        StunAttribute { kind: ATTR_NONCE, value: b"mock-nonce-1".to_vec() },
                                    ],
                                }.encode().unwrap();
                                client_facing.send_to(&challenge, source).await.unwrap();
                                continue;
                            }
                            assert_eq!(
                                request.attribute(ATTR_USERNAME),
                                Some(username.as_bytes()),
                            );
                            let mut attributes = Vec::new();
                            match request.method {
                                METHOD_ALLOCATE => {
                                    assert_eq!(request.attribute(ATTR_REQUESTED_TRANSPORT), Some(&[17, 0, 0, 0][..]));
                                    attributes.push(StunAttribute {
                                        kind: ATTR_XOR_RELAYED_ADDRESS,
                                        value: encode_xor_address(peer_addr, &request.transaction_id),
                                    });
                                    attributes.push(StunAttribute {
                                        kind: ATTR_LIFETIME,
                                        value: 600u32.to_be_bytes().to_vec(),
                                    });
                                }
                                METHOD_CREATE_PERMISSION => {
                                    let peer = request.attributes.iter()
                                        .find(|attribute| attribute.kind == ATTR_XOR_PEER_ADDRESS)
                                        .map(|attribute| decode_xor_address(&attribute.value, &request.transaction_id).unwrap())
                                        .unwrap();
                                    permissions.insert(peer.ip());
                                }
                                METHOD_CHANNEL_BIND => {
                                    let channel = request.attribute(ATTR_CHANNEL_NUMBER).unwrap();
                                    let number = u16::from_be_bytes([channel[0], channel[1]]);
                                    let peer = decode_xor_address(
                                        request.attribute(ATTR_XOR_PEER_ADDRESS).unwrap(),
                                        &request.transaction_id,
                                    ).unwrap();
                                    assert!(permissions.contains(&peer.ip()));
                                    channels.insert(number, peer);
                                }
                                METHOD_REFRESH => {
                                    attributes.push(StunAttribute {
                                        kind: ATTR_LIFETIME,
                                        value: 600u32.to_be_bytes().to_vec(),
                                    });
                                }
                                _ => panic!("unexpected TURN control method"),
                            }
                            let response = StunMessage {
                                method: request.method,
                                class: StunClass::SuccessResponse,
                                transaction_id: request.transaction_id,
                                attributes,
                            };
                            let mut digest = Md5::new();
                            digest.update(format!("{username}:turn.mock:{password}").as_bytes());
                            let response = append_message_integrity(&response, &digest.finalize()).unwrap();
                            client_facing.send_to(&response, source).await.unwrap();
                        }
                    }
                    received = peer_facing.recv_from(&mut peer_buffer) => {
                        let (length, source) = received.unwrap();
                        assert_eq!(source, gateway_addr);
                        let channel = channels.iter()
                            .find(|(_, peer)| **peer == gateway_addr)
                            .map(|(number, _)| *number)
                            .unwrap();
                        let response = encode_channel_data(channel, &peer_buffer[..length]).unwrap();
                        client_facing.send_to(&response, client_addr).await.unwrap();
                    }
                }
            }
        });
        (relay_addr, task)
    }

    fn udp_flow(source: Ipv4Addr, destination: Ipv4Addr, source_port: u16) -> DataDatagram {
        let mut bytes = vec![0u8; 28];
        bytes[0] = 0x45;
        bytes[2..4].copy_from_slice(&28u16.to_be_bytes());
        bytes[8] = 64;
        bytes[9] = 17;
        bytes[12..16].copy_from_slice(&source.octets());
        bytes[16..20].copy_from_slice(&destination.octets());
        bytes[20..22].copy_from_slice(&source_port.to_be_bytes());
        bytes[22..24].copy_from_slice(&443u16.to_be_bytes());
        bytes[24..26].copy_from_slice(&8u16.to_be_bytes());
        DataDatagram { kind: IpPacketKind::Ipv4, packet: bytes }
    }


    #[test]
    fn datagram_dispatch_keeps_each_session_on_one_fifo_shard() {
        use ghulakh_protocol::secure_frame::{FrameDirection, FrameSealer};

        let session_a = [0x11; 8];
        let session_b = [0x22; 8];
        let mut sealer_a = FrameSealer::new(
            [0x31; 32], [0x41; 4], session_a, FrameDirection::ClientToServer,
        );
        let frame_a1 = sealer_a.seal(b"first").unwrap();
        let frame_a2 = sealer_a.seal(b"second").unwrap();
        let mut sealer_b = FrameSealer::new(
            [0x32; 32], [0x42; 4], session_b, FrameDirection::ClientToServer,
        );
        let frame_b = sealer_b.seal(b"other session").unwrap();

        assert_eq!(datagram_dispatch_shard(&frame_a1), datagram_dispatch_shard(&frame_a2));
        assert!(datagram_dispatch_shard(&frame_a1) < DATAGRAM_DISPATCH_SHARDS);
        assert!(datagram_dispatch_shard(&frame_b) < DATAGRAM_DISPATCH_SHARDS);
        assert_eq!(datagram_dispatch_shard(b"GHHS-invalid"), 0);
        assert_eq!(datagram_dispatch_shard(b"malformed"), 0);
    }

    #[tokio::test]
    async fn registers_multiple_authenticated_paths_for_one_virtual_client() {
        let (gateway, _tun_rx) = TurnGateway::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let relay_a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let relay_b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let group_id = [0x73; 16];
        let session_a = [0x81; 8];
        let session_b = [0x82; 8];

        let context_a = TurnPathContext { group_id, path_id: 0, path_count: 2 };
        let context_b = TurnPathContext { group_id, path_id: 1, path_count: 2 };

        gateway.register_session_with_path(
            session_a,
            CLIENT_IP,
            relay_a.local_addr().unwrap(),
            FrameOpener::new([0x11; 32], [0x31; 4], session_a, FrameDirection::ClientToServer),
            FrameSealer::new([0x22; 32], [0x42; 4], session_a, FrameDirection::ServerToClient),
            Some(context_a),
        ).await.unwrap();
        gateway.register_session_with_path(
            session_b,
            CLIENT_IP,
            relay_b.local_addr().unwrap(),
            FrameOpener::new([0x12; 32], [0x32; 4], session_b, FrameDirection::ClientToServer),
            FrameSealer::new([0x23; 32], [0x43; 4], session_b, FrameDirection::ServerToClient),
            Some(context_b),
        ).await.unwrap();

        let route = gateway.clients.read().await.get(&CLIENT_IP).cloned().unwrap();
        assert_eq!(route.group_id, Some(group_id));
        assert_eq!(route.sessions.len(), 2);

        assert!(gateway.unregister_session(session_a).await);
        let route = gateway.clients.read().await.get(&CLIENT_IP).cloned().unwrap();
        assert_eq!(route.sessions, vec![session_b]);

        assert!(gateway.unregister_session(session_b).await);
        assert!(!gateway.clients.read().await.contains_key(&CLIENT_IP));
    }

    #[tokio::test]
    async fn downlink_skips_path_without_recent_authenticated_client_traffic() {
        let (gateway, _tun_rx) = TurnGateway::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let relay_a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let relay_b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let group_id = [0x74; 16];
        let session_a = [0x83; 8];
        let session_b = [0x84; 8];

        for (session_id, relay, path_id, key) in [
            (session_a, &relay_a, 0u16, [0x51; 32]),
            (session_b, &relay_b, 1u16, [0x52; 32]),
        ] {
            let context = TurnPathContext { group_id, path_id, path_count: 2 };
            gateway.register_session_with_path(
                session_id,
                CLIENT_IP,
                relay.local_addr().unwrap(),
                FrameOpener::new(key, [0x61; 4], session_id, FrameDirection::ClientToServer),
                FrameSealer::new(key, [0x71; 4], session_id, FrameDirection::ServerToClient),
                Some(context),
            ).await.unwrap();
        }

        let stale = gateway.sessions.read().await.get(&session_a).cloned().unwrap();
        *stale.last_activity.lock().unwrap() =
            Instant::now() - SESSION_IDLE_TIMEOUT - Duration::from_secs(1);

        let outbound = packet(Ipv4Addr::new(203, 0, 113, 10), CLIENT_IP);
        gateway.send_downlink(&outbound).await.unwrap();

        let mut buffer = [0u8; 1500];
        let (length, _) = timeout(Duration::from_secs(1), relay_b.recv_from(&mut buffer))
            .await.unwrap().unwrap();
        assert!(length > 0);
        assert!(timeout(Duration::from_millis(30), relay_a.recv_from(&mut buffer)).await.is_err());
    }

    #[tokio::test]
    async fn multipath_gateway_forwards_authenticated_uplink_and_flow_affine_downlink() {
        let (gateway, mut tun_rx) =
            TurnGateway::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let relay_a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let relay_b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let group_id = [0x75; 16];
        let session_a = [0x91; 8];
        let session_b = [0x92; 8];
        let client_key_a = [0x11; 32];
        let client_key_b = [0x12; 32];
        let server_key_a = [0x21; 32];
        let server_key_b = [0x22; 32];
        let client_prefix_a = [0x31; 4];
        let client_prefix_b = [0x32; 4];
        let server_prefix_a = [0x41; 4];
        let server_prefix_b = [0x42; 4];

        for (session_id, relay, path_id, client_key, client_prefix, server_key, server_prefix) in [
            (session_a, &relay_a, 0u16, client_key_a, client_prefix_a, server_key_a, server_prefix_a),
            (session_b, &relay_b, 1u16, client_key_b, client_prefix_b, server_key_b, server_prefix_b),
        ] {
            gateway.register_session_with_path(
                session_id,
                CLIENT_IP,
                relay.local_addr().unwrap(),
                FrameOpener::new(
                    client_key,
                    client_prefix,
                    session_id,
                    FrameDirection::ClientToServer,
                ),
                FrameSealer::new(
                    server_key,
                    server_prefix,
                    session_id,
                    FrameDirection::ServerToClient,
                ),
                Some(TurnPathContext { group_id, path_id, path_count: 2 }),
            ).await.unwrap();
        }

        // Each independent path authenticates an uplink with its own key and
        // session ID. The server accepts both into the same client TUN.
        let uplink_a = packet(CLIENT_IP, Ipv4Addr::new(1, 1, 1, 1));
        let uplink_b = packet(CLIENT_IP, Ipv4Addr::new(8, 8, 8, 8));
        for (session_id, relay, key, prefix, uplink) in [
            (session_a, &relay_a, client_key_a, client_prefix_a, uplink_a.clone()),
            (session_b, &relay_b, client_key_b, client_prefix_b, uplink_b.clone()),
        ] {
            let mut sealer = FrameSealer::new(
                key,
                prefix,
                session_id,
                FrameDirection::ClientToServer,
            );
            let frame = sealer.seal(&uplink.encode().unwrap()).unwrap();
            gateway.process_datagram(&frame, relay.local_addr().unwrap()).await;
        }
        assert_eq!(
            timeout(Duration::from_secs(1), tun_rx.recv()).await.unwrap().unwrap(),
            uplink_a
        );
        assert_eq!(
            timeout(Duration::from_secs(1), tun_rx.recv()).await.unwrap().unwrap(),
            uplink_b
        );

        let mut opener_a = FrameOpener::new(
            server_key_a,
            server_prefix_a,
            session_a,
            FrameDirection::ServerToClient,
        );
        let mut opener_b = FrameOpener::new(
            server_key_b,
            server_prefix_b,
            session_b,
            FrameDirection::ServerToClient,
        );

        // Find two distinct UDP flows that the deterministic flow hash maps
        // to different paths. Each flow must remain on its selected path.
        let mut flows: [Option<(usize, DataDatagram)>; 2] = [None, None];
        for source_port in 1..=u16::MAX {
            let mut bytes = vec![0u8; 28];
            bytes[0] = 0x45;
            bytes[2..4].copy_from_slice(&28u16.to_be_bytes());
            bytes[8] = 64;
            bytes[9] = 17;
            bytes[12..16].copy_from_slice(&[203, 0, 113, 9]);
            bytes[16..20].copy_from_slice(&CLIENT_IP.octets());
            bytes[20..22].copy_from_slice(&source_port.to_be_bytes());
            bytes[22..24].copy_from_slice(&443u16.to_be_bytes());
            bytes[24..26].copy_from_slice(&8u16.to_be_bytes());
            let flow = DataDatagram { kind: IpPacketKind::Ipv4, packet: bytes };
            let path = (ghulakh_protocol::ip_flow::flow_hash(&flow.packet) as usize) % 2;
            if flows[path].is_none() {
                flows[path] = Some((path, flow));
            }
            if flows.iter().all(Option::is_some) {
                break;
            }
        }
        let flows = flows.map(Option::unwrap);

        for (expected_path, flow) in flows {
            gateway.send_downlink(&flow).await.unwrap();
            let mut buffer = [0u8; 1500];
            let (length, _) = if expected_path == 0 {
                timeout(Duration::from_secs(1), relay_a.recv_from(&mut buffer))
                    .await.unwrap().unwrap()
            } else {
                timeout(Duration::from_secs(1), relay_b.recv_from(&mut buffer))
                    .await.unwrap().unwrap()
            };
            let plaintext = if expected_path == 0 {
                opener_a.open(&buffer[..length]).unwrap()
            } else {
                opener_b.open(&buffer[..length]).unwrap()
            };
            assert_eq!(DataDatagram::decode(&plaintext).unwrap(), flow);
            let other = if expected_path == 0 { &relay_b } else { &relay_a };
            assert!(timeout(Duration::from_millis(25), other.recv_from(&mut buffer)).await.is_err());
        }

        assert_eq!(gateway.stats().accepted, 2);
        assert_eq!(gateway.stats().downlink_sent, 2);
    }

    #[tokio::test]
    async fn full_mock_turn_client_to_server_to_client_tunnel() {
        use std::{
            collections::{HashMap, HashSet},
            net::{IpAddr, SocketAddr, UdpSocket as StdUdpSocket},
        };
        use super::super::turn_handshake_service::{CredentialVerifier, TurnHandshakeService};
        use md5::{Digest, Md5};
        use ghulakh_protocol::{
            session_handshake::NoiseServerKeyPair,
            stun::{
                append_message_integrity, ATTR_ERROR_CODE, ATTR_NONCE, ATTR_REALM, ATTR_USERNAME,
                decode_xor_address, encode_xor_address, StunAttribute, StunClass, StunMessage,
                ATTR_CHANNEL_NUMBER, ATTR_LIFETIME, ATTR_REQUESTED_TRANSPORT,
                ATTR_XOR_PEER_ADDRESS, ATTR_XOR_RELAYED_ADDRESS,
                METHOD_ALLOCATE, METHOD_CHANNEL_BIND, METHOD_CREATE_PERMISSION, METHOD_REFRESH,
            },
            turn_channel_data::{decode_channel_data, encode_channel_data},
        };
        use ghulakh_transport::{
            turn_client::{TurnClientRuntime, DEFAULT_TURN_CHANNEL},
            turn_credentials::TurnCredentials,
        };
        use tokio::{net::UdpSocket as TokioUdpSocket, sync::oneshot};

        // Model TURN's client-facing server socket separately from the
        // allocation's peer-facing relayed socket. The gateway must observe
        // the relayed tuple, not the TURN control endpoint.
        let relay = TokioUdpSocket::bind("127.0.0.1:0").await.unwrap();
        let relay_addr = relay.local_addr().unwrap();
        let peer_socket = TokioUdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer_addr = peer_socket.local_addr().unwrap();
        let (gateway, mut tun_rx) = TurnGateway::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let gateway_addr = gateway.local_addr().unwrap();

        let keypair = Arc::new(NoiseServerKeyPair::generate().unwrap());
        let verifier: Arc<CredentialVerifier> = Arc::new(|candidate| candidate == b"device-secret");
        let service = TurnHandshakeService::new(Arc::clone(&keypair), verifier).unwrap();
        gateway.install_handshake_service(service).await.unwrap();
        let gateway_task = {
            let gateway = Arc::clone(&gateway);
            tokio::spawn(async move { gateway.run().await })
        };

        let protected_socket = StdUdpSocket::bind("127.0.0.1:0").unwrap();
        protected_socket.set_nonblocking(true).unwrap();
        let client_addr = protected_socket.local_addr().unwrap();
        let credentials_json = serde_json::json!({
            "turn_server": {
                "username": "temporary-user",
                "credential": "temporary-password",
                "urls": [format!("turn:{}?transport=udp", relay_addr)]
            }
        }).to_string();
        let credentials = TurnCredentials::from_vk_response_json(&credentials_json).unwrap();

        let pinned_key = keypair.public_key();
        let (shutdown_tx, mut shutdown_rx) = oneshot::channel::<()>();
        let relay_task = {
            let relay_socket = Arc::new(relay);
            let peer_socket = Arc::new(peer_socket);
            let client_facing = Arc::clone(&relay_socket);
            let peer_facing = Arc::clone(&peer_socket);
            tokio::spawn(async move {
                let mut permissions: HashSet<IpAddr> = HashSet::new();
                let mut channels: HashMap<u16, SocketAddr> = HashMap::new();
                let mut client_buffer = [0u8; 4096];
                let mut peer_buffer = [0u8; 4096];
                loop {
                    tokio::select! {
                        _ = &mut shutdown_rx => break,
                        received = client_facing.recv_from(&mut client_buffer) => {
                            let (length, source) = received.unwrap();
                            assert_eq!(source, client_addr);
                            if client_buffer[0] & 0xc0 == 0x40 {
                                let frame = decode_channel_data(&client_buffer[..length]).unwrap();
                                let peer = *channels.get(&frame.channel_number).unwrap();
                                assert!(permissions.contains(&peer.ip()));
                                // TURN strips ChannelData framing before sending
                                // the payload from the allocation's relayed socket.
                                peer_facing.send_to(frame.data, peer).await.unwrap();
                            } else {
                                let request = StunMessage::decode(&client_buffer[..length]).unwrap();
                                assert_eq!(request.class, StunClass::Request);
                                if request.attribute(ATTR_USERNAME).is_none() {
                                    assert_eq!(request.method, METHOD_ALLOCATE);
                                    let challenge = StunMessage {
                                        method: request.method,
                                        class: StunClass::ErrorResponse,
                                        transaction_id: request.transaction_id,
                                        attributes: vec![
                                            StunAttribute { kind: ATTR_ERROR_CODE, value: vec![0, 0, 4, 1] },
                                            StunAttribute { kind: ATTR_REALM, value: b"turn.mock".to_vec() },
                                            StunAttribute { kind: ATTR_NONCE, value: b"mock-nonce-1".to_vec() },
                                        ],
                                    }.encode().unwrap();
                                    client_facing.send_to(&challenge, source).await.unwrap();
                                    continue;
                                }
                                let mut attributes = Vec::new();
                                match request.method {
                                    METHOD_ALLOCATE => {
                                        assert_eq!(request.attribute(ATTR_REQUESTED_TRANSPORT), Some(&[17, 0, 0, 0][..]));
                                        attributes.push(StunAttribute {
                                            kind: ATTR_XOR_RELAYED_ADDRESS,
                                            value: encode_xor_address(peer_addr, &request.transaction_id),
                                        });
                                        attributes.push(StunAttribute {
                                            kind: ATTR_LIFETIME,
                                            value: 600u32.to_be_bytes().to_vec(),
                                        });
                                    }
                                    METHOD_CREATE_PERMISSION => {
                                        let peer = request.attributes.iter()
                                            .find(|attribute| attribute.kind == ATTR_XOR_PEER_ADDRESS)
                                            .map(|attribute| decode_xor_address(&attribute.value, &request.transaction_id).unwrap())
                                            .unwrap();
                                        permissions.insert(peer.ip());
                                    }
                                    METHOD_CHANNEL_BIND => {
                                        let channel = request.attribute(ATTR_CHANNEL_NUMBER).unwrap();
                                        let number = u16::from_be_bytes([channel[0], channel[1]]);
                                        let peer = decode_xor_address(
                                            request.attribute(ATTR_XOR_PEER_ADDRESS).unwrap(),
                                            &request.transaction_id,
                                        ).unwrap();
                                        assert!(permissions.contains(&peer.ip()));
                                        channels.insert(number, peer);
                                    }
                                    METHOD_REFRESH => {
                                        attributes.push(StunAttribute {
                                            kind: ATTR_LIFETIME,
                                            value: 600u32.to_be_bytes().to_vec(),
                                        });
                                    }
                                    _ => panic!("unexpected TURN control method"),
                                }
                                let response = StunMessage {
                                    method: request.method,
                                    class: StunClass::SuccessResponse,
                                    transaction_id: request.transaction_id,
                                    attributes,
                                };
                                let mut digest = Md5::new();
                                digest.update(b"temporary-user:turn.mock:temporary-password");
                                let integrity_key = digest.finalize();
                                let response = append_message_integrity(&response, &integrity_key).unwrap();
                                client_facing.send_to(&response, source).await.unwrap();
                            }
                        }
                        received = peer_facing.recv_from(&mut peer_buffer) => {
                            let (length, source) = received.unwrap();
                            assert_eq!(source, gateway_addr);
                            // The allocation relay socket receives raw peer data
                            // and re-encapsulates it as ChannelData to the client.
                            let channel = channels.iter()
                                .find(|(_, peer)| **peer == gateway_addr)
                                .map(|(number, _)| *number)
                                .unwrap();
                            let response = encode_channel_data(channel, &peer_buffer[..length]).unwrap();
                            client_facing.send_to(&response, client_addr).await.unwrap();
                        }
                    }
                }
            })
        };

        let client = TurnClientRuntime::connect(
            protected_socket,
            credentials,
            gateway_addr,
            pinned_key,
            b"device-secret",
        ).await.unwrap();
        let config = client.config();
        assert_eq!(config.virtual_ipv4, Ipv4Addr::new(10, 77, 0, 2));
        assert_eq!(config.mtu, 1100);
        assert_eq!(DEFAULT_TURN_CHANNEL, 0x4001);

        let uplink = packet(config.virtual_ipv4, Ipv4Addr::new(1, 1, 1, 1));
        client.send_packet(uplink.clone()).await.unwrap();
        let received_uplink = timeout(Duration::from_secs(2), tun_rx.recv())
            .await.unwrap().unwrap();
        assert_eq!(received_uplink, uplink);

        let downlink = packet(Ipv4Addr::new(1, 1, 1, 1), config.virtual_ipv4);
        gateway.send_downlink(&downlink).await.unwrap();
        let received_downlink = timeout(Duration::from_secs(2), client.receive_packet())
            .await.unwrap().unwrap();
        assert_eq!(received_downlink, downlink);
        assert_eq!(gateway.stats().accepted, 1);

        client.close();
        let _ = shutdown_tx.send(());
        relay_task.abort();
        gateway_task.abort();
    }

    #[tokio::test]
    async fn full_mock_multipath_turn_allocations_recover_after_simultaneous_relay_loss() {
        use std::net::UdpSocket as StdUdpSocket;
        use super::super::turn_handshake_service::{CredentialVerifier, TurnHandshakeService};
        use ghulakh_protocol::{
            session_handshake::NoiseServerKeyPair,
            turn_path_context::TurnPathContext,
            ip_flow::flow_hash,
        };
        use ghulakh_transport::{
            turn_client::{TurnClientPathGroup, TurnClientRuntime},
            turn_credentials::TurnCredentials,
        };

        let (gateway, mut tun_rx) =
            TurnGateway::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let gateway_addr = gateway.local_addr().unwrap();
        let keypair = Arc::new(NoiseServerKeyPair::generate().unwrap());
        let verifier: Arc<CredentialVerifier> =
            Arc::new(|candidate| candidate == b"device-secret");
        let service = TurnHandshakeService::new(Arc::clone(&keypair), verifier).unwrap();
        gateway.install_handshake_service(service).await.unwrap();
        let gateway_task = {
            let gateway = Arc::clone(&gateway);
            tokio::spawn(async move { gateway.run().await })
        };

        let group_id = [0x9a; 16];
        let mut relay_tasks = Vec::new();
        let mut connect_tasks = Vec::new();
        for path_id in 0..2u16 {
            let protected = StdUdpSocket::bind("127.0.0.1:0").unwrap();
            protected.set_nonblocking(true).unwrap();
            let client_addr = protected.local_addr().unwrap();
            let (relay_addr, relay_task) =
                spawn_mock_turn_allocation(
                    client_addr,
                    gateway_addr,
                    "temporary-user",
                    "temporary-password",
                ).await;
            relay_tasks.push(relay_task);

            let credentials_json = serde_json::json!({
                "turn_server": {
                    "username": "temporary-user",
                    "credential": "temporary-password",
                    "urls": [format!("turn:{}?transport=udp", relay_addr)]
                }
            }).to_string();
            let credentials = TurnCredentials::from_vk_response_json(&credentials_json).unwrap();
            let pinned_key = keypair.public_key().to_vec();
            let context = TurnPathContext { group_id, path_id, path_count: 2 };
            connect_tasks.push(tokio::spawn(async move {
                TurnClientRuntime::connect_with_path_context(
                    protected,
                    credentials,
                    gateway_addr,
                    &pinned_key,
                    b"device-secret",
                    context,
                ).await
            }));
        }

        let mut paths = Vec::new();
        for task in connect_tasks {
            paths.push(task.await.unwrap().unwrap());
        }
        let group = TurnClientPathGroup::new(paths).unwrap();
        assert_eq!(group.active_paths(), 2);
        assert_eq!(group.config().virtual_ipv4, CLIENT_IP);
        assert_eq!(group.config().mtu, 1100);

        // Generate one authenticated UDP flow for each path. Each allocation
        // performs its own TURN control exchange and Noise XX handshake.
        let mut uplinks: [Option<DataDatagram>; 2] = [None, None];
        for port in 10000..=u16::MAX {
            let candidate = udp_flow(CLIENT_IP, Ipv4Addr::new(1, 1, 1, 1), port);
            let path = (flow_hash(&candidate.packet) as usize) % 2;
            if uplinks[path].is_none() {
                uplinks[path] = Some(candidate);
            }
            if uplinks.iter().all(Option::is_some) {
                break;
            }
        }
        let uplinks = uplinks.map(Option::unwrap);
        for uplink in &uplinks {
            group.send_packet(uplink.clone()).await.unwrap();
        }

        let mut received = vec![
            timeout(Duration::from_secs(2), tun_rx.recv()).await.unwrap().unwrap(),
            timeout(Duration::from_secs(2), tun_rx.recv()).await.unwrap().unwrap(),
        ];
        received.sort_by_key(|packet| packet.packet[20..22].to_vec());
        let mut expected = uplinks.to_vec();
        expected.sort_by_key(|packet| packet.packet[20..22].to_vec());
        assert_eq!(received, expected);
        assert_eq!(gateway.stats().accepted, 2);

        // Downlink is independently protected on each allocation and merged
        // by the client group. Verify both paths before simulating path loss.
        let mut downlinks: [Option<DataDatagram>; 2] = [None, None];
        for port in 20000..=u16::MAX {
            let candidate = udp_flow(Ipv4Addr::new(1, 1, 1, 1), CLIENT_IP, port);
            let path = (flow_hash(&candidate.packet) as usize) % 2;
            if downlinks[path].is_none() {
                downlinks[path] = Some(candidate);
            }
            if downlinks.iter().all(Option::is_some) {
                break;
            }
        }
        let downlinks = downlinks.map(Option::unwrap);
        for downlink in &downlinks {
            gateway.send_downlink(downlink).await.unwrap();
        }
        let mut merged = vec![
            timeout(Duration::from_secs(2), group.receive_packet()).await.unwrap().unwrap(),
            timeout(Duration::from_secs(2), group.receive_packet()).await.unwrap().unwrap(),
        ];
        merged.sort_by_key(|packet| packet.packet[20..22].to_vec());
        let mut expected_downlinks = downlinks.to_vec();
        expected_downlinks.sort_by_key(|packet| packet.packet[20..22].to_vec());
        assert_eq!(merged, expected_downlinks);
        assert_eq!(gateway.stats().downlink_sent, 2);

        // Kill both TURN relay allocations. The client must detect the missing
        // authenticated keepalive acknowledgements, mark both paths failed,
        // fetch fresh credentials, and establish two new allocations/handshakes.
        for task in relay_tasks.drain(..) {
            task.abort();
        }
        timeout(Duration::from_secs(55), async {
            loop {
                if group.failed_path_ids() == vec![0, 1] {
                    break;
                }
                tokio::task::yield_now().await;
            }
        }).await.expect("both relay failures must be detected by path-health timeout");
        assert_eq!(group.active_paths(), 0);

        let mut replacement_tasks = Vec::new();
        let mut replacement_relays = Vec::new();
        for path_id in 0..2u16 {
            let protected = StdUdpSocket::bind("127.0.0.1:0").unwrap();
            protected.set_nonblocking(true).unwrap();
            let client_addr = protected.local_addr().unwrap();
            let username = format!("recovery-user-{path_id}");
            let password = format!("recovery-password-{path_id}");
            let (relay_addr, relay_task) = spawn_mock_turn_allocation(
                client_addr,
                gateway_addr,
                &username,
                &password,
            ).await;
            replacement_relays.push(relay_task);

            // A new credentials response is issued for each replacement
            // allocation; neither old TURN credentials nor old UDP sockets
            // are reused.
            let credentials_json = serde_json::json!({
                "turn_server": {
                    "username": username,
                    "credential": password,
                    "urls": [format!("turn:{}?transport=udp", relay_addr)]
                }
            }).to_string();
            let credentials = TurnCredentials::from_vk_response_json(&credentials_json).unwrap();
            let pinned_key = keypair.public_key().to_vec();
            let context = TurnPathContext { group_id, path_id, path_count: 2 };
            replacement_tasks.push(tokio::spawn(async move {
                TurnClientRuntime::connect_with_path_context(
                    protected,
                    credentials,
                    gateway_addr,
                    &pinned_key,
                    b"device-secret",
                    context,
                ).await
            }));
        }

        let mut replacements = Vec::new();
        for task in replacement_tasks {
            replacements.push(task.await.unwrap().unwrap());
        }
        for replacement in replacements {
            group.replace_path(replacement).unwrap();
        }
        assert_eq!(group.active_paths(), 2);
        assert!(group.failed_path_ids().is_empty());
        assert_eq!(
            gateway.clients.read().await.get(&CLIENT_IP).unwrap().sessions.len(),
            2,
            "gateway must contain exactly the two newly authenticated paths",
        );

        // Prove both newly allocated paths carry authenticated uplink and
        // downlink after recovery, while retaining the original tunnel IPv4.
        let mut recovered_uplinks: [Option<DataDatagram>; 2] = [None, None];
        for port in 30000..=u16::MAX {
            let candidate = udp_flow(CLIENT_IP, Ipv4Addr::new(9, 9, 9, 9), port);
            let path = (flow_hash(&candidate.packet) as usize) % 2;
            recovered_uplinks[path].get_or_insert(candidate);
            if recovered_uplinks.iter().all(Option::is_some) {
                break;
            }
        }
        let recovered_uplinks = recovered_uplinks.map(Option::unwrap);
        for packet in &recovered_uplinks {
            group.send_packet(packet.clone()).await.unwrap();
        }
        let mut recovered_at_gateway = vec![
            timeout(Duration::from_secs(2), tun_rx.recv()).await.unwrap().unwrap(),
            timeout(Duration::from_secs(2), tun_rx.recv()).await.unwrap().unwrap(),
        ];
        recovered_at_gateway.sort_by_key(|packet| packet.packet[20..22].to_vec());
        let mut expected_recovered = recovered_uplinks.to_vec();
        expected_recovered.sort_by_key(|packet| packet.packet[20..22].to_vec());
        assert_eq!(recovered_at_gateway, expected_recovered);
        assert_eq!(gateway.stats().accepted, 4);

        let mut recovered_downlinks: [Option<DataDatagram>; 2] = [None, None];
        for port in 40000..=u16::MAX {
            let candidate = udp_flow(Ipv4Addr::new(9, 9, 9, 9), CLIENT_IP, port);
            let path = (flow_hash(&candidate.packet) as usize) % 2;
            recovered_downlinks[path].get_or_insert(candidate);
            if recovered_downlinks.iter().all(Option::is_some) {
                break;
            }
        }
        let recovered_downlinks = recovered_downlinks.map(Option::unwrap);
        for packet in &recovered_downlinks {
            gateway.send_downlink(packet).await.unwrap();
        }
        let mut received_recovered = vec![
            timeout(Duration::from_secs(2), group.receive_packet()).await.unwrap().unwrap(),
            timeout(Duration::from_secs(2), group.receive_packet()).await.unwrap().unwrap(),
        ];
        received_recovered.sort_by_key(|packet| packet.packet[20..22].to_vec());
        let mut expected_downlinks = recovered_downlinks.to_vec();
        expected_downlinks.sort_by_key(|packet| packet.packet[20..22].to_vec());
        assert_eq!(received_recovered, expected_downlinks);
        assert_eq!(gateway.stats().downlink_sent, 4);

        group.close();
        for task in replacement_relays {
            task.abort();
        }
        gateway_task.abort();
    }

    #[tokio::test]
    async fn completes_noise_handshake_and_registers_session_before_uplink() {
        use ghulakh_protocol::{
            session_handshake::{NoiseServerKeyPair, TurnSessionConfig},
            turn_handshake::TurnHandshakeClient,
        };
        use super::super::turn_handshake_service::{CredentialVerifier, TurnHandshakeService};

        let relay = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let relay_addr = relay.local_addr().unwrap();
        let _ = relay_addr;
        let (gateway, mut tun_rx) = TurnGateway::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let gateway_addr = gateway.local_addr().unwrap();
        let keypair = Arc::new(NoiseServerKeyPair::generate().unwrap());
        let verifier: Arc<CredentialVerifier> = Arc::new(|candidate| candidate == b"test-device");
        let service = TurnHandshakeService::new(Arc::clone(&keypair), verifier).unwrap();
        gateway.install_handshake_service(service).await.unwrap();

        let gateway_task = {
            let gateway = Arc::clone(&gateway);
            tokio::spawn(async move { gateway.run().await })
        };

        let credential = b"test-device";
        let (mut client, client_init) =
            TurnHandshakeClient::new(keypair.public_key(), credential, [0x71; 16]).unwrap();
        relay.send_to(&client_init, gateway_addr).await.unwrap();

        let mut buffer = [0u8; 2048];
        let (length, source) = timeout(Duration::from_secs(2), relay.recv_from(&mut buffer))
            .await.unwrap().unwrap();
        assert_eq!(source, gateway_addr);
        let client_finish = client.receive_server_response(&buffer[..length]).unwrap();
        relay.send_to(&client_finish, gateway_addr).await.unwrap();

        let (length, source) = timeout(Duration::from_secs(2), relay.recv_from(&mut buffer))
            .await.unwrap().unwrap();
        assert_eq!(source, gateway_addr);
        let (keys, config_payload) = client.receive_server_ack_with_payload(&buffer[..length]).unwrap();
        let config = TurnSessionConfig::decode(&config_payload).unwrap();
        assert_eq!(config.virtual_ipv4, Ipv4Addr::new(10, 77, 0, 2));
        assert_eq!(config.mtu, 1100);

        let session_id = keys.session_id();
        let (mut client_tx, mut client_rx) = keys.into_client_codecs();
        let session = gateway.sessions.read().await.get(&session_id).cloned();
        let session = session.unwrap();
        let previous_activity = *session.last_activity.lock().unwrap();
        let nonce = 0x0102_0304_0506_0708;
        let keepalive = client_tx.seal(&ghulakh_protocol::secure_frame::keepalive_request(nonce)).unwrap();
        relay.send_to(&keepalive, gateway_addr).await.unwrap();
        let (length, source) = timeout(Duration::from_secs(2), relay.recv_from(&mut buffer)).await.unwrap().unwrap();
        assert_eq!(source, gateway_addr);
        assert_eq!(
            client_rx.open(&buffer[..length]).unwrap(),
            ghulakh_protocol::secure_frame::keepalive_ack(nonce),
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
        assert!(*session.last_activity.lock().unwrap() > previous_activity);
        assert!(tun_rx.try_recv().is_err());

        let uplink = packet(config.virtual_ipv4, Ipv4Addr::new(1, 1, 1, 1));
        let protected = client_tx.seal(&uplink.encode().unwrap()).unwrap();
        relay.send_to(&protected, gateway_addr).await.unwrap();
        let received = timeout(Duration::from_secs(2), tun_rx.recv()).await.unwrap().unwrap();
        assert_eq!(received, uplink);
        assert_eq!(gateway.stats().accepted, 1);
        gateway_task.abort();
    }

    #[tokio::test]
    async fn routes_authenticated_uplink_to_tun_and_downlink_to_relay_tuple() {
        let relay = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let relay_addr = relay.local_addr().unwrap();
        let _ = relay_addr;
        let (gateway, mut tun_rx) = TurnGateway::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let gateway_addr = gateway.local_addr().unwrap();
        gateway.register_session(
            SESSION,
            CLIENT_IP,
            relay_addr,
            FrameOpener::new(CLIENT_KEY, CLIENT_PREFIX, SESSION, FrameDirection::ClientToServer),
            FrameSealer::new(SERVER_KEY, SERVER_PREFIX, SESSION, FrameDirection::ServerToClient),
        ).await.unwrap();

        let gateway_task = {
            let gateway = Arc::clone(&gateway);
            tokio::spawn(async move { gateway.run().await })
        };

        let uplink = packet(CLIENT_IP, Ipv4Addr::new(203, 0, 113, 9));
        let mut client_tx = FrameSealer::new(CLIENT_KEY, CLIENT_PREFIX, SESSION, FrameDirection::ClientToServer);
        let protected = client_tx.seal(&uplink.encode().unwrap()).unwrap();
        relay.send_to(&protected, gateway_addr).await.unwrap();

        let received = timeout(Duration::from_secs(2), tun_rx.recv()).await.unwrap().unwrap();
        assert_eq!(received, uplink);

        let downlink = packet(Ipv4Addr::new(203, 0, 113, 9), CLIENT_IP);
        gateway.send_downlink(&downlink).await.unwrap();
        let mut buffer = [0u8; 2048];
        let (length, source) = timeout(Duration::from_secs(2), relay.recv_from(&mut buffer)).await.unwrap().unwrap();
        assert_eq!(source, gateway_addr);
        let mut client_rx = FrameOpener::new(SERVER_KEY, SERVER_PREFIX, SESSION, FrameDirection::ServerToClient);
        let plaintext = client_rx.open(&buffer[..length]).unwrap();
        assert_eq!(DataDatagram::decode(&plaintext).unwrap(), downlink);

        assert_eq!(gateway.stats().accepted, 1);
        assert_eq!(gateway.stats().downlink_sent, 1);
        gateway_task.abort();
    }

    #[tokio::test]
    async fn rejects_spoofed_inner_source_and_replayed_frame() {
        let relay = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let relay_addr = relay.local_addr().unwrap();
        let _ = relay_addr;
        let (gateway, mut tun_rx) = TurnGateway::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let gateway_addr = gateway.local_addr().unwrap();
        gateway.register_session(
            SESSION, CLIENT_IP, relay_addr,
            FrameOpener::new(CLIENT_KEY, CLIENT_PREFIX, SESSION, FrameDirection::ClientToServer),
            FrameSealer::new(SERVER_KEY, SERVER_PREFIX, SESSION, FrameDirection::ServerToClient),
        ).await.unwrap();
        let gateway_task = {
            let gateway = Arc::clone(&gateway);
            tokio::spawn(async move { gateway.run().await })
        };

        let mut client_tx = FrameSealer::new(
            CLIENT_KEY, CLIENT_PREFIX, SESSION, FrameDirection::ClientToServer,
        );
        let spoofed = packet(Ipv4Addr::new(10, 77, 0, 99), Ipv4Addr::new(203, 0, 113, 2));
        let spoofed_frame = client_tx.seal(&spoofed.encode().unwrap()).unwrap();
        relay.send_to(&spoofed_frame, gateway_addr).await.unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(tun_rx.try_recv().is_err());
        assert_eq!(gateway.stats().rejected_packet, 1);

        let valid = packet(CLIENT_IP, Ipv4Addr::new(203, 0, 113, 2));
        let valid_frame = client_tx.seal(&valid.encode().unwrap()).unwrap();
        let valid_datagram = valid_frame;
        relay.send_to(&valid_datagram, gateway_addr).await.unwrap();
        assert_eq!(
            timeout(Duration::from_secs(2), tun_rx.recv()).await.unwrap().unwrap(),
            valid
        );
        relay.send_to(&valid_datagram, gateway_addr).await.unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(gateway.stats().accepted, 1);
        assert_eq!(gateway.stats().rejected_packet, 2);
        gateway_task.abort();
    }

    #[tokio::test]
    async fn expires_idle_session_and_removes_client_route() {
        let relay = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let relay_addr = relay.local_addr().unwrap();
        let (gateway, _tun_rx) = TurnGateway::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        gateway.register_session(
            SESSION,
            CLIENT_IP,
            relay_addr,
            FrameOpener::new(CLIENT_KEY, CLIENT_PREFIX, SESSION, FrameDirection::ClientToServer),
            FrameSealer::new(SERVER_KEY, SERVER_PREFIX, SESSION, FrameDirection::ServerToClient),
        ).await.unwrap();

        let session = gateway.sessions.read().await.get(&SESSION).unwrap().clone();
        *session.last_activity.lock().unwrap() = Instant::now() - Duration::from_secs(120);
        let expired = gateway.expire_idle_sessions(
            Instant::now(),
            Duration::from_secs(60),
        ).await;
        assert_eq!(expired, vec![CLIENT_IP]);
        assert!(gateway.sessions.read().await.is_empty());
        assert!(gateway.clients.read().await.is_empty());
    }

    #[tokio::test]
    async fn rejects_wrong_relay_source_before_frame_authentication() {
        let _relay = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let wrong_relay = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let relay_addr = _relay.local_addr().unwrap();
        let (gateway, _tun_rx) = TurnGateway::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        gateway.register_session(
            SESSION, CLIENT_IP, relay_addr,
            FrameOpener::new(CLIENT_KEY, CLIENT_PREFIX, SESSION, FrameDirection::ClientToServer),
            FrameSealer::new(SERVER_KEY, SERVER_PREFIX, SESSION, FrameDirection::ServerToClient),
        ).await.unwrap();
        let gateway_addr = gateway.local_addr().unwrap();
        let gateway_task = {
            let gateway = Arc::clone(&gateway);
            tokio::spawn(async move { gateway.run().await })
        };
        let mut tx = FrameSealer::new(CLIENT_KEY, CLIENT_PREFIX, SESSION, FrameDirection::ClientToServer);
        let protected = tx.seal(&packet(CLIENT_IP, Ipv4Addr::new(203, 0, 113, 1)).encode().unwrap()).unwrap();
        let datagram = protected;
        wrong_relay.send_to(&datagram, gateway_addr).await.unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(gateway.stats().rejected_source, 1);
        gateway_task.abort();
    }


    #[tokio::test]
    async fn accepts_packet_loss_and_reordering_but_rejects_replay() {
        let relay = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let relay_addr = relay.local_addr().unwrap();
        let (gateway, mut tun_rx) = TurnGateway::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        gateway.register_session(
            SESSION,
            CLIENT_IP,
            relay_addr,
            FrameOpener::new(CLIENT_KEY, CLIENT_PREFIX, SESSION, FrameDirection::ClientToServer),
            FrameSealer::new(SERVER_KEY, SERVER_PREFIX, SESSION, FrameDirection::ServerToClient),
        ).await.unwrap();

        let gateway_task = {
            let gateway = Arc::clone(&gateway);
            tokio::spawn(async move { gateway.run().await })
        };

        let destination = Ipv4Addr::new(203, 0, 113, 17);
        let mut client_tx = FrameSealer::new(
            CLIENT_KEY,
            CLIENT_PREFIX,
            SESSION,
            FrameDirection::ClientToServer,
        );

        // Sequence 0 is intentionally lost. Deliver sequence 2 before 1 to
        // model network loss and reordering without weakening replay protection.
        let lost = client_tx.seal(&packet(CLIENT_IP, destination).encode().unwrap()).unwrap();
        let reordered = client_tx.seal(&packet(CLIENT_IP, destination).encode().unwrap()).unwrap();
        let first = client_tx.seal(&packet(CLIENT_IP, destination).encode().unwrap()).unwrap();
        drop(lost);

        relay.send_to(&first, gateway.local_addr().unwrap()).await.unwrap();
        relay.send_to(&reordered, gateway.local_addr().unwrap()).await.unwrap();

        let received_a = timeout(Duration::from_secs(2), tun_rx.recv()).await.unwrap().unwrap();
        let received_b = timeout(Duration::from_secs(2), tun_rx.recv()).await.unwrap().unwrap();
        let expected = packet(CLIENT_IP, destination);
        assert_eq!(received_a, expected);
        assert_eq!(received_b, expected);
        assert_eq!(gateway.stats().accepted, 2);

        // Replaying an authenticated datagram must still be rejected.
        relay.send_to(&reordered, gateway.local_addr().unwrap()).await.unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(gateway.stats().accepted, 2);
        assert_eq!(gateway.stats().rejected_packet, 1);
        gateway_task.abort();
    }

    fn scheduler_udp_flow(source_port: u16, total_len: usize) -> Vec<u8> {
        let mut bytes = vec![0u8; total_len];
        bytes[0] = 0x45;
        bytes[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
        bytes[9] = 17;
        bytes[12..16].copy_from_slice(&[10, 77, 0, 2]);
        bytes[16..20].copy_from_slice(&[203, 0, 113, 8]);
        bytes[20..22].copy_from_slice(&source_port.to_be_bytes());
        bytes[22..24].copy_from_slice(&443u16.to_be_bytes());
        bytes
    }

    #[test]
    fn downlink_scheduler_fallback_considers_paths_before_cursor() {
        let mut scheduler = DownlinkScheduler::new();
        let active = [[0x11; 8], [0x22; 8], [0x33; 8]];
        scheduler.cursor = 1;
        scheduler.tokens.insert(active[0], 5.0);
        scheduler.tokens.insert(active[1], 1.0);
        scheduler.tokens.insert(active[2], 1.0);

        assert_eq!(scheduler.choose(&active, Instant::now(), 100), active[0]);
    }

    #[test]
    fn downlink_scheduler_keeps_token_state_isolated_between_client_groups() {
        let mut scheduler = DownlinkScheduler::new();
        let first_group = [[0xa1; 8], [0xa2; 8]];
        let second_group = [[0xb1; 8], [0xb2; 8]];
        let now = Instant::now();

        // Initialize accounting for every path in the group before comparing
        // snapshots; select() only refills the path it actually chooses.
        for id in first_group {
            scheduler.refill(id, now);
        }
        scheduler.select(&first_group, CLIENT_IP, &scheduler_udp_flow(16_101, 1200), now);
        let first_group_tokens = first_group.map(|id| scheduler.tokens[&id]);
        scheduler.select(
            &second_group,
            Ipv4Addr::new(10, 77, 0, 3),
            &scheduler_udp_flow(16_102, 1200),
            now + Duration::from_millis(1),
        );

        for (id, expected) in first_group.into_iter().zip(first_group_tokens) {
            assert_eq!(scheduler.tokens.get(&id), Some(&expected));
            assert!(scheduler.last_update.contains_key(&id));
        }
        for id in second_group {
            assert!(scheduler.tokens.contains_key(&id));
        }

        scheduler.remove_session(first_group[0]);
        assert!(!scheduler.tokens.contains_key(&first_group[0]));
        assert!(!scheduler.last_update.contains_key(&first_group[0]));
    }

    #[test]
    fn downlink_scheduler_reassigns_flow_after_path_loss_and_expires_idle_state() {
        let mut scheduler = DownlinkScheduler::new();
        let active = [[0x61; 8], [0x62; 8]];
        let start = Instant::now();
        let flow = scheduler_udp_flow(16_000, 1200);
        let original = scheduler.select(&active, CLIENT_IP, &flow, start);
        let surviving = if original == active[0] { active[1] } else { active[0] };
        assert_eq!(scheduler.select(&[surviving], CLIENT_IP, &flow, start + Duration::from_millis(1)), surviving);

        scheduler.evict_counter = FLOW_EVICT_EVERY - 1;
        let expired_at = start + FLOW_IDLE_TTL + Duration::from_secs(1);
        scheduler.select(&[surviving], CLIENT_IP, &scheduler_udp_flow(16_001, 1200), expired_at);
        let key = (CLIENT_IP, ghulakh_protocol::ip_flow::ipv4_flow_key(&flow).unwrap());
        assert!(!scheduler.flows.contains_key(&key));
    }

    #[test]
    fn downlink_scheduler_distributes_distinct_flows_between_paths() {
        let mut scheduler = DownlinkScheduler::new();
        let active = [[0x11; 8], [0x22; 8]];
        let now = Instant::now();
        let first = scheduler.select(&active, CLIENT_IP, &scheduler_udp_flow(10001, 1200), now);
        let second = scheduler.select(&active, CLIENT_IP, &scheduler_udp_flow(10002, 1200), now);
        assert_ne!(first, second);
    }

    #[test]
    fn downlink_scheduler_balances_independent_flows_across_ten_paths() {
        let mut scheduler = DownlinkScheduler::new();
        let active: Vec<[u8; 8]> = (0..10).map(|index| [index + 1; 8]).collect();
        let start = Instant::now();
        let mut per_path = HashMap::<[u8; 8], usize>::new();

        for flow_index in 0..1_000u16 {
            let flow = scheduler_udp_flow(20_000 + flow_index, 1200);
            let first_at = start + Duration::from_micros(u64::from(flow_index) * 1_000);
            let selected = scheduler.select(&active, CLIENT_IP, &flow, first_at);
            *per_path.entry(selected).or_default() += 1;

            // Every packet within the current 16 KiB burst must retain the
            // same allocation, even while other flows are being scheduled.
            for packet_index in 1..10u64 {
                let now = first_at + Duration::from_micros(packet_index * 100);
                assert_eq!(
                    scheduler.select(&active, CLIENT_IP, &flow, now),
                    selected,
                    "flow {flow_index} changed allocation inside its burst",
                );
            }
        }

        assert_eq!(
            per_path.len(),
            active.len(),
            "independent flows must reach every configured path: {per_path:?}",
        );
    }

    #[test]
    fn downlink_scheduler_clears_full_flow_table_after_expiry_sweep() {
        let mut scheduler = DownlinkScheduler::new();
        let active = [[0x41; 8], [0x42; 8]];
        let start = Instant::now();

        for (index, port) in (10_000..10_000 + FLOW_TABLE_MAX as u16).enumerate() {
            let flow = scheduler_udp_flow(port, 1200);
            scheduler.select(&active, CLIENT_IP, &flow, start + Duration::from_micros(index as u64));
        }
        assert_eq!(scheduler.flows.len(), FLOW_TABLE_MAX);

        let overflow = scheduler_udp_flow(30_000, 1200);
        let selected = scheduler.select(
            &active,
            CLIENT_IP,
            &overflow,
            start + Duration::from_micros(FLOW_TABLE_MAX as u64),
        );

        assert!(active.contains(&selected));
        assert_eq!(scheduler.flows.len(), 1);
        assert!(scheduler.flows.contains_key(&(
            CLIENT_IP,
            ghulakh_protocol::ip_flow::ipv4_flow_key(&overflow).unwrap(),
        )));
    }

    #[test]
    fn downlink_scheduler_reclaims_expired_flow_at_capacity() {
        let mut scheduler = DownlinkScheduler::new();
        let active = [[0x43; 8], [0x44; 8]];
        let start = Instant::now();

        for (index, port) in (10_000..10_000 + FLOW_TABLE_MAX as u16).enumerate() {
            let flow = scheduler_udp_flow(port, 1200);
            scheduler.select(&active, CLIENT_IP, &flow, start + Duration::from_micros(index as u64));
        }
        let expired_key = (CLIENT_IP, ghulakh_protocol::ip_flow::ipv4_flow_key(&scheduler_udp_flow(10_000, 1200)).unwrap());
        let sweep_at = start + FLOW_IDLE_TTL + Duration::from_secs(1);
        for (key, state) in &mut scheduler.flows {
            state.last_seen = if *key == expired_key { start } else { sweep_at };
        }
        scheduler.evict_counter = FLOW_EVICT_EVERY - 1;
        let new_flow = scheduler_udp_flow(30_001, 1200);
        scheduler.select(&active, CLIENT_IP, &new_flow, sweep_at);

        assert_eq!(scheduler.flows.len(), FLOW_TABLE_MAX);
        assert!(!scheduler.flows.contains_key(&expired_key));
        assert!(scheduler.flows.contains_key(&(CLIENT_IP, ghulakh_protocol::ip_flow::ipv4_flow_key(&new_flow).unwrap())));
    }

    #[test]
    fn downlink_scheduler_scopes_identical_flows_to_virtual_clients() {
        let mut scheduler = DownlinkScheduler::new();
        let active = [[0x51; 8], [0x52; 8]];
        let flow = scheduler_udp_flow(15_000, 1200);
        scheduler.select(&active, CLIENT_IP, &flow, Instant::now());
        scheduler.select(&active, Ipv4Addr::new(10, 77, 0, 3), &flow, Instant::now());
        assert_eq!(scheduler.flows.len(), 2);
    }

    #[test]
    fn downlink_scheduler_keeps_each_flow_on_one_path() {
        let mut scheduler = DownlinkScheduler::new();
        let active = [[0x31; 8], [0x32; 8]];
        let start = Instant::now();
        let game_flow = scheduler_udp_flow(12000, 120);
        let game_path = scheduler.select(&active, CLIENT_IP, &game_flow, start);
        for index in 1..250 {
            let now = start + Duration::from_micros(index * 100);
            assert_eq!(scheduler.select(&active, CLIENT_IP, &game_flow, now), game_path);
        }

        let another_flow = scheduler_udp_flow(12002, 1200);
        let another_path = scheduler.select(&active, CLIENT_IP, &another_flow, start);
        assert_ne!(another_path, game_path);
    }

    #[test]
    fn downlink_scheduler_distributes_sustained_bulk_udp_across_paths() {
        let mut scheduler = DownlinkScheduler::new();
        let active: Vec<[u8; 8]> = (0..10).map(|index| [index + 1; 8]).collect();
        let start = Instant::now();
        // Model a sustained QUIC-like download: large UDP datagrams arrive
        // continuously, while each flowlet remains on one allocation.
        let flow = scheduler_udp_flow(12_001, 1300);
        let mut per_path = HashMap::<[u8; 8], usize>::new();

        for index in 0..4_000u64 {
            let now = start + Duration::from_micros(index * 520);
            let path = scheduler.select(&active, CLIENT_IP, &flow, now);
            *per_path.entry(path).or_default() += 1;
        }

        assert_eq!(
            per_path.len(),
            active.len(),
            "bulk flow should use every active path: {per_path:?}",
        );
        let busiest = per_path.values().copied().max().unwrap_or_default();
        assert!(
            busiest < 800,
            "bulk flow remains pinned to too few paths: {per_path:?}",
        );
    }

}
