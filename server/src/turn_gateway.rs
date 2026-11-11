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
const SESSION_IDLE_TIMEOUT: Duration = Duration::from_secs(600);
const SESSION_MAINTENANCE_INTERVAL: Duration = Duration::from_secs(30);

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

        let outcome = {
            let mut service = self.handshake.lock().await;
            let service = service.as_mut().context("TURN handshake service is not installed")?;
            service.process(payload, relay_peer, std::time::Instant::now())?
        };

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
            let replaced_generation = established.replaced_generation;
            if let Err(error) = self.register_session_with_path_generation(
                session_id,
                client_ipv4,
                established.relay_peer,
                opener,
                sealer,
                path_context.map(|context| (context, Some(handshake_id))),
            ).await {
                if let Some(context) = path_context {
                    {
                        let mut handshake = self.handshake.lock().await;
                        if let Some(service) = handshake.as_mut() {
                            service.rollback_path_replacement(
                                context,
                                handshake_id,
                                replaced_generation,
                            );
                        }
                    }
                } else {
                    self.release_session_lease(client_ipv4, None, None, true).await;
                }
                return Err(error).context("register authenticated TURN session before ServerAck commit");
            }

            let mut handshake = self.handshake.lock().await;
            let service = handshake.as_mut().context("TURN handshake service is not installed")?;
            service.commit_established_response(
                payload,
                &response,
                relay_peer,
                std::time::Instant::now(),
            ).context("commit ServerAck after gateway registration")?;
        }

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
                    leases.push((session.client_ipv4, session.path_context, session.lease_generation, group_empty));
                }
            }
            leases
        };
        let mut released = Vec::new();
        for (address, path_context, generation, group_empty) in expired {
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

    /// Receive relay datagrams continuously. Unknown sessions, wrong relay
    /// tuples, invalid protected frames and spoofed inner IP sources are dropped.
    pub async fn run(self: Arc<Self>) -> Result<()> {
        let mut buffer = vec![0u8; UDP_BUFFER_SIZE];
        let mut maintenance = tokio::time::interval(SESSION_MAINTENANCE_INTERVAL);
        loop {
            tokio::select! {
                received = self.socket.recv_from(&mut buffer) => {
                    let (length, source) = received.context("receive TURN relay datagram")?;
                    self.process_datagram(&buffer[..length], source).await;
                }
                _ = maintenance.tick() => {
                    self.expire_idle_sessions(Instant::now(), SESSION_IDLE_TIMEOUT).await;
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
        let active_paths: Vec<Arc<GatewaySession>> = route.sessions.iter()
            .filter_map(|session_id| {
                let session = sessions.get(session_id)?.clone();
                let last_activity = *session.last_activity.lock().ok()?;
                (now.saturating_duration_since(last_activity) < SESSION_IDLE_TIMEOUT)
                    .then_some(session)
            })
            .collect();
        drop(sessions);
        ensure!(!active_paths.is_empty(), "TURN session group has no recently authenticated paths");
        let selected = ghulakh_protocol::ip_flow::flow_hash(&packet.packet) as usize % active_paths.len();
        let session = Arc::clone(&active_paths[selected]);
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
    async fn full_mock_multipath_turn_allocations_share_one_tunnel_and_survive_path_removal() {
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
                spawn_mock_turn_allocation(client_addr, gateway_addr).await;
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

        // Remove one authenticated path from the gateway registry. The
        // surviving allocation remains routable for the same virtual client.
        let failed_session = {
            let sessions = gateway.sessions.read().await;
            sessions.iter()
                .find_map(|(id, session)| {
                    session.path_context
                        .filter(|context| context.path_id == 0)
                        .map(|_| *id)
                })
                .unwrap()
        };
        assert!(gateway.unregister_session(failed_session).await);
        let after_failure = udp_flow(
            Ipv4Addr::new(203, 0, 113, 7),
            CLIENT_IP,
            32123,
        );
        gateway.send_downlink(&after_failure).await.unwrap();
        let received_after_failure = timeout(
            Duration::from_secs(2),
            group.receive_packet(),
        ).await.unwrap().unwrap();
        assert_eq!(received_after_failure, after_failure);
        assert_eq!(gateway.stats().downlink_sent, 3);
        assert_eq!(gateway.clients.read().await.get(&CLIENT_IP).unwrap().sessions.len(), 1);

        group.close();
        for task in relay_tasks {
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
}
