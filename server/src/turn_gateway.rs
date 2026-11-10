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
    crypto: Mutex<SessionCrypto>,
    last_activity: Mutex<Instant>,
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
    clients: RwLock<HashMap<Ipv4Addr, [u8; 8]>>,
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
        // The service has already cached ServerAck. Register the authenticated
        // session before sending it so the first client packet cannot race the
        // registration. If UDP send fails, the client retry receives this cache.
        if let Some(established) = established {
            let client_ipv4 = established.config.virtual_ipv4;
            let session_id = established.frame_keys.session_id();
            let (opener, sealer) = established.frame_keys.into_server_codecs();
            if let Err(error) = self.register_session(
                session_id,
                client_ipv4,
                established.relay_peer,
                opener,
                sealer,
            ).await {
                self.release_virtual_ipv4(client_ipv4).await;
                return Err(error).context("register authenticated TURN session after ServerAck cache");
            }
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
        ensure!(client_ipv4 != Ipv4Addr::UNSPECIFIED, "client IPv4 address is unspecified");
        ensure!(client_ipv4 != Ipv4Addr::BROADCAST, "client IPv4 address is broadcast");
        ensure!(relay_peer.port() != 0, "TURN relay peer port is zero");
        ensure!(opener.session_id() == session_id, "opener session identifier mismatch");
        ensure!(sealer.session_id() == session_id, "sealer session identifier mismatch");

        let mut sessions = self.sessions.write().await;
        let mut clients = self.clients.write().await;
        ensure!(!sessions.contains_key(&session_id), "TURN session already exists");
        ensure!(!clients.contains_key(&client_ipv4), "client IPv4 address already registered");
        let session = Arc::new(GatewaySession {
            client_ipv4,
            relay_peer,
            crypto: Mutex::new(SessionCrypto { opener, sealer }),
            last_activity: Mutex::new(Instant::now()),
        });
        sessions.insert(session_id, session);
        clients.insert(client_ipv4, session_id);
        Ok(())
    }

    pub async fn unregister_session(&self, session_id: [u8; 8]) -> bool {
        let removed = {
            let mut sessions = self.sessions.write().await;
            let mut clients = self.clients.write().await;
            if let Some(session) = sessions.remove(&session_id) {
                clients.remove(&session.client_ipv4);
                Some(session.client_ipv4)
            } else {
                None
            }
        };
        if let Some(address) = removed {
            self.release_virtual_ipv4(address).await;
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
            let expired: Vec<([u8; 8], Ipv4Addr)> = sessions.iter()
                .filter_map(|(session_id, session)| {
                    let last = session.last_activity.lock().ok().map(|value| *value)?;
                    (now.saturating_duration_since(last) >= idle_timeout)
                        .then_some((*session_id, session.client_ipv4))
                })
                .collect();
            for (session_id, address) in &expired {
                sessions.remove(session_id);
                clients.remove(address);
            }
            expired.into_iter().map(|(_, address)| address).collect::<Vec<_>>()
        };
        for address in &expired {
            self.release_virtual_ipv4(*address).await;
        }
        expired
    }

    async fn release_virtual_ipv4(&self, address: Ipv4Addr) {
        if let Some(service) = self.handshake.lock().await.as_mut() {
            service.release_virtual_ipv4(address);
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
        if plaintext.as_slice() == ghulakh_protocol::secure_frame::SESSION_KEEPALIVE_PAYLOAD {
            if let Ok(mut last_activity) = session.last_activity.lock() {
                *last_activity = Instant::now();
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
        let session_id = self.clients.read().await.get(&destination).copied()
            .context("no active TURN session for packet destination")?;
        let session = self.sessions.read().await.get(&session_id).cloned()
            .context("TURN session disappeared during downlink routing")?;
        let encoded = {
            let mut crypto = session.crypto.lock().map_err(|_| anyhow::anyhow!("TURN session crypto lock poisoned"))?;
            crypto.sealer.seal(&packet.encode().context("encode downlink IP packet")?)
                .context("protect TURN downlink frame")?
        };
        let sent = self.socket.send_to(&encoded, session.relay_peer).await
            .context("send raw downlink payload to observed TURN relay peer")?;
        ensure!(sent == encoded.len(), "partial TURN gateway UDP datagram send");
        if let Ok(mut last_activity) = session.last_activity.lock() {
            *last_activity = Instant::now();
        }
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
        let (mut client_tx, _) = keys.into_client_codecs();
        let session = gateway.sessions.read().await.get(&session_id).cloned();
        let session = session.unwrap();
        let previous_activity = *session.last_activity.lock().unwrap();
        let keepalive = client_tx.seal(ghulakh_protocol::secure_frame::SESSION_KEEPALIVE_PAYLOAD).unwrap();
        relay.send_to(&keepalive, gateway_addr).await.unwrap();
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

        // Sequence 1 is intentionally lost. Deliver sequence 2 before 0 to
        // model network reordering without weakening replay protection.
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
