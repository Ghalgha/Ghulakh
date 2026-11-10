use anyhow::{bail, Context, Result};
use bytes::Bytes;
use ghulakh_protocol::{
    validate_envelope, validate_message, ControlEnvelope, ControlMessage, DataDatagram,
    IpPacketKind, MAX_CONTROL_BODY, MAX_DATAGRAM_SIZE, PROTOCOL_VERSION,
};
use quinn::{crypto::rustls::QuicServerConfig, Connection, Endpoint};
use rand::{rngs::OsRng, RngCore};
use rustls::pki_types::CertificateDer;
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    env, fs, fs::File, io::BufReader, net::{Ipv4Addr, SocketAddr},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};
use subtle::ConstantTimeEq;
use tokio::{
    io::AsyncWriteExt,
    sync::{mpsc, RwLock},
};
use tun_rs::DeviceBuilder;

const ALPN: &[u8] = b"ghulakh/1";
const DATAGRAM_RECEIVE_BUDGET: usize = MAX_DATAGRAM_SIZE * 32;
const TUN_MTU: u16 = 1100;
const TUN_QUEUE_CAPACITY: usize = 512;
const TUN_SERVER_IPV4: &str = "10.77.0.1";
type SessionMap = Arc<RwLock<HashMap<Ipv4Addr, Connection>>>;

#[derive(Default)]
struct DatagramMetrics {
    accepted: std::sync::atomic::AtomicU64,
    rejected: std::sync::atomic::AtomicU64,
}

struct IpAllocator {
    next_host: std::sync::atomic::AtomicU32,
}

impl IpAllocator {
    fn new() -> Self {
        Self {
            next_host: std::sync::atomic::AtomicU32::new(2),
        }
    }

    fn allocate(&self) -> Result<Ipv4Addr> {
        let host = self.next_host.fetch_add(1, Ordering::Relaxed);
        anyhow::ensure!(host <= 65_534, "client IPv4 address pool exhausted");
        Ok(Ipv4Addr::new(10, 77, (host >> 8) as u8, host as u8))
    }
}

fn ipv4_endpoints(packet: &[u8]) -> Option<(Ipv4Addr, Ipv4Addr)> {
    if packet.len() < 20 || packet[0] >> 4 != 4 {
        return None;
    }
    Some((
        Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]),
        Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]),
    ))
}

fn start_tun(name: &str, sessions: SessionMap) -> Result<mpsc::Sender<Vec<u8>>> {
    let device = Arc::new(
        DeviceBuilder::new()
            .name(name)
            .ipv4(TUN_SERVER_IPV4, 16, None)
            .mtu(TUN_MTU)
            .build_async()
            .with_context(|| format!("create TUN interface {name}"))?,
    );
    let (packet_sender, mut packet_receiver) = mpsc::channel::<Vec<u8>>(TUN_QUEUE_CAPACITY);

    let writer = Arc::clone(&device);
    let _tun_writer_task = tokio::spawn(async move {
        while let Some(packet) = packet_receiver.recv().await {
            if let Err(error) = writer.send(&packet).await {
                eprintln!("TUN write failed: {error}");
                break;
            }
        }
    });

    let reader = Arc::clone(&device);
    let _tun_reader_task = tokio::spawn(async move {
        let mut buffer = vec![0u8; 65_535];
        loop {
            let length = match reader.recv(&mut buffer).await {
                Ok(length) => length,
                Err(error) => {
                    eprintln!("TUN read failed: {error}");
                    break;
                }
            };
            let Some((_, destination)) = ipv4_endpoints(&buffer[..length]) else {
                continue;
            };
            let connection = sessions.read().await.get(&destination).cloned();
            let Some(connection) = connection else {
                continue;
            };
            let datagram = DataDatagram {
                kind: IpPacketKind::Ipv4,
                packet: buffer[..length].to_vec(),
            };
            let Ok(encoded) = datagram.encode() else {
                continue;
            };
            let Some(maximum) = connection.max_datagram_size() else {
                continue;
            };
            if encoded.len() <= maximum {
                let _ = connection.send_datagram(Bytes::from(encoded));
            }
        }
    });

    Ok(packet_sender)
}

fn load_server_config(cert_path: &str, key_path: &str) -> Result<quinn::ServerConfig> {
    let mut cert_reader = BufReader::new(
        File::open(cert_path)
            .with_context(|| format!("open certificate file: {cert_path}"))?,
    );
    let cert_chain: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_reader)
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("parse certificate chain")?;
    anyhow::ensure!(!cert_chain.is_empty(), "certificate chain is empty");

    let mut key_reader = BufReader::new(
        File::open(key_path).with_context(|| format!("open private key file: {key_path}"))?,
    );
    let key = rustls_pemfile::private_key(&mut key_reader)
        .context("parse private key")?
        .context("private key file contains no supported key")?;

    let mut tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, key)
        .context("configure TLS certificate")?;
    tls.alpn_protocols = vec![ALPN.to_vec()];

    let crypto = QuicServerConfig::try_from(tls).context("configure QUIC TLS crypto")?;
    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    let mut transport = quinn::TransportConfig::default();
    transport.max_concurrent_bidi_streams(quinn::VarInt::from_u32(16));
    transport.max_concurrent_uni_streams(quinn::VarInt::from_u32(0));
    transport.datagram_receive_buffer_size(Some(DATAGRAM_RECEIVE_BUDGET));
    transport.datagram_send_buffer_size(DATAGRAM_RECEIVE_BUDGET);
    transport.keep_alive_interval(Some(Duration::from_secs(15)));
    server_config.transport_config(Arc::new(transport));
    Ok(server_config)
}

fn load_credential_hashes(path: &str) -> Result<Vec<[u8; 32]>> {
    let content = fs::read_to_string(path)
        .with_context(|| format!("read credential digest file: {path}"))?;
    let mut hashes = Vec::new();

    for (line_number, line) in content.lines().enumerate() {
        let value = line.trim();
        if value.is_empty() || value.starts_with('#') {
            continue;
        }

        let decoded = hex::decode(value)
            .with_context(|| format!("invalid hex credential digest on line {}", line_number + 1))?;
        let digest: [u8; 32] = decoded.try_into().map_err(|_| {
            anyhow::anyhow!("credential digest on line {} must be 32 bytes", line_number + 1)
        })?;
        hashes.push(digest);
    }

    anyhow::ensure!(!hashes.is_empty(), "credential digest file contains no credentials");
    anyhow::ensure!(hashes.len() <= 10_000, "credential digest file exceeds 10000 entries");
    Ok(hashes)
}

fn credential_matches(candidate: &str, expected_hashes: &[[u8; 32]]) -> bool {
    let candidate_hash: [u8; 32] = Sha256::digest(candidate.as_bytes()).into();
    expected_hashes.iter().fold(false, |matched, expected| {
        bool::from(candidate_hash.ct_eq(expected)) || matched
    })
}

fn new_session_id() -> String {
    let mut bytes = [0u8; 16];
    OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

fn request_id(message: &ControlMessage) -> &str {
    match message {
        ControlMessage::ClientHello { request_id, .. }
        | ControlMessage::ServerHello { request_id, .. }
        | ControlMessage::Ping { request_id }
        | ControlMessage::Pong { request_id }
        | ControlMessage::Close { request_id } => request_id,
    }
}

async fn handle_control_stream(
    connection: Connection,
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    credential_hashes: Arc<Vec<[u8; 32]>>,
    session_id: Arc<String>,
    authenticated: Arc<AtomicBool>,
    sessions: SessionMap,
    ip_allocator: Arc<IpAllocator>,
    client_address: Arc<tokio::sync::Mutex<Option<Ipv4Addr>>>,
    tunnel_enabled: bool,
) -> Result<()> {
    let bytes = match tokio::time::timeout(
        Duration::from_secs(15),
        recv.read_to_end(MAX_CONTROL_BODY),
    )
    .await
    {
        Ok(Ok(bytes)) => bytes,
        Ok(Err(_)) | Err(_) => {
            connection.close(0u32.into(), b"invalid control stream");
            bail!("control stream read failed");
        }
    };

    if bytes.len() > MAX_CONTROL_BODY {
        connection.close(0u32.into(), b"control message too large");
        bail!("control message exceeds limit");
    }

    let envelope: ControlEnvelope = match serde_json::from_slice(&bytes) {
        Ok(envelope) => envelope,
        Err(error) => {
            connection.close(0u32.into(), b"invalid control message");
            return Err(error).context("decode control envelope");
        }
    };
    if let Err(error) = validate_envelope(
        envelope.version,
        bytes.len(),
        request_id(&envelope.message),
    )
    .and_then(|()| validate_message(&envelope.message))
    {
        connection.close(0u32.into(), b"invalid control message");
        return Err(error.into());
    }

    let response = match envelope.message {
        ControlMessage::ClientHello {
            credential,
            request_id,
        } => {
            if !credential_matches(&credential, credential_hashes.as_slice())
                || authenticated
                    .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                    .is_err()
            {
                connection.close(0u32.into(), b"authentication failed");
                bail!("client authentication failed or repeated");
            }
            let address = match ip_allocator.allocate() {
                Ok(address) => address,
                Err(error) => {
                    connection.close(0u32.into(), b"address pool exhausted");
                    return Err(error);
                }
            };
            if sessions
                .write()
                .await
                .insert(address, connection.clone())
                .is_some()
            {
                connection.close(0u32.into(), b"address collision");
                bail!("client address collision");
            }
            *client_address.lock().await = Some(address);
            ControlMessage::ServerHello {
                session_id: session_id.as_ref().clone(),
                client_ipv4: address.to_string(),
                tunnel_enabled,
                request_id,
            }
        }
        ControlMessage::Ping { request_id } if authenticated.load(Ordering::Acquire) => {
            ControlMessage::Pong { request_id }
        }
        ControlMessage::Close { .. } if authenticated.load(Ordering::Acquire) => {
            connection.close(0u32.into(), b"client requested close");
            return Ok(());
        }
        _ => {
            connection.close(0u32.into(), b"unexpected control message");
            bail!("unexpected control message or unauthenticated request");
        }
    };

    let encoded = serde_json::to_vec(&ControlEnvelope {
        version: PROTOCOL_VERSION,
        message: response,
    })?;
    if encoded.len() > MAX_CONTROL_BODY {
        bail!("internal response exceeds protocol limit");
    }
    send.write_all(&encoded)
        .await
        .context("write control response")?;
    send.finish().context("finish control response stream")?;
    Ok(())
}

#[derive(Debug, PartialEq, Eq)]
enum DatagramDisposition {
    Unauthenticated,
    Invalid,
    UnsupportedAddressFamily,
    SourceMismatch,
    DestinationBlocked,
    Accepted(Vec<u8>),
}

fn destination_allowed(address: Ipv4Addr) -> bool {
    address != Ipv4Addr::BROADCAST
        && !address.is_private()
        && !address.is_loopback()
        && !address.is_link_local()
        && !address.is_multicast()
        && !address.is_unspecified()
        && address.octets()[0] != 0
        && address.octets()[0] < 240
        && !(address.octets()[0] == 100
            && (64..=127).contains(&address.octets()[1]))
        && !(address.octets()[0] == 192
            && address.octets()[1] == 0
            && address.octets()[2] == 0)
}

fn inspect_datagram(
    bytes: &[u8],
    authenticated: bool,
    expected_source: Option<Ipv4Addr>,
) -> DatagramDisposition {
    if !authenticated || expected_source.is_none() {
        return DatagramDisposition::Unauthenticated;
    }
    match DataDatagram::decode(bytes) {
        Ok(datagram) if datagram.kind == IpPacketKind::Ipv4 => {
            let Some((source, destination)) = ipv4_endpoints(&datagram.packet) else {
                return DatagramDisposition::Invalid;
            };
            if Some(source) != expected_source {
                return DatagramDisposition::SourceMismatch;
            }
            if !destination_allowed(destination) {
                return DatagramDisposition::DestinationBlocked;
            }
            DatagramDisposition::Accepted(datagram.packet)
        }
        Ok(_) => DatagramDisposition::UnsupportedAddressFamily,
        Err(_) => DatagramDisposition::Invalid,
    }
}

async fn handle_connection(
    connection: Connection,
    credential_hashes: Arc<Vec<[u8; 32]>>,
    metrics: Arc<DatagramMetrics>,
    tun_sender: Option<mpsc::Sender<Vec<u8>>>,
    sessions: SessionMap,
    ip_allocator: Arc<IpAllocator>,
    tunnel_enabled: bool,
) -> Result<()> {
    let session_id = Arc::new(new_session_id());
    let authenticated = Arc::new(AtomicBool::new(false));
    let client_address = Arc::new(tokio::sync::Mutex::new(None));
    let mut valid_datagrams = 0u64;
    let mut rejected_datagrams = 0u64;
    let mut forwarded_datagrams = 0u64;
    let mut queue_drops = 0u64;

    loop {
        tokio::select! {
            incoming = connection.accept_bi() => {
                let (send, recv) = match incoming {
                    Ok(streams) => streams,
                    Err(_) => break,
                };
                let connection = connection.clone();
                let hashes = Arc::clone(&credential_hashes);
                let session = Arc::clone(&session_id);
                let auth = Arc::clone(&authenticated);
                let session_map = Arc::clone(&sessions);
                let allocator = Arc::clone(&ip_allocator);
                let assigned_address = Arc::clone(&client_address);
                let tun_active = tunnel_enabled;
                let _control_stream_task = tokio::spawn(async move {
                    if let Err(error) = handle_control_stream(
                        connection.clone(),
                        send,
                        recv,
                        hashes,
                        session,
                        auth,
                        session_map,
                        allocator,
                        assigned_address,
                        tun_active,
                    ).await {
                        eprintln!("control stream rejected: {error:#}");
                    }
                });
            }
            datagram = connection.read_datagram() => {
                let bytes = match datagram {
                    Ok(bytes) => bytes,
                    Err(_) => break,
                };
                let expected_source = *client_address.lock().await;
                match inspect_datagram(
                    bytes.as_ref(),
                    authenticated.load(Ordering::Acquire),
                    expected_source,
                ) {
                    DatagramDisposition::Accepted(packet) => {
                        valid_datagrams = valid_datagrams.saturating_add(1);
                        metrics.accepted.fetch_add(1, Ordering::Relaxed);
                        if let Some(sender) = &tun_sender {
                            if sender.try_send(packet).is_ok() {
                                forwarded_datagrams = forwarded_datagrams.saturating_add(1);
                            } else {
                                queue_drops = queue_drops.saturating_add(1);
                            }
                        }
                    }
                    DatagramDisposition::Unauthenticated
                    | DatagramDisposition::Invalid
                    | DatagramDisposition::UnsupportedAddressFamily
                    | DatagramDisposition::SourceMismatch
                    | DatagramDisposition::DestinationBlocked => {
                        rejected_datagrams = rejected_datagrams.saturating_add(1);
                        metrics.rejected.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        }
    }

    if let Some(address) = client_address.lock().await.take() {
        let _ = sessions.write().await.remove(&address);
    }

    if valid_datagrams > 0 || rejected_datagrams > 0 {
        eprintln!(
            "connection packets: valid={}, rejected={}, forwarded_to_tun={}, queue_drops={}, tun_enabled={}",
            valid_datagrams,
            rejected_datagrams,
            forwarded_datagrams,
            queue_drops,
            tun_sender.is_some()
        );
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let credential_path = env::var("GHULAKH_CREDENTIAL_HASHES")
        .context("set GHULAKH_CREDENTIAL_HASHES to a file of SHA-256 credential digests")?;
    let credential_hashes = Arc::new(load_credential_hashes(&credential_path)?);

    let cert_path = env::var("GHULAKH_TLS_CERT")
        .context("set GHULAKH_TLS_CERT to a PEM certificate chain")?;
    let key_path = env::var("GHULAKH_TLS_KEY")
        .context("set GHULAKH_TLS_KEY to a PEM private key")?;
    let bind: SocketAddr = env::var("GHULAKH_QUIC_BIND")
        .unwrap_or_else(|_| "0.0.0.0:4433".to_string())
        .parse()
        .context("invalid GHULAKH_QUIC_BIND address")?;

    let sessions: SessionMap = Arc::new(RwLock::new(HashMap::new()));
    let ip_allocator = Arc::new(IpAllocator::new());
    let tun_enabled = env::var("GHULAKH_TUN_ENABLED")
        .unwrap_or_else(|_| "false".to_string())
        .eq_ignore_ascii_case("true");
    let tun_sender = if tun_enabled {
        let name = env::var("GHULAKH_TUN_NAME").unwrap_or_else(|_| "ghulakh0".to_string());
        let sender = start_tun(&name, Arc::clone(&sessions))?;
        eprintln!(
            "TUN interface {} is active at {}/16 with MTU {}",
            name, TUN_SERVER_IPV4, TUN_MTU
        );
        Some(sender)
    } else {
        eprintln!("TUN forwarding is disabled; authenticated packets are validated and dropped");
        None
    };

    let server_config = load_server_config(&cert_path, &key_path)?;
    let endpoint = Endpoint::server(server_config, bind)?;

    eprintln!(
        "ГӀулакх QUIC endpoint listening on {}",
        endpoint.local_addr()?
    );
    let connection_limit = Arc::new(tokio::sync::Semaphore::new(1024));
    while let Some(connecting) = endpoint.accept().await {
        let permit = Arc::clone(&connection_limit)
            .acquire_owned()
            .await
            .context("connection limit semaphore closed")?;
        let hashes = Arc::clone(&credential_hashes);
        let metrics = Arc::new(DatagramMetrics::default());
        let sender = tun_sender.clone();
        let session_map = Arc::clone(&sessions);
        let allocator = Arc::clone(&ip_allocator);
        let _connection_task = tokio::spawn(async move {
            let _permit = permit;
            match connecting.await {
                Ok(connection) => {
                    if let Err(error) = handle_connection(
                        connection,
                        hashes,
                        metrics,
                        sender,
                        session_map,
                        allocator,
                        tun_enabled,
                    )
                    .await
                    {
                        eprintln!("connection closed: {error:#}");
                    }
                }
                Err(error) => eprintln!("QUIC handshake failed: {error}"),
            }
        });
    }

    bail!("QUIC endpoint stopped accepting connections")
}

#[cfg(test)]
mod tests {
    use super::*;
    use ghulakh_protocol::{DataDatagram, IpPacketKind};

    fn valid_ipv4_datagram(source: Ipv4Addr) -> Vec<u8> {
        let mut packet = vec![0u8; 20];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&20u16.to_be_bytes());
        packet[12..16].copy_from_slice(&source.octets());
        packet[16..20].copy_from_slice(&[1, 1, 1, 1]);
        DataDatagram {
            kind: IpPacketKind::Ipv4,
            packet,
        }
        .encode()
        .unwrap()
    }

    #[test]
    fn client_address_pool_allocates_unique_ipv4_addresses() {
        let pool = IpAllocator::new();
        assert_eq!(pool.allocate().unwrap(), Ipv4Addr::new(10, 77, 0, 2));
        assert_eq!(pool.allocate().unwrap(), Ipv4Addr::new(10, 77, 0, 3));
    }

    #[test]
    fn datagrams_are_rejected_before_authentication() {
        assert_eq!(
            inspect_datagram(
                &valid_ipv4_datagram(Ipv4Addr::new(10, 77, 0, 2)),
                false,
                None
            ),
            DatagramDisposition::Unauthenticated
        );
    }

    #[test]
    fn authenticated_datagram_requires_assigned_source_address() {
        let assigned = Ipv4Addr::new(10, 77, 0, 2);
        assert_eq!(
            inspect_datagram(&valid_ipv4_datagram(assigned), true, Some(assigned)),
            DatagramDisposition::Accepted({
                let mut packet = vec![0u8; 20];
                packet[0] = 0x45;
                packet[2..4].copy_from_slice(&20u16.to_be_bytes());
                packet[12..16].copy_from_slice(&assigned.octets());
                packet[16..20].copy_from_slice(&[1, 1, 1, 1]);
                packet
            })
        );
    }

    #[test]
    fn spoofed_source_address_is_rejected() {
        assert_eq!(
            inspect_datagram(
                &valid_ipv4_datagram(Ipv4Addr::new(10, 77, 0, 9)),
                true,
                Some(Ipv4Addr::new(10, 77, 0, 2))
            ),
            DatagramDisposition::SourceMismatch
        );
    }

    #[test]
    fn private_destinations_are_blocked_by_default() {
        assert!(!destination_allowed(Ipv4Addr::new(10, 0, 0, 1)));
        assert!(!destination_allowed(Ipv4Addr::new(192, 168, 1, 1)));
        assert!(!destination_allowed(Ipv4Addr::new(127, 0, 0, 1)));
        assert!(destination_allowed(Ipv4Addr::new(1, 1, 1, 1)));
    }

    #[test]
    fn malformed_datagram_is_rejected() {
        assert_eq!(
            inspect_datagram(b"not-a-packet", true, Some(Ipv4Addr::new(10, 77, 0, 2))),
            DatagramDisposition::Invalid
        );
    }

    #[test]
    fn credential_hash_match_is_per_device() {
        let credential = "test-only-random-credential";
        let digest: [u8; 32] = Sha256::digest(credential.as_bytes()).into();
        assert!(credential_matches(credential, &[digest]));
        assert!(!credential_matches("different-credential", &[digest]));
    }

    #[tokio::test]
    async fn native_client_authenticates_and_sends_quic_datagram() {
        use ghulakh_transport::{ClientOptions, QuicClient};

        let certificate = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let directory = tempfile::tempdir().unwrap();
        let certificate_path = directory.path().join("server-cert.pem");
        let key_path = directory.path().join("server-key.pem");
        let credential_path = directory.path().join("credential-hashes.txt");
        std::fs::write(&certificate_path, certificate.cert.pem()).unwrap();
        std::fs::write(&key_path, certificate.key_pair.serialize_pem()).unwrap();

        let credential = "integration-test-device-secret".to_string();
        let digest = hex::encode(Sha256::digest(credential.as_bytes()));
        std::fs::write(&credential_path, digest).unwrap();

        let server_config = load_server_config(
            certificate_path.to_str().unwrap(),
            key_path.to_str().unwrap(),
        )
        .unwrap();
        let endpoint = Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
        let server_addr = endpoint.local_addr().unwrap();
        let server_endpoint = endpoint.clone();
        let hashes = Arc::new(load_credential_hashes(credential_path.to_str().unwrap()).unwrap());
        let metrics = Arc::new(DatagramMetrics::default());
        let server_metrics = Arc::clone(&metrics);
        let sessions: SessionMap = Arc::new(RwLock::new(HashMap::new()));
        let server_sessions = Arc::clone(&sessions);
        let allocator = Arc::new(IpAllocator::new());
        let server_allocator = Arc::clone(&allocator);

        let server_task = tokio::spawn(async move {
            while let Some(connecting) = server_endpoint.accept().await {
                let hashes = Arc::clone(&hashes);
                let metrics = Arc::clone(&server_metrics);
                let sessions = Arc::clone(&server_sessions);
                let allocator = Arc::clone(&server_allocator);
                let _server_connection_task = tokio::spawn(async move {
                    if let Ok(connection) = connecting.await {
                        let _ = handle_connection(
                            connection,
                            hashes,
                            metrics,
                            None,
                            sessions,
                            allocator,
                            false,
                        )
                        .await;
                    }
                });
            }
        });

        let client = QuicClient::connect(ClientOptions {
            server_addr,
            server_name: "localhost".into(),
            root_certificate_der: certificate.cert.der().to_vec(),
            credential,
            udp_socket: None,
        })
        .await
        .unwrap();

        assert_eq!(client.session_id().len(), 32);
        assert_eq!(client.client_ipv4(), "10.77.0.2");
        assert!(!client.tunnel_enabled());
        client.ping().await.unwrap();

        let assigned: Ipv4Addr = client.client_ipv4().parse().unwrap();
        client
            .send_packet(&DataDatagram {
                kind: IpPacketKind::Ipv4,
                packet: {
                    let mut ipv4 = vec![0u8; 20];
                    ipv4[0] = 0x45;
                    ipv4[2..4].copy_from_slice(&20u16.to_be_bytes());
                    ipv4[12..16].copy_from_slice(&assigned.octets());
                    ipv4[16..20].copy_from_slice(&[1, 1, 1, 1]);
                    ipv4
                },
            })
            .await
            .unwrap();

        tokio::time::timeout(Duration::from_secs(2), async {
            while metrics.accepted.load(Ordering::Relaxed) == 0 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("server did not receive the authenticated QUIC datagram");

        client.close();
        endpoint.close(0u32.into(), b"test complete");
        server_task.abort();
    }
}
