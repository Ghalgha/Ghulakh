pub mod turn_gateway;
pub mod turn_handshake_service;

use anyhow::{bail, Context, Result};
use bytes::Bytes;
use ghulakh_protocol::{
    validate_envelope, validate_message, ControlEnvelope, ControlMessage, DataDatagram,
    IpPacketKind, MAX_CONTROL_BODY, MAX_DATAGRAM_SIZE, PROTOCOL_VERSION,
};
use quinn::{crypto::rustls::QuicServerConfig, Connection};
use rand::{rngs::OsRng, RngCore};
use rustls::pki_types::CertificateDer;
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    env, fs, fs::{File, OpenOptions}, io::{BufReader, Read, Write}, net::{Ipv4Addr, SocketAddr},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};
use subtle::ConstantTimeEq;
use tokio::sync::{mpsc, RwLock};
use tun_rs::DeviceBuilder;
use zeroize::Zeroizing;

#[allow(dead_code)]
const ALPN: &[u8] = b"ghulakh/1";
#[allow(dead_code)]
const DATAGRAM_RECEIVE_BUDGET: usize = MAX_DATAGRAM_SIZE * 32;
const TUN_MTU: u16 = 1100;
const TUN_QUEUE_CAPACITY: usize = 512;
const TUN_SERVER_IPV4: &str = "10.77.0.1";
const TUN_SERVER_IPV6: &str = "fd77:77::1";
type SessionMap = Arc<RwLock<HashMap<Ipv4Addr, Connection>>>;
type TunTaskHandles = (
    mpsc::Sender<Vec<u8>>,
    tokio::task::JoinHandle<Result<()>>,
    tokio::task::JoinHandle<Result<()>>,
);

#[allow(dead_code)]
#[derive(Default)]
struct DatagramMetrics {
    accepted: std::sync::atomic::AtomicU64,
    rejected: std::sync::atomic::AtomicU64,
}

#[allow(dead_code)]
struct IpAllocator {
    next_host: std::sync::atomic::AtomicU32,
}

#[allow(dead_code)]
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

fn start_tun(
    name: &str,
    sessions: SessionMap,
    turn_gateway: Option<Arc<turn_gateway::TurnGateway>>,
) -> Result<TunTaskHandles> {
    let mut builder = DeviceBuilder::new()
        .name(name)
        .ipv4(TUN_SERVER_IPV4, 16, None);
    if turn_gateway.is_some() {
        builder = builder.ipv6(TUN_SERVER_IPV6, 64);
    }
    let device = Arc::new(
        builder
            .mtu(TUN_MTU)
            .build_async()
            .with_context(|| format!("create TUN interface {name}"))?,
    );
    let (packet_sender, mut packet_receiver) = mpsc::channel::<Vec<u8>>(TUN_QUEUE_CAPACITY);

    let writer = Arc::clone(&device);
    let tun_writer_task = tokio::spawn(async move {
        while let Some(packet) = packet_receiver.recv().await {
            writer.send(&packet).await.context("write packet to TUN")?;
        }
        bail!("TUN packet channel closed unexpectedly")
    });

    let reader = Arc::clone(&device);
    let tun_reader_task = tokio::spawn(async move {
        let mut buffer = vec![0u8; 65_535];
        loop {
            let length = reader.recv(&mut buffer).await.context("read packet from TUN")?;
            let packet = &buffer[..length];
            let kind = match packet.first().map(|byte| byte >> 4) {
                Some(4) => IpPacketKind::Ipv4,
                Some(6) => IpPacketKind::Ipv6,
                _ => continue,
            };
            if let Some(gateway) = &turn_gateway {
                let datagram = DataDatagram {
                    kind,
                    packet: packet.to_vec(),
                };
                if let Err(error) = gateway.send_downlink(&datagram).await {
                    eprintln!("TURN downlink rejected: {error:#}");
                }
                continue;
            }
            let Some((_, destination)) = ipv4_endpoints(packet) else {
                continue;
            };
            let datagram = DataDatagram {
                kind: IpPacketKind::Ipv4,
                packet: packet.to_vec(),
            };
            let connection = sessions.read().await.get(&destination).cloned();
            let Some(connection) = connection else {
                continue;
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

    Ok((packet_sender, tun_writer_task, tun_reader_task))
}

#[allow(dead_code)]
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

// Keep scanning every digest to avoid leaking the matching entry position through timing.
#[allow(clippy::unnecessary_fold)]
fn credential_matches(candidate: &str, expected_hashes: &[[u8; 32]]) -> bool {
    let candidate_hash: [u8; 32] = Sha256::digest(candidate.as_bytes()).into();
    expected_hashes.iter().fold(false, |matched, expected| {
        bool::from(candidate_hash.ct_eq(expected)) || matched
    })
}

#[allow(dead_code)]
fn new_session_id() -> String {
    let mut bytes = [0u8; 16];
    OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

#[allow(dead_code)]
fn request_id(message: &ControlMessage) -> &str {
    match message {
        ControlMessage::ClientHello { request_id, .. }
        | ControlMessage::ServerHello { request_id, .. }
        | ControlMessage::Ping { request_id }
        | ControlMessage::Pong { request_id }
        | ControlMessage::Close { request_id } => request_id,
    }
}

// Parameters are the per-session control state; grouping them would obscure ownership
// across the spawned stream task.
#[allow(clippy::too_many_arguments)]
#[allow(dead_code)]
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
    forwarding_enabled: bool,
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
                forwarding_enabled,
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
#[allow(dead_code)]
enum DatagramDisposition {
    Unauthenticated,
    Invalid,
    UnsupportedAddressFamily,
    SourceMismatch,
    DestinationBlocked,
    Accepted(Vec<u8>),
}

#[allow(dead_code)]
fn destination_allowed(address: Ipv4Addr) -> bool {
    let octets = address.octets();
    let in_subnet = |a: u8, b: u8, c: u8, mask: u8| {
        let value = u32::from(octets[0]) << 24
            | u32::from(octets[1]) << 16
            | u32::from(octets[2]) << 8
            | u32::from(octets[3]);
        let network = u32::from(a) << 24
            | u32::from(b) << 16
            | u32::from(c) << 8;
        let prefix_mask = u32::MAX << (32 - mask);
        value & prefix_mask == network & prefix_mask
    };

    address != Ipv4Addr::BROADCAST
        && !address.is_private()
        && !address.is_loopback()
        && !address.is_link_local()
        && !address.is_multicast()
        && !address.is_unspecified()
        && octets[0] != 0
        && octets[0] < 224
        // Shared address space (100.64.0.0/10) is not public egress.
        && !(octets[0] == 100 && (64..=127).contains(&octets[1]))
        // IETF protocol assignments, documentation and benchmarking ranges.
        && !in_subnet(192, 0, 0, 24)
        && !in_subnet(192, 0, 2, 24)
        && !in_subnet(192, 88, 99, 24)
        && !in_subnet(198, 18, 0, 15)
        && !in_subnet(198, 51, 100, 24)
        && !in_subnet(203, 0, 113, 24)
}

#[allow(dead_code)]
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

// The connection task owns these independent runtime resources for its full lifetime.
#[allow(clippy::too_many_arguments)]
#[allow(dead_code)]
async fn handle_connection(
    connection: Connection,
    credential_hashes: Arc<Vec<[u8; 32]>>,
    metrics: Arc<DatagramMetrics>,
    tun_sender: Option<mpsc::Sender<Vec<u8>>>,
    sessions: SessionMap,
    ip_allocator: Arc<IpAllocator>,
    tunnel_enabled: bool,
    forwarding_enabled: bool,
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
                let routing_active = forwarding_enabled;
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
                        routing_active,
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
                        if forwarding_enabled {
                            if let Some(sender) = &tun_sender {
                                if sender.try_send(packet).is_ok() {
                                    forwarded_datagrams = forwarded_datagrams.saturating_add(1);
                                } else {
                                    queue_drops = queue_drops.saturating_add(1);
                                }
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
            "connection packets: valid={}, rejected={}, forwarded_to_tun={}, queue_drops={}, tun_enabled={}, forwarding_enabled={}",
            valid_datagrams,
            rejected_datagrams,
            forwarded_datagrams,
            queue_drops,
            tun_sender.is_some(),
            forwarding_enabled
        );
    }
    Ok(())
}

fn ensure_keygen_args(args: &[String]) -> Result<()> {
    anyhow::ensure!(
        args.len() == 4,
        "usage: ghulakh-server --generate-noise-keypair <private-hex-file> <public-hex-file>"
    );
    Ok(())
}

fn read_noise_private_key(path: &str) -> Result<Zeroizing<Vec<u8>>> {
    let mut file = File::open(path)
        .with_context(|| format!("open Noise private key file {path}"))?;
    let metadata = file.metadata()
        .with_context(|| format!("inspect Noise private key file {path}"))?;
    anyhow::ensure!(metadata.is_file(), "Noise private key path {path} is not a regular file");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = metadata.permissions().mode();
        anyhow::ensure!(
            mode & 0o077 == 0 && mode & 0o400 != 0,
            "Noise private key file {path} must be owner-readable and inaccessible to group/others (mode {:04o})",
            mode & 0o777
        );
    }
    let mut encoded = Zeroizing::new(String::new());
    file.read_to_string(&mut encoded)
        .with_context(|| format!("read Noise private key file {path}"))?;
    let encoded = encoded.trim();
    anyhow::ensure!(encoded.len() == 64, "persistent Noise private key must contain exactly 32 bytes");
    let mut decoded = Zeroizing::new([0u8; 32]);
    hex::decode_to_slice(encoded, &mut decoded[..])
        .context("decode persistent Noise private key")?;
    Ok(Zeroizing::new(decoded.to_vec()))
}

fn write_noise_key_file(path: &str, bytes: &[u8], private: bool) -> Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(if private { 0o600 } else { 0o644 });
    }
    let mut file = options.open(path)
        .with_context(|| format!("create Noise key file {path} without overwriting an existing file"))?;
    file.write_all(bytes).with_context(|| format!("write Noise key file {path}"))?;
    file.sync_all().with_context(|| format!("sync Noise key file {path}"))?;
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.get(1).is_some_and(|arg| arg == "--generate-noise-keypair") {
        ensure_keygen_args(&args)?;
        let keypair = ghulakh_protocol::session_handshake::NoiseServerKeyPair::generate()
            .context("generate persistent Noise server keypair")?;
        let private_path = &args[2];
        let public_path = &args[3];
        anyhow::ensure!(private_path != public_path, "private and public key paths must differ");
        let mut private_hex = Zeroizing::new(hex::encode(keypair.private_key_bytes()));
        private_hex.push('\\n');
        let public_hex = format!("{}\n", hex::encode(keypair.public_key()));
        write_noise_key_file(private_path, private_hex.as_bytes(), true)?;
        if let Err(error) = write_noise_key_file(public_path, public_hex.as_bytes(), false) {
            let _ = fs::remove_file(private_path);
            return Err(error);
        }
        println!("noise_server_public_key_hex={}", hex::encode(keypair.public_key()));
        return Ok(());
    }

    let credential_path = env::var("GHULAKH_CREDENTIAL_HASHES")
        .context("set GHULAKH_CREDENTIAL_HASHES to a file of SHA-256 credential digests")?;
    let credential_hashes = Arc::new(load_credential_hashes(&credential_path)?);

    let sessions: SessionMap = Arc::new(RwLock::new(HashMap::new()));
    let tun_enabled = env::var("GHULAKH_TUN_ENABLED")
        .unwrap_or_else(|_| "false".to_string())
        .eq_ignore_ascii_case("true");
    let forwarding_enabled = tun_enabled
        && env::var("GHULAKH_FORWARDING_ENABLED")
            .unwrap_or_else(|_| "false".to_string())
            .eq_ignore_ascii_case("true");

    let mut turn_gateway_setup = if let Ok(gateway_bind) = env::var("GHULAKH_TURN_GATEWAY_BIND") {
        anyhow::ensure!(
            tun_enabled && forwarding_enabled,
            "TURN gateway requires GHULAKH_TUN_ENABLED=true and GHULAKH_FORWARDING_ENABLED=true"
        );
        let bind: SocketAddr = gateway_bind.parse().context("invalid GHULAKH_TURN_GATEWAY_BIND")?;
        let private_path = env::var("GHULAKH_NOISE_PRIVATE_KEY")
            .context("set GHULAKH_NOISE_PRIVATE_KEY to a hex-encoded private key file")?;
        let public_path = env::var("GHULAKH_NOISE_PUBLIC_KEY")
            .context("set GHULAKH_NOISE_PUBLIC_KEY to a hex-encoded public key file")?;
        let public_key = hex::decode(fs::read_to_string(&public_path)?.trim())
            .context("decode persistent Noise public key")?;
        let keypair = Arc::new(
            ghulakh_protocol::session_handshake::NoiseServerKeyPair::from_bytes(
                read_noise_private_key(&private_path)?,
                public_key,
            ).context("validate persistent Noise server keypair")?
        );
        let hashes = Arc::clone(&credential_hashes);
        let verifier: Arc<turn_handshake_service::CredentialVerifier> = Arc::new(move |candidate| {
            std::str::from_utf8(candidate)
                .ok()
                .is_some_and(|credential| credential_matches(credential, &hashes))
        });
        let service = turn_handshake_service::TurnHandshakeService::new(keypair, verifier)
            .context("initialize server TURN handshake service")?;
        let (gateway, receiver) = turn_gateway::TurnGateway::bind(bind).await
            .context("bind server TURN gateway")?;
        gateway.install_handshake_service(service).await?;
        let gateway_task = Arc::clone(&gateway);
        let turn_gateway_task = tokio::spawn(async move { gateway_task.run().await });
        eprintln!("TURN gateway listening on {}", gateway.local_addr()?);
        Some((gateway, Some(receiver), turn_gateway_task))
    } else {
        None
    };

    anyhow::ensure!(
        turn_gateway_setup.is_some(),
        "TURN gateway is required; no alternative transport is enabled"
    );

    if turn_gateway_setup.is_some() {
        let ip_forward = fs::read_to_string("/proc/sys/net/ipv4/ip_forward")
            .context("read Linux IPv4 forwarding state")?;
        anyhow::ensure!(
            ip_forward.trim() == "1",
            "Linux IPv4 forwarding is disabled; set net.ipv4.ip_forward=1"
        );
        let ipv6_forward = fs::read_to_string("/proc/sys/net/ipv6/conf/all/forwarding")
            .context("read Linux IPv6 forwarding state")?;
        anyhow::ensure!(
            ipv6_forward.trim() == "1",
            "Linux IPv6 forwarding is disabled; set net.ipv6.conf.all.forwarding=1"
        );
    }

    let mut turn_ingress_task = None;
    let (tun_sender, tun_writer_task, tun_reader_task) = if tun_enabled {
        let name = env::var("GHULAKH_TUN_NAME").unwrap_or_else(|_| "ghulakh0".to_string());
        let turn_gateway = turn_gateway_setup.as_ref().map(|(gateway, _, _)| Arc::clone(gateway));
        let (sender, writer_task, reader_task) =
            start_tun(&name, Arc::clone(&sessions), turn_gateway)?;
        if let Some((_, ingress, _)) = turn_gateway_setup.as_mut() {
            let mut ingress = ingress.take().expect("TURN ingress receiver is available during startup");
            let tun_ingress_sender = sender.clone();
            turn_ingress_task = Some(tokio::spawn(async move {
                while let Some(packet) = ingress.recv().await {
                    tun_ingress_sender
                        .send(packet.packet)
                        .await
                        .context("forward TURN ingress packet to TUN")?;
                }
                anyhow::bail!("TURN ingress channel closed unexpectedly");
            }));
        }
        eprintln!(
            "Dual-stack TUN interface {} is active at {}/16 and {}/64 with MTU {}",
            name, TUN_SERVER_IPV4, TUN_SERVER_IPV6, TUN_MTU
        );
        (sender, writer_task, reader_task)
    } else {
        bail!("TUN is required when the TURN gateway is enabled");
    };

    let (_, _, turn_gateway_task) = turn_gateway_setup
        .expect("TURN gateway is required by the startup guard");
    let turn_ingress_task = turn_ingress_task
        .expect("TURN ingress task is required when the gateway is enabled");
    tokio::select! {
        result = turn_gateway_task => {
            result
                .context("TURN gateway task panicked")?
                .context("TURN gateway task failed")?;
        }
        result = turn_ingress_task => {
            result
                .context("TURN ingress task panicked")?
                .context("TURN ingress task failed")?;
        }
        result = tun_writer_task => {
            result
                .context("TUN writer task panicked")?
                .context("TUN writer task failed")?;
        }
        result = tun_reader_task => {
            result
                .context("TUN reader task panicked")?
                .context("TUN reader task failed")?;
        }
    }
    drop(tun_sender);
    Ok(())
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
        assert!(!destination_allowed(Ipv4Addr::new(192, 0, 2, 1)));
        assert!(!destination_allowed(Ipv4Addr::new(198, 18, 0, 1)));
        assert!(!destination_allowed(Ipv4Addr::new(198, 51, 100, 1)));
        assert!(!destination_allowed(Ipv4Addr::new(203, 0, 113, 1)));
        assert!(!destination_allowed(Ipv4Addr::new(100, 64, 0, 1)));
        assert!(destination_allowed(Ipv4Addr::new(1, 1, 1, 1)));
    }

    #[test]
    fn malformed_datagram_is_rejected() {
        assert_eq!(
            inspect_datagram(b"not-a-packet", true, Some(Ipv4Addr::new(10, 77, 0, 2))),
            DatagramDisposition::Invalid
        );
    }

    #[cfg(unix)]
    #[test]
    fn noise_private_key_loader_accepts_owner_only_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("noise-private.key");
        std::fs::write(&path, "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(
            read_noise_private_key(path.to_str().unwrap()).unwrap().as_slice(),
            &[
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
            ]
        );
    }

    #[test]
    fn noise_private_key_loader_rejects_malformed_hex() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("noise-private.key");
        std::fs::write(&path, "not-a-private-key").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        assert!(read_noise_private_key(path.to_str().unwrap()).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn noise_private_key_loader_rejects_group_or_other_access() {
        use std::os::unix::fs::PermissionsExt;
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("noise-private.key");
        std::fs::write(&path, "00112233").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
        let error = read_noise_private_key(path.to_str().unwrap()).unwrap_err();
        assert!(error.to_string().contains("owner-readable and inaccessible to group/others"));
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
        use quinn::Endpoint;

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
                            false,
                        )
                        .await;
                    }
                });
            }
        });

        let client = Arc::new(QuicClient::connect(ClientOptions {
            server_addr,
            server_name: "localhost".into(),
            root_certificate_der: certificate.cert.der().to_vec(),
            credential,
            udp_socket: None,
        })
        .await
        .unwrap());

        assert_eq!(client.session_id().len(), 32);
        assert_eq!(client.client_ipv4(), "10.77.0.2");
        assert!(!client.tunnel_enabled());
        assert!(!client.forwarding_enabled());
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

        // A blocked native receive must be released by close so Android's
        // VPN worker can terminate without waiting for another packet.
        let receiver = Arc::clone(&client);
        let receive_task = tokio::spawn(async move { receiver.receive_packet().await });
        tokio::time::sleep(Duration::from_millis(50)).await;
        client.close();
        let receive_result = tokio::time::timeout(Duration::from_secs(2), receive_task)
            .await
            .expect("closing the client did not unblock a pending receive")
            .expect("receive task panicked");
        assert!(receive_result.is_err(), "closed connection returned a packet");

        endpoint.close(0u32.into(), b"test complete");
        server_task.abort();
    }
}
