use anyhow::{bail, Context, Result};
use ghulakh_protocol::{
    validate_envelope, validate_message, ControlEnvelope, ControlMessage, DataDatagram,
    MAX_CONTROL_BODY, MAX_DATAGRAM_SIZE, PROTOCOL_VERSION,
};
use quinn::{crypto::rustls::QuicServerConfig, Endpoint};
use rand::{rngs::OsRng, RngCore};
use rustls::pki_types::CertificateDer;
use sha2::{Digest, Sha256};
use std::{
    env, fs, fs::File, io::BufReader, net::SocketAddr,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};
use subtle::ConstantTimeEq;
use tokio::io::AsyncWriteExt;

const ALPN: &[u8] = b"ghulakh/1";
const DATAGRAM_RECEIVE_BUDGET: usize = MAX_DATAGRAM_SIZE * 32;

#[derive(Default)]
struct DatagramMetrics {
    accepted: std::sync::atomic::AtomicU64,
    rejected: std::sync::atomic::AtomicU64,
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
    connection: quinn::Connection,
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    credential_hashes: Arc<Vec<[u8; 32]>>,
    session_id: Arc<String>,
    authenticated: Arc<AtomicBool>,
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
            ControlMessage::ServerHello {
                session_id: session_id.as_ref().clone(),
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
    Accepted(usize),
}

fn inspect_datagram(bytes: &[u8], authenticated: bool) -> DatagramDisposition {
    if !authenticated {
        return DatagramDisposition::Unauthenticated;
    }
    match DataDatagram::decode(bytes) {
        Ok(packet) => DatagramDisposition::Accepted(packet.packet.len()),
        Err(_) => DatagramDisposition::Invalid,
    }
}

async fn handle_connection(
    connection: quinn::Connection,
    credential_hashes: Arc<Vec<[u8; 32]>>,
    metrics: Arc<DatagramMetrics>,
) -> Result<()> {
    let session_id = Arc::new(new_session_id());
    let authenticated = Arc::new(AtomicBool::new(false));
    let mut valid_datagrams = 0u64;
    let mut rejected_datagrams = 0u64;

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
                tokio::spawn(async move {
                    if let Err(error) = handle_control_stream(
                        connection.clone(),
                        send,
                        recv,
                        hashes,
                        session,
                        auth,
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

                match inspect_datagram(bytes.as_ref(), authenticated.load(Ordering::Acquire)) {
                    DatagramDisposition::Accepted(_packet_len) => {
                        // The validated packet boundary is ready for the future TUN adapter.
                        // Until a server TUN is configured, packets are deliberately not routed.
                        valid_datagrams = valid_datagrams.saturating_add(1);
                        metrics.accepted.fetch_add(1, Ordering::Relaxed);
                    }
                    DatagramDisposition::Unauthenticated | DatagramDisposition::Invalid => {
                        rejected_datagrams = rejected_datagrams.saturating_add(1);
                        metrics.rejected.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        }
    }

    if valid_datagrams > 0 || rejected_datagrams > 0 {
        eprintln!(
            "connection datagrams: accepted={}, rejected={}, forwarding=disabled",
            valid_datagrams, rejected_datagrams
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
        tokio::spawn(async move {
            let _permit = permit;
            match connecting.await {
                Ok(connection) => {
                    let metrics = Arc::new(DatagramMetrics::default());
                    if let Err(error) = handle_connection(connection, hashes, metrics).await {
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

    fn valid_ipv4_datagram() -> Vec<u8> {
        let mut packet = vec![0u8; 20];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&20u16.to_be_bytes());
        DataDatagram {
            kind: IpPacketKind::Ipv4,
            packet,
        }
        .encode()
        .unwrap()
    }

    #[test]
    fn datagrams_are_rejected_before_authentication() {
        assert_eq!(
            inspect_datagram(&valid_ipv4_datagram(), false),
            DatagramDisposition::Unauthenticated
        );
    }

    #[test]
    fn authenticated_valid_datagram_is_accepted_for_tun_adapter() {
        assert_eq!(
            inspect_datagram(&valid_ipv4_datagram(), true),
            DatagramDisposition::Accepted(20)
        );
    }

    #[test]
    fn malformed_datagram_is_rejected() {
        assert_eq!(
            inspect_datagram(b"not-a-packet", true),
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
        use ghulakh_protocol::{DataDatagram, IpPacketKind};
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

        let server_task = tokio::spawn(async move {
            while let Some(connecting) = server_endpoint.accept().await {
                let hashes = Arc::clone(&hashes);
                let metrics = Arc::clone(&server_metrics);
                tokio::spawn(async move {
                    if let Ok(connection) = connecting.await {
                        let _ = handle_connection(connection, hashes, metrics).await;
                    }
                });
            }
        });

        let client = QuicClient::connect(ClientOptions {
            server_addr,
            server_name: "localhost".into(),
            root_certificate_der: certificate.cert.der().to_vec(),
            credential,
        })
        .await
        .unwrap();

        assert_eq!(client.session_id().len(), 32);
        client.ping().await.unwrap();

        let mut ipv4 = vec![0u8; 20];
        ipv4[0] = 0x45;
        ipv4[2..4].copy_from_slice(&20u16.to_be_bytes());
        client
            .send_packet(&DataDatagram {
                kind: IpPacketKind::Ipv4,
                packet: ipv4,
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
