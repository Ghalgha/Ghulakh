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
    env, fs, fs::File, io::BufReader, net::SocketAddr, sync::Arc, time::Duration,
};
use subtle::ConstantTimeEq;
use tokio::{io::AsyncWriteExt, sync::Semaphore};

const ALPN: &[u8] = b"ghulakh/1";
const DATAGRAM_RECEIVE_BUDGET: usize = MAX_DATAGRAM_SIZE * 32;

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

async fn handle_connection(
    connection: quinn::Connection,
    credential_hashes: Arc<Vec<[u8; 32]>>,
) -> Result<()> {
    let session_id = new_session_id();
    let mut authenticated = false;
    let mut valid_datagrams = 0u64;
    let mut rejected_datagrams = 0u64;

    loop {
        tokio::select! {
            incoming = connection.accept_bi() => {
                let (mut send, mut recv) = match incoming {
                    Ok(streams) => streams,
                    Err(_) => break,
                };

                let bytes = match tokio::time::timeout(
                    Duration::from_secs(15),
                    recv.read_to_end(MAX_CONTROL_BODY),
                ).await {
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

                let envelope: ControlEnvelope =
                    serde_json::from_slice(&bytes).context("decode control envelope")?;
                validate_envelope(envelope.version, bytes.len(), request_id(&envelope.message))
                    .context("validate control envelope")?;
                validate_message(&envelope.message).context("validate control message")?;

                let response = match envelope.message {
                    ControlMessage::ClientHello {
                        credential,
                        request_id,
                    } if !authenticated => {
                        if !credential_matches(&credential, credential_hashes.as_slice()) {
                            connection.close(0u32.into(), b"authentication failed");
                            bail!("client authentication failed");
                        }
                        authenticated = true;
                        ControlMessage::ServerHello {
                            session_id: session_id.clone(),
                            request_id,
                        }
                    }
                    ControlMessage::Ping { request_id } if authenticated => {
                        ControlMessage::Pong { request_id }
                    }
                    ControlMessage::Close { .. } if authenticated => {
                        connection.close(0u32.into(), b"client requested close");
                        break;
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
            }
            datagram = connection.read_datagram() => {
                let bytes = match datagram {
                    Ok(bytes) => bytes,
                    Err(_) => break,
                };

                if !authenticated {
                    rejected_datagrams = rejected_datagrams.saturating_add(1);
                    continue;
                }

                match DataDatagram::decode(bytes.as_ref()) {
                    Ok(packet) => {
                        // The validated packet boundary is ready for the future TUN adapter.
                        // Until a server TUN is configured, packets are deliberately not routed.
                        valid_datagrams = valid_datagrams.saturating_add(1);
                        let _packet_len = packet.packet.len();
                    }
                    Err(_) => {
                        rejected_datagrams = rejected_datagrams.saturating_add(1);
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
    let connection_limit = Arc::new(Semaphore::new(1024));
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
                    if let Err(error) = handle_connection(connection, hashes).await {
                        eprintln!("connection closed: {error:#}");
                    }
                }
                Err(error) => eprintln!("QUIC handshake failed: {error}"),
            }
        });
    }

    bail!("QUIC endpoint stopped accepting connections")
}
