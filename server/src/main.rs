use anyhow::{bail, Context, Result};
use ghulakh_protocol::{validate_envelope, ControlEnvelope, ControlMessage, PROTOCOL_VERSION, MAX_CONTROL_BODY};
use quinn::{crypto::rustls::QuicServerConfig, Endpoint};
use rand::{rngs::OsRng, RngCore};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use sha2::{Digest, Sha256};
use std::{
    env,
    fs::File,
    io::BufReader,
    net::SocketAddr,
    sync::Arc,
};
use subtle::ConstantTimeEq;

const ALPN: &[u8] = b"ghulakh/1";

fn load_server_config(cert_path: &str, key_path: &str) -> Result<quinn::ServerConfig> {
    let mut cert_reader = BufReader::new(File::open(cert_path)
        .with_context(|| format!("open certificate file: {cert_path}"))?);
    let cert_chain: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_reader)
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("parse certificate chain")?;
    anyhow::ensure!(!cert_chain.is_empty(), "certificate chain is empty");

    let mut key_reader = BufReader::new(File::open(key_path)
        .with_context(|| format!("open private key file: {key_path}"))?);
    let key = rustls_pemfile::private_key(&mut key_reader)
        .context("parse private key")?
        .context("private key file contains no supported key")?;

    let mut tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, key)
        .context("configure TLS certificate")?;
    tls.alpn_protocols = vec![ALPN.to_vec()];

    let crypto = QuicServerConfig::try_from(tls)
        .context("configure QUIC TLS crypto")?;
    Ok(quinn::ServerConfig::with_crypto(Arc::new(crypto)))
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

    loop {
        let (mut send, mut recv) = match connection.accept_bi().await {
            Ok(streams) => streams,
            Err(_) => break,
        };

        let bytes = match recv.read_to_end(MAX_CONTROL_BODY).await {
            Ok(bytes) => bytes,
            Err(_) => {
                let _ = connection.close(0u32.into(), b"invalid control stream");
                bail!("control stream read failed");
            }
        };

        if bytes.len() > MAX_CONTROL_BODY {
            let _ = connection.close(0u32.into(), b"control message too large");
            bail!("control message exceeds limit");
        }

        let envelope: ControlEnvelope = serde_json::from_slice(&bytes)
            .context("decode control envelope")?;
        validate_envelope(envelope.version, bytes.len(), request_id(&envelope.message))
            .context("validate control envelope")?;

        let response = match envelope.message {
            ControlMessage::ClientHello { credential, request_id } => {
                if !credential_matches(&credential, credential_hashes.as_slice()) {
                    let _ = connection.close(0u32.into(), b"authentication failed");
                    bail!("client authentication failed");
                }
                authenticated = true;
                ControlMessage::ServerHello { session_id: session_id.clone(), request_id }
            }
            ControlMessage::Ping { request_id } if authenticated => {
                ControlMessage::Pong { request_id }
            }
            ControlMessage::Close { .. } if authenticated => {
                let _ = connection.close(0u32.into(), b"client requested close");
                break;
            }
            _ => {
                let _ = connection.close(0u32.into(), b"unexpected control message");
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
        send.write_all(&encoded).await.context("write control response")?;
        send.finish().context("finish control response stream")?;
    }

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let token = env::var("GHULAKH_BOOTSTRAP_TOKEN")
        .context("set GHULAKH_BOOTSTRAP_TOKEN to a unique high-entropy credential")?;
    anyhow::ensure!(token.len() >= 32, "credential must contain at least 32 characters");

    let cert_path = env::var("GHULAKH_TLS_CERT")
        .context("set GHULAKH_TLS_CERT to a PEM certificate chain")?;
    let key_path = env::var("GHULAKH_TLS_KEY")
        .context("set GHULAKH_TLS_KEY to a PEM private key")?;
    let bind: SocketAddr = env::var("GHULAKH_QUIC_BIND")
        .unwrap_or_else(|_| "0.0.0.0:4433".to_string())
        .parse()
        .context("invalid GHULAKH_QUIC_BIND address")?;

    let digest: [u8; 32] = Sha256::digest(token.as_bytes()).into();
    let credential_hashes = Arc::new(vec![digest]);
    let server_config = load_server_config(&cert_path, &key_path)?;
    let endpoint = Endpoint::server(server_config, bind)?;

    eprintln!("ГӀулакх QUIC control endpoint listening on {}", endpoint.local_addr()?);
    while let Some(connecting) = endpoint.accept().await {
        let hashes = Arc::clone(&credential_hashes);
        tokio::spawn(async move {
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
