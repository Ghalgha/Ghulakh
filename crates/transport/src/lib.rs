//! Reusable QUIC client transport for native and Android integration.

use anyhow::{bail, Context, Result};
use bytes::Bytes;
use ghulakh_protocol::{
    validate_envelope, validate_message, ControlEnvelope, ControlMessage, DataDatagram,
    MAX_CONTROL_BODY, MAX_DATAGRAM_SIZE, PROTOCOL_VERSION,
};
use quinn::{crypto::rustls::QuicClientConfig, Connection, Endpoint};
use rand::{rngs::OsRng, RngCore};
use rustls::{pki_types::CertificateDer, RootCertStore};
use std::{net::SocketAddr, sync::Arc, time::Duration};

const ALPN: &[u8] = b"ghulakh/1";
const DATAGRAM_BUFFER: usize = MAX_DATAGRAM_SIZE * 32;

/// Connection parameters. The root certificate is DER encoded and is used as
/// the sole trust anchor for this connection.
pub struct ClientOptions {
    pub server_addr: SocketAddr,
    pub server_name: String,
    pub root_certificate_der: Vec<u8>,
    pub credential: String,
}

/// An authenticated QUIC session with a bounded IP datagram interface.
pub struct QuicClient {
    _endpoint: Endpoint,
    connection: Connection,
    session_id: String,
}

impl QuicClient {
    pub async fn connect(options: ClientOptions) -> Result<Self> {
        anyhow::ensure!(!options.server_name.trim().is_empty(), "server name is empty");
        anyhow::ensure!(
            !options.root_certificate_der.is_empty(),
            "trusted root certificate is empty"
        );
        anyhow::ensure!(
            !options.credential.is_empty()
                && options.credential.len() <= ghulakh_protocol::MAX_CREDENTIAL_LEN,
            "credential length is invalid"
        );

        let mut roots = RootCertStore::empty();
        roots
            .add(CertificateDer::from(options.root_certificate_der))
            .context("add trusted server certificate")?;

        let mut tls = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        tls.alpn_protocols = vec![ALPN.to_vec()];

        let crypto = QuicClientConfig::try_from(tls).context("configure QUIC client TLS")?;
        let mut client_config = quinn::ClientConfig::new(Arc::new(crypto));
        let mut transport = quinn::TransportConfig::default();
        transport.datagram_receive_buffer_size(Some(DATAGRAM_BUFFER));
        transport.datagram_send_buffer_size(DATAGRAM_BUFFER);
        client_config.transport_config(Arc::new(transport));

        let endpoint = Endpoint::client("0.0.0.0:0".parse()?)
            .context("bind QUIC client endpoint")?;
        let connection = tokio::time::timeout(
            Duration::from_secs(15),
            endpoint
                .connect_with(client_config, options.server_addr, &options.server_name)
                .context("start QUIC connection")?,
        )
        .await
        .context("QUIC connection timed out")?
        .context("establish QUIC connection")?;

        let request_id = new_request_id();
        let response = exchange_control(
            &connection,
            ControlMessage::ClientHello {
                credential: options.credential,
                request_id: request_id.clone(),
            },
        )
        .await?;

        let session_id = match response {
            ControlMessage::ServerHello {
                session_id,
                request_id: response_id,
            } if response_id == request_id => session_id,
            _ => {
                connection.close(0u32.into(), b"invalid server authentication response");
                bail!("server returned an unexpected authentication response");
            }
        };

        Ok(Self {
            _endpoint: endpoint,
            connection,
            session_id,
        })
    }

    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    pub fn max_datagram_size(&self) -> Option<usize> {
        self.connection.max_datagram_size()
    }

    /// Send one complete IPv4 or IPv6 packet. QUIC DATAGRAM is unreliable and
    /// unordered; callers must not assume delivery.
    pub async fn send_packet(&self, packet: &DataDatagram) -> Result<()> {
        let encoded = packet.encode().context("encode IP datagram")?;
        let maximum = self
            .connection
            .max_datagram_size()
            .context("peer or local endpoint does not support QUIC DATAGRAM")?;
        anyhow::ensure!(
            encoded.len() <= maximum,
            "encoded datagram exceeds negotiated QUIC limit"
        );
        self.connection
            .send_datagram_wait(Bytes::from(encoded))
            .await
            .context("send QUIC datagram")?;
        Ok(())
    }

    /// Receive and validate one complete IP packet.
    pub async fn receive_packet(&self) -> Result<DataDatagram> {
        let bytes = self
            .connection
            .read_datagram()
            .await
            .context("receive QUIC datagram")?;
        DataDatagram::decode(bytes.as_ref()).context("decode received IP datagram")
    }

    pub async fn ping(&self) -> Result<()> {
        let request_id = new_request_id();
        match exchange_control(
            &self.connection,
            ControlMessage::Ping {
                request_id: request_id.clone(),
            },
        )
        .await?
        {
            ControlMessage::Pong {
                request_id: response_id,
            } if response_id == request_id => Ok(()),
            _ => bail!("server returned an unexpected ping response"),
        }
    }

    pub fn close(self) {
        self.connection.close(0u32.into(), b"client closed session");
        self._endpoint.close(0u32.into(), b"client closed endpoint");
    }
}

async fn exchange_control(connection: &Connection, message: ControlMessage) -> Result<ControlMessage> {
    let expected_request_id = request_id(&message).to_owned();
    let encoded = serde_json::to_vec(&ControlEnvelope {
        version: PROTOCOL_VERSION,
        message,
    })?;
    anyhow::ensure!(encoded.len() <= MAX_CONTROL_BODY, "control request is too large");

    let (mut send, mut recv) = connection
        .open_bi()
        .await
        .context("open QUIC control stream")?;
    tokio::io::AsyncWriteExt::write_all(&mut send, &encoded)
        .await
        .context("write QUIC control request")?;
    send.finish().context("finish QUIC control request")?;

    let response_bytes = tokio::time::timeout(
        Duration::from_secs(15),
        recv.read_to_end(MAX_CONTROL_BODY),
    )
    .await
    .context("control response timed out")?
    .context("read QUIC control response")?;
    let response: ControlEnvelope =
        serde_json::from_slice(&response_bytes).context("decode QUIC control response")?;
    validate_envelope(
        response.version,
        response_bytes.len(),
        request_id(&response.message),
    )
    .context("validate QUIC control response")?;
    validate_message(&response.message).context("validate QUIC control response message")?;
    anyhow::ensure!(
        request_id(&response.message) == expected_request_id,
        "control response request ID mismatch"
    );
    Ok(response.message)
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

fn new_request_id() -> String {
    let mut bytes = [0u8; 16];
    OsRng.fill_bytes(&mut bytes);
    hex_encode(&bytes)
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}
