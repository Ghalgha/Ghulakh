//! Authenticated session-key establishment for the TURN tunnel.
//!
//! Noise XX authenticates the server by a pinned static public key and
//! authenticates the client through a credential carried inside the encrypted
//! third handshake message. Directional frame keys are derived from the final
//! Noise handshake hash with HKDF-SHA256.

use hkdf::Hkdf;
use sha2::Sha256;
use snow::{params::NoiseParams, Builder, HandshakeState, TransportState};
use std::net::{Ipv4Addr, Ipv6Addr};
use zeroize::{Zeroize, Zeroizing};

use crate::{
    secure_frame::{FrameDirection, FrameOpener, FrameSealer},
    turn_path_context::{TurnClientAuthPayload, TurnPathContext},
};

const NOISE_PATTERN: &str = "Noise_XX_25519_ChaChaPoly_BLAKE2s";
const PROTOCOL_PROLOGUE: &[u8] = b"Ghulakh TURN tunnel session v1";
const HKDF_SALT: &[u8] = b"Ghulakh session key schedule v1";
const HKDF_INFO: &[u8] = b"ghulakh/turn/session-frames/v1";
const AUTH_ACCEPTED: &[u8] = b"GHLK-AUTH-ACCEPTED-v1";
const MAX_HANDSHAKE_MESSAGE: usize = 1024;
const MAX_CREDENTIAL_SIZE: usize = crate::MAX_CREDENTIAL_LEN;

/// Tunnel parameters authenticated inside the encrypted Noise server ack.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TurnSessionConfig {
    pub virtual_ipv4: Ipv4Addr,
    pub virtual_ipv6: Ipv6Addr,
    pub mtu: u16,
}

impl TurnSessionConfig {
    pub const ENCODED_LEN: usize = 22;

    pub fn encode(self) -> Result<[u8; Self::ENCODED_LEN], SessionHandshakeError> {
        if self.virtual_ipv4.is_unspecified()
            || self.virtual_ipv4.is_multicast()
            || self.virtual_ipv6.is_unspecified()
            || self.virtual_ipv6.is_multicast()
            || self.mtu < 576
            || self.mtu > 1500
        {
            return Err(SessionHandshakeError::InvalidSessionConfig);
        }
        let mut encoded = [0u8; Self::ENCODED_LEN];
        encoded[..4].copy_from_slice(&self.virtual_ipv4.octets());
        encoded[4..20].copy_from_slice(&self.virtual_ipv6.octets());
        encoded[20..].copy_from_slice(&self.mtu.to_be_bytes());
        Ok(encoded)
    }

    pub fn decode(encoded: &[u8]) -> Result<Self, SessionHandshakeError> {
        if encoded.len() != Self::ENCODED_LEN {
            return Err(SessionHandshakeError::InvalidSessionConfig);
        }
        let config = Self {
            virtual_ipv4: Ipv4Addr::new(encoded[0], encoded[1], encoded[2], encoded[3]),
            virtual_ipv6: Ipv6Addr::from(
                <[u8; 16]>::try_from(&encoded[4..20])
                    .map_err(|_| SessionHandshakeError::InvalidSessionConfig)?,
            ),
            mtu: u16::from_be_bytes([encoded[20], encoded[21]]),
        };
        config.encode()?;
        Ok(config)
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SessionHandshakeError {
    #[error("Noise handshake failed: {0}")]
    Noise(String),
    #[error("server static key does not match the pinned key")]
    ServerIdentityMismatch,
    #[error("client credential was rejected")]
    CredentialRejected,
    #[error("client credential length is invalid")]
    InvalidCredential,
    #[error("handshake message exceeds the configured limit")]
    MessageTooLarge,
    #[error("Noise handshake is in an invalid state")]
    InvalidState,
    #[error("session key derivation failed")]
    KeyDerivation,
    #[error("server authentication acknowledgement is invalid")]
    InvalidAcknowledgement,
    #[error("server session configuration is invalid")]
    InvalidSessionConfig,
}

fn noise_params() -> Result<NoiseParams, SessionHandshakeError> {
    NOISE_PATTERN
        .parse()
        .map_err(|error: snow::Error| SessionHandshakeError::Noise(error.to_string()))
}

fn noise_error(error: snow::Error) -> SessionHandshakeError {
    SessionHandshakeError::Noise(error.to_string())
}

/// Persistent server static key pair. Persist both values in protected server
/// configuration; publish only `public_key()` to clients for pinning.
pub struct NoiseServerKeyPair {
    private_key: Zeroizing<Vec<u8>>,
    public_key: Vec<u8>,
}

impl NoiseServerKeyPair {
    pub fn generate() -> Result<Self, SessionHandshakeError> {
        let builder = Builder::new(noise_params()?);
        let keypair = builder.generate_keypair().map_err(noise_error)?;
        Ok(Self {
            private_key: Zeroizing::new(keypair.private),
            public_key: keypair.public,
        })
    }

    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    /// Export only for writing to a protected server key store.
    pub fn private_key_bytes(&self) -> &[u8] {
        &self.private_key
    }

    /// Load a persisted key pair and verify that its public/private halves match.
    pub fn from_bytes(
        private_key: Zeroizing<Vec<u8>>,
        public_key: Vec<u8>,
    ) -> Result<Self, SessionHandshakeError> {
        if private_key.len() != 32 || public_key.len() != 32 {
            return Err(SessionHandshakeError::ServerIdentityMismatch);
        }
        let keypair = Self {
            private_key,
            public_key,
        };
        let (client, first) = NoiseClientHandshake::new(keypair.public_key(), b"key-pair-check")?;
        let mut server = NoiseServerHandshake::new(&keypair)?;
        let second = server.receive_client_hello(&first)?;
        client.receive_server_hello(&second)?;
        Ok(keypair)
    }
}

/// Client-side Noise XX state. The credential is only sent in the encrypted
/// third handshake message after the pinned server static key is verified.
pub struct NoiseClientHandshake {
    state: Option<HandshakeState>,
    pinned_server_key: Vec<u8>,
    credential: Zeroizing<Vec<u8>>,
}

pub struct NoiseClientFinish {
    /// Third Noise handshake message. Send this to the server unchanged.
    pub message: Vec<u8>,
    pending: NoiseClientPendingAuth,
}

impl NoiseClientFinish {
    pub fn accept_server_ack(
        self,
        acknowledgement: &[u8],
    ) -> Result<SessionFrameKeys, SessionHandshakeError> {
        let (keys, payload) = self
            .pending
            .accept_server_ack_with_payload(acknowledgement)?;
        if !payload.is_empty() {
            return Err(SessionHandshakeError::InvalidAcknowledgement);
        }
        Ok(keys)
    }

    pub fn accept_server_ack_with_payload(
        self,
        acknowledgement: &[u8],
    ) -> Result<(SessionFrameKeys, Vec<u8>), SessionHandshakeError> {
        self.pending.accept_server_ack_with_payload(acknowledgement)
    }
}

pub struct NoiseClientPendingAuth {
    transport: TransportState,
    keys: SessionFrameKeys,
}

impl NoiseClientPendingAuth {
    /// Verify the encrypted server acknowledgement before enabling the tunnel.
    pub fn accept_server_ack(
        self,
        acknowledgement: &[u8],
    ) -> Result<SessionFrameKeys, SessionHandshakeError> {
        let (keys, payload) = self.accept_server_ack_with_payload(acknowledgement)?;
        if !payload.is_empty() {
            return Err(SessionHandshakeError::InvalidAcknowledgement);
        }
        Ok(keys)
    }

    pub fn accept_server_ack_with_payload(
        mut self,
        acknowledgement: &[u8],
    ) -> Result<(SessionFrameKeys, Vec<u8>), SessionHandshakeError> {
        if acknowledgement.len() > MAX_HANDSHAKE_MESSAGE {
            return Err(SessionHandshakeError::MessageTooLarge);
        }
        let mut plaintext = [0u8; MAX_HANDSHAKE_MESSAGE];
        let length = self
            .transport
            .read_message(acknowledgement, &mut plaintext)
            .map_err(noise_error)?;
        if length < AUTH_ACCEPTED.len() || &plaintext[..AUTH_ACCEPTED.len()] != AUTH_ACCEPTED {
            return Err(SessionHandshakeError::InvalidAcknowledgement);
        }
        Ok((self.keys, plaintext[AUTH_ACCEPTED.len()..length].to_vec()))
    }
}

impl NoiseClientHandshake {
    pub fn new(
        pinned_server_key: &[u8],
        credential: &[u8],
    ) -> Result<(Self, Vec<u8>), SessionHandshakeError> {
        if credential.is_empty() || credential.len() > MAX_CREDENTIAL_SIZE {
            return Err(SessionHandshakeError::InvalidCredential);
        }
        Self::new_with_encoded_credential(pinned_server_key, Zeroizing::new(credential.to_vec()))
    }

    pub fn new_with_path_context(
        pinned_server_key: &[u8],
        credential: &[u8],
        context: TurnPathContext,
    ) -> Result<(Self, Vec<u8>), SessionHandshakeError> {
        let payload = TurnClientAuthPayload::new(context, credential)
            .map_err(|_| SessionHandshakeError::InvalidCredential)?
            .encode()
            .map_err(|_| SessionHandshakeError::InvalidCredential)?;
        Self::new_with_encoded_credential(pinned_server_key, payload)
    }

    fn new_with_encoded_credential(
        pinned_server_key: &[u8],
        credential: Zeroizing<Vec<u8>>,
    ) -> Result<(Self, Vec<u8>), SessionHandshakeError> {
        if pinned_server_key.len() != 32 {
            return Err(SessionHandshakeError::ServerIdentityMismatch);
        }
        if credential.is_empty() || credential.len() > MAX_HANDSHAKE_MESSAGE - 64 {
            return Err(SessionHandshakeError::InvalidCredential);
        }

        let params = noise_params()?;
        let key_builder = Builder::new(noise_params()?);
        let client_static = key_builder.generate_keypair().map_err(noise_error)?;
        let client_private = Zeroizing::new(client_static.private);
        let mut state = Builder::new(params)
            .local_private_key(&client_private)
            .map_err(noise_error)?
            .prologue(PROTOCOL_PROLOGUE)
            .map_err(noise_error)?
            .build_initiator()
            .map_err(noise_error)?;

        let mut message = [0u8; MAX_HANDSHAKE_MESSAGE];
        let length = state
            .write_message(&[], &mut message)
            .map_err(noise_error)?;
        Ok((
            Self {
                state: Some(state),
                pinned_server_key: pinned_server_key.to_vec(),
                credential,
            },
            message[..length].to_vec(),
        ))
    }

    pub fn receive_server_hello(
        mut self,
        message: &[u8],
    ) -> Result<NoiseClientFinish, SessionHandshakeError> {
        if message.len() > MAX_HANDSHAKE_MESSAGE {
            return Err(SessionHandshakeError::MessageTooLarge);
        }
        let mut state = self
            .state
            .take()
            .ok_or(SessionHandshakeError::InvalidState)?;
        let mut payload = [0u8; MAX_HANDSHAKE_MESSAGE];
        let length = state
            .read_message(message, &mut payload)
            .map_err(noise_error)?;
        if length != 0 {
            return Err(SessionHandshakeError::InvalidState);
        }
        if state.get_remote_static() != Some(self.pinned_server_key.as_slice()) {
            return Err(SessionHandshakeError::ServerIdentityMismatch);
        }

        let mut third_message = [0u8; MAX_HANDSHAKE_MESSAGE];
        let length = state
            .write_message(&self.credential, &mut third_message)
            .map_err(noise_error)?;
        let keys = SessionFrameKeys::derive(state.get_handshake_hash())?;
        let transport = state.into_transport_mode().map_err(noise_error)?;
        self.credential.zeroize();

        Ok(NoiseClientFinish {
            message: third_message[..length].to_vec(),
            pending: NoiseClientPendingAuth { transport, keys },
        })
    }
}

/// Server-side Noise XX responder. A caller must verify the decrypted credential
/// before it receives an acknowledgement or session frame keys.
pub struct NoiseServerHandshake {
    state: Option<HandshakeState>,
}

impl NoiseServerHandshake {
    pub fn new(keypair: &NoiseServerKeyPair) -> Result<Self, SessionHandshakeError> {
        let state = Builder::new(noise_params()?)
            .local_private_key(&keypair.private_key)
            .map_err(noise_error)?
            .prologue(PROTOCOL_PROLOGUE)
            .map_err(noise_error)?
            .build_responder()
            .map_err(noise_error)?;
        Ok(Self { state: Some(state) })
    }

    pub fn receive_client_hello(
        &mut self,
        message: &[u8],
    ) -> Result<Vec<u8>, SessionHandshakeError> {
        if message.len() > MAX_HANDSHAKE_MESSAGE {
            return Err(SessionHandshakeError::MessageTooLarge);
        }
        let state = self
            .state
            .as_mut()
            .ok_or(SessionHandshakeError::InvalidState)?;
        let mut payload = [0u8; MAX_HANDSHAKE_MESSAGE];
        let length = state
            .read_message(message, &mut payload)
            .map_err(noise_error)?;
        if length != 0 {
            return Err(SessionHandshakeError::InvalidState);
        }
        let mut response = [0u8; MAX_HANDSHAKE_MESSAGE];
        let length = state
            .write_message(&[], &mut response)
            .map_err(noise_error)?;
        Ok(response[..length].to_vec())
    }

    pub fn receive_client_finish(
        self,
        message: &[u8],
        verify_credential: impl FnOnce(&[u8]) -> bool,
    ) -> Result<(Vec<u8>, SessionFrameKeys), SessionHandshakeError> {
        self.receive_client_finish_with_payload(message, verify_credential, &[])
    }

    pub fn receive_client_finish_with_payload(
        self,
        message: &[u8],
        verify_credential: impl FnOnce(&[u8]) -> bool,
        acknowledgement_payload: &[u8],
    ) -> Result<(Vec<u8>, SessionFrameKeys), SessionHandshakeError> {
        let (ack, keys, _) = self.receive_client_finish_with_path_context(
            message,
            verify_credential,
            acknowledgement_payload,
        )?;
        Ok((ack, keys))
    }

    pub fn receive_client_finish_with_path_context(
        self,
        message: &[u8],
        verify_credential: impl FnOnce(&[u8]) -> bool,
        acknowledgement_payload: &[u8],
    ) -> Result<(Vec<u8>, SessionFrameKeys, Option<TurnPathContext>), SessionHandshakeError> {
        self.receive_client_finish_with_path_context_builder(message, verify_credential, |_| {
            Ok(acknowledgement_payload.to_vec())
        })
    }

    pub fn receive_client_finish_with_path_context_builder(
        mut self,
        message: &[u8],
        verify_credential: impl FnOnce(&[u8]) -> bool,
        build_acknowledgement: impl FnOnce(
            Option<TurnPathContext>,
        ) -> Result<Vec<u8>, SessionHandshakeError>,
    ) -> Result<(Vec<u8>, SessionFrameKeys, Option<TurnPathContext>), SessionHandshakeError> {
        if message.len() > MAX_HANDSHAKE_MESSAGE {
            return Err(SessionHandshakeError::MessageTooLarge);
        }
        let mut state = self
            .state
            .take()
            .ok_or(SessionHandshakeError::InvalidState)?;
        let mut plaintext = Zeroizing::new([0u8; MAX_HANDSHAKE_MESSAGE]);
        let length = state
            .read_message(message, plaintext.as_mut())
            .map_err(noise_error)?;
        if length == 0 || length > MAX_HANDSHAKE_MESSAGE {
            return Err(SessionHandshakeError::InvalidCredential);
        }

        let (credential, path_context) = if plaintext[..length].starts_with(b"GHMP") {
            let payload = TurnClientAuthPayload::decode(&plaintext[..length])
                .map_err(|_| SessionHandshakeError::InvalidCredential)?;
            let context = payload.context;
            let credential = Zeroizing::new(payload.credential().to_vec());
            (credential, Some(context))
        } else {
            if length > MAX_CREDENTIAL_SIZE {
                return Err(SessionHandshakeError::InvalidCredential);
            }
            (Zeroizing::new(plaintext[..length].to_vec()), None)
        };
        if !verify_credential(&credential) {
            return Err(SessionHandshakeError::CredentialRejected);
        }

        // Allocate the group address only after the encrypted credential has
        // been verified, but before the authenticated ServerAck is produced.
        let acknowledgement_payload = build_acknowledgement(path_context)?;
        if AUTH_ACCEPTED.len() + acknowledgement_payload.len() > MAX_HANDSHAKE_MESSAGE {
            return Err(SessionHandshakeError::MessageTooLarge);
        }
        let keys = SessionFrameKeys::derive(state.get_handshake_hash())?;
        let mut transport = state.into_transport_mode().map_err(noise_error)?;
        let mut acknowledgement = [0u8; MAX_HANDSHAKE_MESSAGE];
        let mut acknowledgement_plaintext =
            Vec::with_capacity(AUTH_ACCEPTED.len() + acknowledgement_payload.len());
        acknowledgement_plaintext.extend_from_slice(AUTH_ACCEPTED);
        acknowledgement_plaintext.extend_from_slice(&acknowledgement_payload);
        let ack_length = transport
            .write_message(&acknowledgement_plaintext, &mut acknowledgement)
            .map_err(noise_error)?;
        Ok((acknowledgement[..ack_length].to_vec(), keys, path_context))
    }
}

/// Independent directional frame keys derived from the completed Noise session.
pub struct SessionFrameKeys {
    client_to_server_key: Zeroizing<[u8; 32]>,
    client_to_server_prefix: Zeroizing<[u8; 4]>,
    server_to_client_key: Zeroizing<[u8; 32]>,
    server_to_client_prefix: Zeroizing<[u8; 4]>,
    session_id: [u8; 8],
}

impl SessionFrameKeys {
    fn derive(handshake_hash: &[u8]) -> Result<Self, SessionHandshakeError> {
        let hkdf = Hkdf::<Sha256>::new(Some(HKDF_SALT), handshake_hash);
        let mut output = Zeroizing::new([0u8; 80]);
        hkdf.expand(HKDF_INFO, output.as_mut())
            .map_err(|_| SessionHandshakeError::KeyDerivation)?;

        let mut client_to_server_key = [0u8; 32];
        client_to_server_key.copy_from_slice(&output[..32]);
        let mut client_to_server_prefix = [0u8; 4];
        client_to_server_prefix.copy_from_slice(&output[32..36]);
        let mut server_to_client_key = [0u8; 32];
        server_to_client_key.copy_from_slice(&output[36..68]);
        let mut server_to_client_prefix = [0u8; 4];
        server_to_client_prefix.copy_from_slice(&output[68..72]);
        let mut session_id = [0u8; 8];
        session_id.copy_from_slice(&output[72..80]);

        Ok(Self {
            client_to_server_key: Zeroizing::new(client_to_server_key),
            client_to_server_prefix: Zeroizing::new(client_to_server_prefix),
            server_to_client_key: Zeroizing::new(server_to_client_key),
            server_to_client_prefix: Zeroizing::new(server_to_client_prefix),
            session_id,
        })
    }

    pub fn session_id(&self) -> [u8; 8] {
        self.session_id
    }

    /// Duplicate the derived directional keys for a bounded handshake commit retry.
    /// The copies remain zeroizing and are discarded when the pending commit expires.
    pub fn duplicate(&self) -> Self {
        Self {
            client_to_server_key: Zeroizing::new(*self.client_to_server_key),
            client_to_server_prefix: Zeroizing::new(*self.client_to_server_prefix),
            server_to_client_key: Zeroizing::new(*self.server_to_client_key),
            server_to_client_prefix: Zeroizing::new(*self.server_to_client_prefix),
            session_id: self.session_id,
        }
    }

    pub fn into_client_codecs(self) -> (FrameSealer, FrameOpener) {
        let sender = FrameSealer::new(
            *self.client_to_server_key,
            *self.client_to_server_prefix,
            self.session_id,
            FrameDirection::ClientToServer,
        );
        let receiver = FrameOpener::new(
            *self.server_to_client_key,
            *self.server_to_client_prefix,
            self.session_id,
            FrameDirection::ServerToClient,
        );
        (sender, receiver)
    }

    pub fn into_server_codecs(self) -> (FrameOpener, FrameSealer) {
        let receiver = FrameOpener::new(
            *self.client_to_server_key,
            *self.client_to_server_prefix,
            self.session_id,
            FrameDirection::ClientToServer,
        );
        let sender = FrameSealer::new(
            *self.server_to_client_key,
            *self.server_to_client_prefix,
            self.session_id,
            FrameDirection::ServerToClient,
        );
        (receiver, sender)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DataDatagram, IpPacketKind};

    fn test_packet() -> DataDatagram {
        let mut packet = vec![0u8; 20];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&20u16.to_be_bytes());
        DataDatagram {
            kind: IpPacketKind::Ipv4,
            packet,
        }
    }

    #[test]
    fn noise_xx_authenticates_server_and_derives_directional_frame_keys() {
        let server_key = NoiseServerKeyPair::generate().unwrap();
        let token = b"one-time-test-device-token";

        let (client, message1) = NoiseClientHandshake::new(server_key.public_key(), token).unwrap();
        let mut server = NoiseServerHandshake::new(&server_key).unwrap();
        let message2 = server.receive_client_hello(&message1).unwrap();
        let finish = client.receive_server_hello(&message2).unwrap();

        let (ack, server_keys) = server
            .receive_client_finish(&finish.message, |candidate| candidate == token)
            .unwrap();
        let client_keys = finish.accept_server_ack(&ack).unwrap();
        assert_eq!(client_keys.session_id(), server_keys.session_id());

        let (mut client_tx, mut client_rx) = client_keys.into_client_codecs();
        let (mut server_rx, mut server_tx) = server_keys.into_server_codecs();
        let packet = test_packet();
        let uplink = client_tx.seal(&packet.encode().unwrap()).unwrap();
        assert_eq!(server_rx.open(&uplink).unwrap(), packet.encode().unwrap());
        let downlink = server_tx.seal(&packet.encode().unwrap()).unwrap();
        assert_eq!(client_rx.open(&downlink).unwrap(), packet.encode().unwrap());
    }

    #[test]
    fn persisted_server_key_pair_is_validated() {
        let generated = NoiseServerKeyPair::generate().unwrap();
        let loaded = NoiseServerKeyPair::from_bytes(
            Zeroizing::new(generated.private_key_bytes().to_vec()),
            generated.public_key().to_vec(),
        )
        .unwrap();
        assert_eq!(loaded.public_key(), generated.public_key());

        let wrong = NoiseServerKeyPair::generate().unwrap();
        assert!(NoiseServerKeyPair::from_bytes(
            Zeroizing::new(generated.private_key_bytes().to_vec()),
            wrong.public_key().to_vec(),
        )
        .is_err());
    }

    #[test]
    fn rejects_wrong_pinned_server_key() {
        let server_key = NoiseServerKeyPair::generate().unwrap();
        let wrong_key = NoiseServerKeyPair::generate().unwrap();
        let (client, message1) =
            NoiseClientHandshake::new(wrong_key.public_key(), b"credential").unwrap();
        let mut server = NoiseServerHandshake::new(&server_key).unwrap();
        let message2 = server.receive_client_hello(&message1).unwrap();
        assert_eq!(
            client.receive_server_hello(&message2).err().unwrap(),
            SessionHandshakeError::ServerIdentityMismatch
        );
    }

    #[test]
    fn rejects_invalid_client_credential_without_server_ack() {
        let server_key = NoiseServerKeyPair::generate().unwrap();
        let token = b"bad-credential";
        let (client, message1) = NoiseClientHandshake::new(server_key.public_key(), token).unwrap();
        let mut server = NoiseServerHandshake::new(&server_key).unwrap();
        let message2 = server.receive_client_hello(&message1).unwrap();
        let finish = client.receive_server_hello(&message2).unwrap();
        assert_eq!(
            server
                .receive_client_finish(&finish.message, |_| false)
                .err()
                .unwrap(),
            SessionHandshakeError::CredentialRejected
        );
    }
}
