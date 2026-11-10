//! End-to-end Noise handshake state machine over TURN handshake envelopes.
//!
//! This module owns the cryptographic phase transitions only. Socket ownership,
//! TURN ChannelData framing, retries, replay caching, admission control and
//! authenticated relay-source binding remain with the transport/session layer.

use crate::{
    handshake_datagram::{HandshakeEnvelope, HandshakeEnvelopeError, HandshakePhase},
    session_handshake::{
        NoiseClientFinish, NoiseClientHandshake, NoiseServerHandshake,
        NoiseServerKeyPair, SessionFrameKeys, SessionHandshakeError,
    },
    turn_path_context::TurnPathContext,
};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum TurnHandshakeError {
    #[error("invalid handshake envelope: {0}")]
    Envelope(#[from] HandshakeEnvelopeError),
    #[error("Noise handshake failed: {0}")]
    Noise(#[from] SessionHandshakeError),
    #[error("unexpected handshake phase")]
    UnexpectedPhase,
    #[error("handshake identifier does not match")]
    HandshakeIdMismatch,
    #[error("handshake phase has already been processed")]
    InvalidState,
}

/// Client-side three-message Noise XX exchange plus encrypted server ack.
pub struct TurnHandshakeClient {
    handshake_id: [u8; 16],
    noise: Option<NoiseClientHandshake>,
    pending_auth: Option<NoiseClientFinish>,
}

impl TurnHandshakeClient {
    /// Creates ClientInit. The caller must send the returned envelope through
    /// the established TURN allocation and retain exact bytes for retries.
    pub fn new(
        pinned_server_key: &[u8],
        credential: &[u8],
        handshake_id: [u8; 16],
    ) -> Result<(Self, Vec<u8>), TurnHandshakeError> {
        if handshake_id.iter().all(|byte| *byte == 0) {
            return Err(TurnHandshakeError::HandshakeIdMismatch);
        }
        let (noise, message) = NoiseClientHandshake::new(pinned_server_key, credential)?;
        let datagram = HandshakeEnvelope {
            phase: HandshakePhase::ClientInit,
            handshake_id,
            payload: message,
        }.encode()?;
        Ok((Self {
            handshake_id,
            noise: Some(noise),
            pending_auth: None,
        }, datagram))
    }

    pub fn new_with_path_context(
        pinned_server_key: &[u8],
        credential: &[u8],
        context: TurnPathContext,
        handshake_id: [u8; 16],
    ) -> Result<(Self, Vec<u8>), TurnHandshakeError> {
        if handshake_id.iter().all(|byte| *byte == 0) {
            return Err(TurnHandshakeError::HandshakeIdMismatch);
        }
        let (noise, message) =
            NoiseClientHandshake::new_with_path_context(pinned_server_key, credential, context)?;
        let datagram = HandshakeEnvelope {
            phase: HandshakePhase::ClientInit,
            handshake_id,
            payload: message,
        }.encode()?;
        Ok((Self {
            handshake_id,
            noise: Some(noise),
            pending_auth: None,
        }, datagram))
    }

    /// Authenticates the server static key through Noise XX and returns the
    /// encrypted ClientFinish envelope. No tunnel keys are enabled yet.
    pub fn receive_server_response(
        &mut self,
        datagram: &[u8],
    ) -> Result<Vec<u8>, TurnHandshakeError> {
        let envelope = HandshakeEnvelope::decode(datagram)?;
        self.validate(&envelope, HandshakePhase::ServerResponse)?;
        if self.pending_auth.is_some() {
            return Err(TurnHandshakeError::InvalidState);
        }
        let noise = self.noise.take().ok_or(TurnHandshakeError::InvalidState)?;
        let finish = noise.receive_server_hello(&envelope.payload)?;
        let response = HandshakeEnvelope {
            phase: HandshakePhase::ClientFinish,
            handshake_id: self.handshake_id,
            payload: finish.message.clone(),
        }.encode()?;
        self.pending_auth = Some(finish);
        Ok(response)
    }

    /// Enables directional frame keys only after the encrypted server
    /// acknowledgement has been verified.
    pub fn receive_server_ack(
        &mut self,
        datagram: &[u8],
    ) -> Result<SessionFrameKeys, TurnHandshakeError> {
        let (keys, payload) = self.receive_server_ack_with_payload(datagram)?;
        if !payload.is_empty() {
            return Err(TurnHandshakeError::Noise(SessionHandshakeError::InvalidAcknowledgement));
        }
        Ok(keys)
    }

    pub fn receive_server_ack_with_payload(
        &mut self,
        datagram: &[u8],
    ) -> Result<(SessionFrameKeys, Vec<u8>), TurnHandshakeError> {
        let envelope = HandshakeEnvelope::decode(datagram)?;
        self.validate(&envelope, HandshakePhase::ServerAck)?;
        let pending = self.pending_auth.take().ok_or(TurnHandshakeError::InvalidState)?;
        Ok(pending.accept_server_ack_with_payload(&envelope.payload)?)
    }

    fn validate(
        &self,
        envelope: &HandshakeEnvelope,
        expected: HandshakePhase,
    ) -> Result<(), TurnHandshakeError> {
        if envelope.handshake_id != self.handshake_id {
            return Err(TurnHandshakeError::HandshakeIdMismatch);
        }
        if envelope.phase != expected {
            return Err(TurnHandshakeError::UnexpectedPhase);
        }
        Ok(())
    }
}

/// Server-side Noise XX responder. A caller must apply bounded admission and
/// replay-cache lookup before invoking state transitions on received requests.
pub struct TurnHandshakeServer {
    noise: Option<NoiseServerHandshake>,
    handshake_id: Option<[u8; 16]>,
}

impl TurnHandshakeServer {
    pub fn new(keypair: &NoiseServerKeyPair) -> Result<Self, TurnHandshakeError> {
        Ok(Self {
            noise: Some(NoiseServerHandshake::new(keypair)?),
            handshake_id: None,
        })
    }

    /// Processes ClientInit exactly once and returns ServerResponse.
    pub fn receive_client_init(
        &mut self,
        datagram: &[u8],
    ) -> Result<Vec<u8>, TurnHandshakeError> {
        let envelope = HandshakeEnvelope::decode(datagram)?;
        if envelope.phase != HandshakePhase::ClientInit {
            return Err(TurnHandshakeError::UnexpectedPhase);
        }
        if self.handshake_id.is_some() {
            return Err(TurnHandshakeError::InvalidState);
        }
        let noise = self.noise.as_mut().ok_or(TurnHandshakeError::InvalidState)?;
        let message = noise.receive_client_hello(&envelope.payload)?;
        let response = HandshakeEnvelope {
            phase: HandshakePhase::ServerResponse,
            handshake_id: envelope.handshake_id,
            payload: message,
        }.encode()?;
        self.handshake_id = Some(envelope.handshake_id);
        Ok(response)
    }

    /// Verifies the encrypted client credential before creating ServerAck or
    /// exposing frame keys. The caller must cache the exact response before
    /// sending it and register the session only after its authenticated state
    /// transition has been committed.
    pub fn receive_client_finish(
        &mut self,
        datagram: &[u8],
        verify_credential: impl FnOnce(&[u8]) -> bool,
    ) -> Result<(Vec<u8>, SessionFrameKeys), TurnHandshakeError> {
        self.receive_client_finish_with_payload(datagram, verify_credential, &[])
    }

    pub fn receive_client_finish_with_payload(
        &mut self,
        datagram: &[u8],
        verify_credential: impl FnOnce(&[u8]) -> bool,
        acknowledgement_payload: &[u8],
    ) -> Result<(Vec<u8>, SessionFrameKeys), TurnHandshakeError> {
        let (response, keys, _) = self.receive_client_finish_with_path_context(
            datagram,
            verify_credential,
            acknowledgement_payload,
        )?;
        Ok((response, keys))
    }

    pub fn receive_client_finish_with_path_context(
        &mut self,
        datagram: &[u8],
        verify_credential: impl FnOnce(&[u8]) -> bool,
        acknowledgement_payload: &[u8],
    ) -> Result<(Vec<u8>, SessionFrameKeys, Option<TurnPathContext>), TurnHandshakeError> {
        self.receive_client_finish_with_path_context_builder(
            datagram,
            verify_credential,
            |_| Ok(acknowledgement_payload.to_vec()),
        )
    }

    pub fn receive_client_finish_with_path_context_builder(
        &mut self,
        datagram: &[u8],
        verify_credential: impl FnOnce(&[u8]) -> bool,
        build_acknowledgement: impl FnOnce(Option<TurnPathContext>) -> Result<Vec<u8>, SessionHandshakeError>,
    ) -> Result<(Vec<u8>, SessionFrameKeys, Option<TurnPathContext>), TurnHandshakeError> {
        let envelope = HandshakeEnvelope::decode(datagram)?;
        if envelope.phase != HandshakePhase::ClientFinish {
            return Err(TurnHandshakeError::UnexpectedPhase);
        }
        if self.handshake_id != Some(envelope.handshake_id) {
            return Err(TurnHandshakeError::HandshakeIdMismatch);
        }
        let noise = self.noise.take().ok_or(TurnHandshakeError::InvalidState)?;
        let (acknowledgement, keys, path_context) =
            noise.receive_client_finish_with_path_context_builder(
                &envelope.payload,
                verify_credential,
                build_acknowledgement,
            )?;
        let response = HandshakeEnvelope {
            phase: HandshakePhase::ServerAck,
            handshake_id: envelope.handshake_id,
            payload: acknowledgement,
        }.encode()?;
        Ok((response, keys, path_context))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn completes_noise_exchange_over_handshake_envelopes() {
        let keypair = NoiseServerKeyPair::generate().unwrap();
        let credential = b"test-credential";
        let handshake_id = [0x5a; 16];
        let (mut client, client_init) =
            TurnHandshakeClient::new(keypair.public_key(), credential, handshake_id).unwrap();
        let mut server = TurnHandshakeServer::new(&keypair).unwrap();

        let server_response = server.receive_client_init(&client_init).unwrap();
        let client_finish = client.receive_server_response(&server_response).unwrap();
        let (server_ack, server_keys) = server.receive_client_finish(
            &client_finish,
            |candidate| candidate == credential,
        ).unwrap();
        let client_keys = client.receive_server_ack(&server_ack).unwrap();

        assert_eq!(client_keys.session_id(), server_keys.session_id());
    }

    #[test]
    fn authenticates_path_context_inside_noise_handshake() {
        let keypair = NoiseServerKeyPair::generate().unwrap();
        let credential = b"test-path-credential";
        let context = TurnPathContext {
            group_id: [0x37; 16],
            path_id: 1,
            path_count: 3,
        };
        let (mut client, client_init) = TurnHandshakeClient::new_with_path_context(
            keypair.public_key(),
            credential,
            context,
            [0x5b; 16],
        ).unwrap();
        let mut server = TurnHandshakeServer::new(&keypair).unwrap();
        let response = server.receive_client_init(&client_init).unwrap();
        let finish = client.receive_server_response(&response).unwrap();
        let (ack, server_keys, received_context) = server
            .receive_client_finish_with_path_context(
                &finish,
                |candidate| candidate == credential,
                &[],
            )
            .unwrap();
        assert_eq!(received_context, Some(context));
        let client_keys = client.receive_server_ack(&ack).unwrap();
        assert_eq!(client_keys.session_id(), server_keys.session_id());
    }

    #[test]
    fn rejects_wrong_handshake_id_without_advancing_client_state() {
        let keypair = NoiseServerKeyPair::generate().unwrap();
        let (mut client, client_init) =
            TurnHandshakeClient::new(keypair.public_key(), b"credential", [1; 16]).unwrap();
        let mut server = TurnHandshakeServer::new(&keypair).unwrap();
        let response = server.receive_client_init(&client_init).unwrap();
        let mut envelope = HandshakeEnvelope::decode(&response).unwrap();
        envelope.handshake_id = [2; 16];
        let forged = envelope.encode().unwrap();

        assert!(matches!(
            client.receive_server_response(&forged),
            Err(TurnHandshakeError::HandshakeIdMismatch)
        ));
        assert!(client.receive_server_response(&response).is_ok());
    }

    #[test]
    fn rejected_client_credential_never_produces_server_ack() {
        let keypair = NoiseServerKeyPair::generate().unwrap();
        let (mut client, client_init) =
            TurnHandshakeClient::new(keypair.public_key(), b"credential", [3; 16]).unwrap();
        let mut server = TurnHandshakeServer::new(&keypair).unwrap();
        let response = server.receive_client_init(&client_init).unwrap();
        let finish = client.receive_server_response(&response).unwrap();

        assert!(matches!(
            server.receive_client_finish(&finish, |_| false),
            Err(TurnHandshakeError::Noise(SessionHandshakeError::CredentialRejected))
        ));
    }
}
