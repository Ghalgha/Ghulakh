//! Shared, versioned control-plane message types.

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const PROTOCOL_VERSION: u16 = 1;
pub const MAX_CONTROL_BODY: usize = 16 * 1024;
pub const MAX_REQUEST_ID_LEN: usize = 128;
pub const MAX_CREDENTIAL_LEN: usize = 256;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ControlEnvelope {
    pub version: u16,
    pub message: ControlMessage,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", content = "body", rename_all = "snake_case")]
pub enum ControlMessage {
    ClientHello {
        credential: String,
        request_id: String,
    },
    ServerHello {
        session_id: String,
        request_id: String,
    },
    Ping {
        request_id: String,
    },
    Pong {
        request_id: String,
    },
    Close {
        request_id: String,
    },
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ProtocolError {
    #[error("unsupported protocol version: {0}")]
    UnsupportedVersion(u16),
    #[error("control body exceeds maximum size")]
    BodyTooLarge,
    #[error("empty request identifier")]
    EmptyRequestId,
    #[error("request identifier exceeds maximum length")]
    RequestIdTooLong,
    #[error("credential length is invalid")]
    InvalidCredentialLength,
}

pub fn validate_envelope(
    version: u16,
    body_len: usize,
    request_id: &str,
) -> Result<(), ProtocolError> {
    if version != PROTOCOL_VERSION {
        return Err(ProtocolError::UnsupportedVersion(version));
    }
    if body_len > MAX_CONTROL_BODY {
        return Err(ProtocolError::BodyTooLarge);
    }
    if request_id.trim().is_empty() {
        return Err(ProtocolError::EmptyRequestId);
    }
    if request_id.len() > MAX_REQUEST_ID_LEN {
        return Err(ProtocolError::RequestIdTooLong);
    }
    Ok(())
}

pub fn validate_message(message: &ControlMessage) -> Result<(), ProtocolError> {
    if let ControlMessage::ClientHello { credential, .. } = message {
        if credential.is_empty() || credential.len() > MAX_CREDENTIAL_LEN {
            return Err(ProtocolError::InvalidCredentialLength);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_unknown_version() {
        assert_eq!(
            validate_envelope(99, 1, "r1"),
            Err(ProtocolError::UnsupportedVersion(99))
        );
    }

    #[test]
    fn rejects_oversized_body() {
        assert_eq!(
            validate_envelope(1, MAX_CONTROL_BODY + 1, "r1"),
            Err(ProtocolError::BodyTooLarge)
        );
    }

    #[test]
    fn rejects_empty_request_id() {
        assert_eq!(
            validate_envelope(1, 1, "  "),
            Err(ProtocolError::EmptyRequestId)
        );
    }

    #[test]
    fn rejects_long_request_id() {
        let request_id = "x".repeat(MAX_REQUEST_ID_LEN + 1);
        assert_eq!(
            validate_envelope(1, 1, &request_id),
            Err(ProtocolError::RequestIdTooLong)
        );
    }

    #[test]
    fn rejects_empty_credential() {
        let message = ControlMessage::ClientHello {
            credential: String::new(),
            request_id: "r1".into(),
        };
        assert_eq!(validate_message(&message), Err(ProtocolError::InvalidCredentialLength));
    }

    #[test]
    fn envelope_round_trip_preserves_version() {
        let envelope = ControlEnvelope {
            version: PROTOCOL_VERSION,
            message: ControlMessage::Ping {
                request_id: "test-1".into(),
            },
        };
        let encoded = serde_json::to_vec(&envelope).unwrap();
        let decoded: ControlEnvelope = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(decoded, envelope);
    }
}
