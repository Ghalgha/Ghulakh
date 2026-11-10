//! Shared, versioned control-plane and data-plane message types.

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const PROTOCOL_VERSION: u16 = 1;
pub const MAX_CONTROL_BODY: usize = 16 * 1024;
pub const MAX_REQUEST_ID_LEN: usize = 128;
pub const MAX_CREDENTIAL_LEN: usize = 256;
pub const DATAGRAM_VERSION: u8 = 1;
pub const DATAGRAM_HEADER_LEN: usize = 8;
pub const MAX_DATAGRAM_SIZE: usize = 1200;
const DATAGRAM_MAGIC: &[u8; 4] = b"GHLK";

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
        client_ipv4: String,
        tunnel_enabled: bool,
        forwarding_enabled: bool,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum IpPacketKind {
    Ipv4 = 4,
    Ipv6 = 6,
}

impl TryFrom<u8> for IpPacketKind {
    type Error = DatagramError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            4 => Ok(Self::Ipv4),
            6 => Ok(Self::Ipv6),
            _ => Err(DatagramError::UnsupportedPacketKind),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataDatagram {
    pub kind: IpPacketKind,
    pub packet: Vec<u8>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum DatagramError {
    #[error("invalid datagram magic")]
    InvalidMagic,
    #[error("unsupported datagram version")]
    UnsupportedVersion,
    #[error("unsupported IP packet kind")]
    UnsupportedPacketKind,
    #[error("datagram length is invalid")]
    InvalidLength,
    #[error("datagram exceeds the maximum size")]
    TooLarge,
    #[error("IP packet version does not match datagram kind")]
    IpVersionMismatch,
    #[error("IP packet header or declared length is invalid")]
    InvalidIpPacket,
}


fn validate_ip_packet(kind: IpPacketKind, packet: &[u8]) -> Result<(), DatagramError> {
    let first_byte = *packet.first().ok_or(DatagramError::InvalidLength)?;
    let version = first_byte >> 4;
    if version != kind as u8 {
        return Err(DatagramError::IpVersionMismatch);
    }

    match kind {
        IpPacketKind::Ipv4 => {
            if packet.len() < 20 {
                return Err(DatagramError::InvalidIpPacket);
            }
            let header_len = usize::from(packet[0] & 0x0f) * 4;
            let total_len = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
            if header_len < 20 || header_len > packet.len() || total_len != packet.len() {
                return Err(DatagramError::InvalidIpPacket);
            }
        }
        IpPacketKind::Ipv6 => {
            if packet.len() < 40 {
                return Err(DatagramError::InvalidIpPacket);
            }
            let payload_len = usize::from(u16::from_be_bytes([packet[4], packet[5]]));
            if payload_len + 40 != packet.len() {
                return Err(DatagramError::InvalidIpPacket);
            }
        }
    }
    Ok(())
}

impl DataDatagram {
    pub fn encode(&self) -> Result<Vec<u8>, DatagramError> {
        let total_len = DATAGRAM_HEADER_LEN + self.packet.len();
        if total_len > MAX_DATAGRAM_SIZE {
            return Err(DatagramError::TooLarge);
        }
        validate_ip_packet(self.kind, &self.packet)?;

        let payload_len = u16::try_from(self.packet.len())
            .map_err(|_| DatagramError::TooLarge)?;
        let mut encoded = Vec::with_capacity(total_len);
        encoded.extend_from_slice(DATAGRAM_MAGIC);
        encoded.push(DATAGRAM_VERSION);
        encoded.push(self.kind as u8);
        encoded.extend_from_slice(&payload_len.to_be_bytes());
        encoded.extend_from_slice(&self.packet);
        Ok(encoded)
    }

    pub fn decode(encoded: &[u8]) -> Result<Self, DatagramError> {
        if encoded.len() > MAX_DATAGRAM_SIZE {
            return Err(DatagramError::TooLarge);
        }
        if encoded.len() < DATAGRAM_HEADER_LEN {
            return Err(DatagramError::InvalidLength);
        }
        if &encoded[..4] != DATAGRAM_MAGIC {
            return Err(DatagramError::InvalidMagic);
        }
        if encoded[4] != DATAGRAM_VERSION {
            return Err(DatagramError::UnsupportedVersion);
        }

        let kind = IpPacketKind::try_from(encoded[5])?;
        let declared_len = u16::from_be_bytes([encoded[6], encoded[7]]) as usize;
        let packet = &encoded[DATAGRAM_HEADER_LEN..];
        if declared_len == 0 || declared_len != packet.len() {
            return Err(DatagramError::InvalidLength);
        }
        validate_ip_packet(kind, packet)?;

        Ok(Self {
            kind,
            packet: packet.to_vec(),
        })
    }
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
        assert_eq!(
            validate_message(&message),
            Err(ProtocolError::InvalidCredentialLength)
        );
    }

    #[test]
    fn rejects_oversized_credential() {
        let message = ControlMessage::ClientHello {
            credential: "x".repeat(MAX_CREDENTIAL_LEN + 1),
            request_id: "r1".into(),
        };
        assert_eq!(
            validate_message(&message),
            Err(ProtocolError::InvalidCredentialLength)
        );
    }

    #[test]
    fn control_envelope_round_trip_preserves_version() {
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

    #[test]
    fn ipv4_datagram_round_trip() {
        let mut packet = vec![0u8; 20];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&20u16.to_be_bytes());
        let datagram = DataDatagram {
            kind: IpPacketKind::Ipv4,
            packet,
        };
        let encoded = datagram.encode().unwrap();
        assert_eq!(DataDatagram::decode(&encoded).unwrap(), datagram);
    }

    #[test]
    fn ipv6_datagram_round_trip() {
        let mut packet = vec![0u8; 40];
        packet[0] = 0x60;
        let datagram = DataDatagram {
            kind: IpPacketKind::Ipv6,
            packet,
        };
        let encoded = datagram.encode().unwrap();
        assert_eq!(DataDatagram::decode(&encoded).unwrap(), datagram);
    }

    #[test]
    fn rejects_datagram_with_mismatched_ip_version() {
        let datagram = DataDatagram {
            kind: IpPacketKind::Ipv4,
            packet: vec![0x60; 40],
        };
        assert_eq!(datagram.encode(), Err(DatagramError::IpVersionMismatch));
    }

    #[test]
    fn rejects_datagram_with_invalid_declared_length() {
        let mut encoded = DataDatagram {
            kind: IpPacketKind::Ipv4,
            packet: {
                let mut packet = vec![0u8; 20];
                packet[0] = 0x45;
                packet[2..4].copy_from_slice(&20u16.to_be_bytes());
                packet
            },
        }
        .encode()
        .unwrap();
        encoded[7] = 19;
        assert_eq!(
            DataDatagram::decode(&encoded),
            Err(DatagramError::InvalidLength)
        );
    }

    #[test]
    fn rejects_invalid_ipv4_total_length() {
        let mut packet = vec![0u8; 20];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&19u16.to_be_bytes());
        let datagram = DataDatagram {
            kind: IpPacketKind::Ipv4,
            packet,
        };
        assert_eq!(datagram.encode(), Err(DatagramError::InvalidIpPacket));
    }

    #[test]
    fn rejects_oversized_datagram() {
        let datagram = DataDatagram {
            kind: IpPacketKind::Ipv4,
            packet: {
                let mut packet = vec![0u8; MAX_DATAGRAM_SIZE];
                packet[0] = 0x45;
                packet[2..4].copy_from_slice(&(MAX_DATAGRAM_SIZE as u16).to_be_bytes());
                packet
            },
        };
        assert_eq!(datagram.encode(), Err(DatagramError::TooLarge));
    }
}
