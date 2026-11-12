//! Optional ordering metadata for packets merged from independent TURN paths.
//!
//! A sequence number is assigned by the gateway per client tunnel. The client
//! resequences packets before writing them to TUN. Unsequenced packets retain
//! the original datagram encoding for client-to-server traffic.

use crate::{DataDatagram, DatagramError, MAX_DATAGRAM_SIZE};

const SEQUENCE_MAGIC: &[u8; 4] = b"GHSQ";
const SEQUENCE_HEADER_LEN: usize = 12;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SequencedDataDatagram {
    pub sequence: Option<u64>,
    pub datagram: DataDatagram,
}

impl SequencedDataDatagram {
    pub fn new(sequence: u64, datagram: DataDatagram) -> Self {
        Self { sequence: Some(sequence), datagram }
    }

    pub fn unsequenced(datagram: DataDatagram) -> Self {
        Self { sequence: None, datagram }
    }

    pub fn encode(&self) -> Result<Vec<u8>, DatagramError> {
        let encoded = self.datagram.encode()?;
        let Some(sequence) = self.sequence else {
            return Ok(encoded);
        };
        let total_len = SEQUENCE_HEADER_LEN.checked_add(encoded.len())
            .ok_or(DatagramError::TooLarge)?;
        if total_len > MAX_DATAGRAM_SIZE {
            return Err(DatagramError::TooLarge);
        }
        let mut output = Vec::with_capacity(total_len);
        output.extend_from_slice(SEQUENCE_MAGIC);
        output.extend_from_slice(&sequence.to_be_bytes());
        output.extend_from_slice(&encoded);
        Ok(output)
    }

    pub fn decode(encoded: &[u8]) -> Result<Self, DatagramError> {
        if encoded.len() > MAX_DATAGRAM_SIZE {
            return Err(DatagramError::TooLarge);
        }
        if encoded.starts_with(SEQUENCE_MAGIC) {
            if encoded.len() <= SEQUENCE_HEADER_LEN {
                return Err(DatagramError::InvalidLength);
            }
            let sequence = u64::from_be_bytes(
                encoded[4..SEQUENCE_HEADER_LEN].try_into()
                    .map_err(|_| DatagramError::InvalidLength)?,
            );
            let datagram = DataDatagram::decode(&encoded[SEQUENCE_HEADER_LEN..])?;
            Ok(Self::new(sequence, datagram))
        } else {
            Ok(Self::unsequenced(DataDatagram::decode(encoded)?))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::IpPacketKind;

    fn packet(length: usize) -> DataDatagram {
        let mut packet = vec![0u8; length.max(20)];
        packet[0] = 0x45;
        let packet_len = packet.len() as u16;
        packet[2..4].copy_from_slice(&packet_len.to_be_bytes());
        DataDatagram { kind: IpPacketKind::Ipv4, packet }
    }

    #[test]
    fn sequenced_datagram_round_trips_sequence_and_packet() {
        let datagram = SequencedDataDatagram::new(0x0102_0304_0506_0708, packet(28));
        assert_eq!(SequencedDataDatagram::decode(&datagram.encode().unwrap()).unwrap(), datagram);
    }

    #[test]
    fn unsequenced_datagram_keeps_legacy_wire_encoding() {
        let datagram = packet(28);
        let encoded = SequencedDataDatagram::unsequenced(datagram.clone()).encode().unwrap();
        assert_eq!(DataDatagram::decode(&encoded).unwrap(), datagram);
        assert_eq!(SequencedDataDatagram::decode(&encoded).unwrap().sequence, None);
    }

    #[test]
    fn rejects_truncated_sequence_envelope() {
        assert_eq!(SequencedDataDatagram::decode(b"GHSQ"), Err(DatagramError::InvalidLength));
    }

    #[test]
    fn rejects_sequence_envelope_that_exceeds_datagram_limit() {
        assert_eq!(SequencedDataDatagram::new(1, packet(1190)).encode(), Err(DatagramError::TooLarge));
    }
}
