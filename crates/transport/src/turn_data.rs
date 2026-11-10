//! Composition of authenticated tunnel frames and TURN ChannelData messages.
//!
//! This is the single-allocation UDP data path codec. Socket scheduling,
//! ChannelBind confirmation, permission checks and session key agreement are
//! deliberately owned by their respective drivers.

use anyhow::{ensure, Context, Result};
use ghulakh_protocol::{
    secure_frame::{FrameOpener, FrameSealer},
    turn_channel_data::{decode_channel_data, encode_channel_data},
    DataDatagram,
};

pub struct TurnDataSender {
    channel_number: u16,
    sealer: FrameSealer,
}

impl TurnDataSender {
    pub fn new(channel_number: u16, sealer: FrameSealer) -> Self {
        Self { channel_number, sealer }
    }

    /// Encode one IP packet as AEAD-protected bytes inside TURN ChannelData.
    pub fn encode_packet(&mut self, packet: &DataDatagram) -> Result<Vec<u8>> {
        let encoded_packet = packet.encode().context("encode IP datagram")?;
        let protected = self.sealer.seal(&encoded_packet).context("protect tunnel frame")?;
        encode_channel_data(self.channel_number, &protected)
            .context("encode TURN ChannelData")
    }
}

pub struct TurnDataReceiver {
    channel_number: u16,
    opener: FrameOpener,
}

impl TurnDataReceiver {
    pub fn new(channel_number: u16, opener: FrameOpener) -> Self {
        Self { channel_number, opener }
    }

    /// Validate channel framing, authenticate/decrypt the frame, then decode IP.
    pub fn decode_packet(&mut self, datagram: &[u8]) -> Result<DataDatagram> {
        let channel_data = decode_channel_data(datagram).context("decode TURN ChannelData")?;
        ensure!(
            channel_data.channel_number == self.channel_number,
            "TURN ChannelData arrived on an unexpected channel"
        );
        let plaintext = self.opener.open(channel_data.data)
            .context("authenticate tunnel frame")?;
        DataDatagram::decode(&plaintext).context("decode protected IP datagram")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ghulakh_protocol::secure_frame::FrameDirection;

    fn pair() -> (TurnDataSender, TurnDataReceiver) {
        let key = [0x42; 32];
        let prefix = [0x31; 4];
        let session = [0x77; 8];
        (
            TurnDataSender::new(
                0x4001,
                FrameSealer::new(key, prefix, session, FrameDirection::ClientToServer),
            ),
            TurnDataReceiver::new(
                0x4001,
                FrameOpener::new(key, prefix, session, FrameDirection::ClientToServer),
            ),
        )
    }

    fn ipv4_packet() -> DataDatagram {
        let mut packet = vec![0u8; 20];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&20u16.to_be_bytes());
        DataDatagram {
            kind: ghulakh_protocol::IpPacketKind::Ipv4,
            packet,
        }
    }

    #[test]
    fn round_trips_ip_packet_through_protected_channel_data() {
        let (mut sender, mut receiver) = pair();
        let packet = ipv4_packet();
        let encoded = sender.encode_packet(&packet).unwrap();
        assert_eq!(&encoded[..2], &[0x40, 0x01]);
        assert_eq!(receiver.decode_packet(&encoded).unwrap(), packet);
    }

    #[test]
    fn rejects_wrong_channel_before_decryption() {
        let (mut sender, _) = pair();
        let mut encoded = sender.encode_packet(&ipv4_packet()).unwrap();
        encoded[1] = 0x02;
        let mut receiver = pair().1;
        assert!(receiver.decode_packet(&encoded).is_err());
    }

    #[test]
    fn rejects_replayed_channel_data_frame() {
        let (mut sender, mut receiver) = pair();
        let encoded = sender.encode_packet(&ipv4_packet()).unwrap();
        receiver.decode_packet(&encoded).unwrap();
        assert!(receiver.decode_packet(&encoded).is_err());
    }
}
