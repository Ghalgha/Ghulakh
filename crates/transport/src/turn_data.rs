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


#[cfg(test)]
mod relay_path_tests {
    use super::*;
    use ghulakh_protocol::secure_frame::FrameDirection;
    use tokio::net::UdpSocket;
    use tokio::time::{timeout, Duration};

    const CHANNEL: u16 = 0x4001;
    const SESSION: [u8; 8] = [0x71; 8];
    const CLIENT_KEY: [u8; 32] = [0x11; 32];
    const SERVER_KEY: [u8; 32] = [0x22; 32];
    const CLIENT_NONCE: [u8; 4] = [0x31; 4];
    const SERVER_NONCE: [u8; 4] = [0x42; 4];

    fn test_packet(marker: u8) -> DataDatagram {
        let mut packet = vec![0u8; 20];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&20u16.to_be_bytes());
        packet[8] = 64;
        packet[9] = 17;
        packet[12..16].copy_from_slice(&[10, 77, 0, 2]);
        packet[16..20].copy_from_slice(&[10, 77, 0, marker]);
        DataDatagram {
            kind: ghulakh_protocol::IpPacketKind::Ipv4,
            packet,
        }
    }

    // Models only the datagram forwarding behavior needed by the gateway path:
    // client -> relay -> gateway, then gateway -> relay -> client.
    // It is not an implementation of the TURN control protocol.
    #[tokio::test]
    async fn protected_ip_packet_round_trips_through_relay_and_gateway() {
        let relay = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let relay_addr = relay.local_addr().unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_addr = client.local_addr().unwrap();
        let gateway = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let gateway_addr = gateway.local_addr().unwrap();

        let relay_task = tokio::spawn(async move {
            let mut buffer = vec![0u8; 2048];
            loop {
                let (length, source) = relay.recv_from(&mut buffer).await.unwrap();
                if source == client_addr {
                    relay.send_to(&buffer[..length], gateway_addr).await.unwrap();
                } else if source == gateway_addr {
                    relay.send_to(&buffer[..length], client_addr).await.unwrap();
                    return;
                } else {
                    panic!("unexpected UDP source at relay: {source}");
                }
            }
        });

        let mut client_tx = TurnDataSender::new(
            CHANNEL,
            FrameSealer::new(
                CLIENT_KEY,
                CLIENT_NONCE,
                SESSION,
                FrameDirection::ClientToServer,
            ),
        );
        let mut client_rx = TurnDataReceiver::new(
            CHANNEL,
            FrameOpener::new(
                SERVER_KEY,
                SERVER_NONCE,
                SESSION,
                FrameDirection::ServerToClient,
            ),
        );
        let mut gateway_rx = TurnDataReceiver::new(
            CHANNEL,
            FrameOpener::new(
                CLIENT_KEY,
                CLIENT_NONCE,
                SESSION,
                FrameDirection::ClientToServer,
            ),
        );
        let mut gateway_tx = TurnDataSender::new(
            CHANNEL,
            FrameSealer::new(
                SERVER_KEY,
                SERVER_NONCE,
                SESSION,
                FrameDirection::ServerToClient,
            ),
        );

        let original = test_packet(9);
        let uplink = client_tx.encode_packet(&original).unwrap();
        client.send_to(&uplink, relay_addr).await.unwrap();

        let mut gateway_buffer = vec![0u8; 2048];
        let (length, relay_source) = timeout(
            Duration::from_secs(2),
            gateway.recv_from(&mut gateway_buffer),
        )
        .await
        .expect("gateway did not receive relayed uplink")
        .unwrap();
        assert_eq!(relay_source, relay_addr);
        let received = gateway_rx.decode_packet(&gateway_buffer[..length]).unwrap();
        assert_eq!(received, original);

        // The gateway replies to the observed relay source tuple, never to an
        // address supplied by the untrusted packet payload.
        let downlink = gateway_tx.encode_packet(&received).unwrap();
        gateway.send_to(&downlink, relay_source).await.unwrap();

        let mut client_buffer = vec![0u8; 2048];
        let (length, source) = timeout(
            Duration::from_secs(2),
            client.recv_from(&mut client_buffer),
        )
        .await
        .expect("client did not receive relayed downlink")
        .unwrap();
        assert_eq!(source, relay_addr);
        let returned = client_rx.decode_packet(&client_buffer[..length]).unwrap();
        assert_eq!(returned, original);

        relay_task.await.unwrap();
    }
}
