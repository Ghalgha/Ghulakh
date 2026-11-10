//! Bidirectional protected IP datagram path over an established TURN ChannelBind.
//!
//! The dataplane owns only frame codecs and bounded application queues. TURN
//! allocation, peer permission, channel binding, credentials and key agreement
//! remain owned by their dedicated control/session layers.

use std::net::SocketAddr;

use anyhow::{Context, Result};
use ghulakh_protocol::DataDatagram;
use tokio::sync::mpsc;

use crate::{
    turn_data::{TurnDataReceiver, TurnDataSender},
    turn_socket_actor::{TurnInbound, TurnSocketHandle},
};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TurnDataPlaneStats {
    pub received_frames: u64,
    pub sent_frames: u64,
    pub rejected_frames: u64,
    pub rejected_sources: u64,
}

/// Runs the client-side IP packet pump for one authenticated TURN channel.
///
/// `uplink` receives complete packets read from Android TUN. `downlink`
/// delivers authenticated packets to the TUN writer. Both queues are supplied
/// by the owner and should be bounded. The actor's data queue is independently
/// bounded and drops newest frames under overload.
pub struct TurnDataPlane {
    actor: TurnSocketHandle,
    inbound: mpsc::Receiver<TurnInbound>,
    relay_endpoint: SocketAddr,
    sender: TurnDataSender,
    receiver: TurnDataReceiver,
}

impl TurnDataPlane {
    pub fn new(
        actor: TurnSocketHandle,
        inbound: mpsc::Receiver<TurnInbound>,
        relay_endpoint: SocketAddr,
        sender: TurnDataSender,
        receiver: TurnDataReceiver,
    ) -> Self {
        Self { actor, inbound, relay_endpoint, sender, receiver }
    }

    /// Pump packets until either application queue or the socket actor closes.
    /// Invalid/authentication-failed frames are dropped and counted, not fatal.
    pub async fn run(
        mut self,
        mut uplink: mpsc::Receiver<DataDatagram>,
        downlink: mpsc::Sender<DataDatagram>,
    ) -> Result<TurnDataPlaneStats> {
        let mut stats = TurnDataPlaneStats::default();
        loop {
            tokio::select! {
                inbound = self.inbound.recv() => {
                    let Some(TurnInbound::Data { datagram, source }) = inbound else {
                        return Ok(stats);
                    };
                    if source != self.relay_endpoint {
                        stats.rejected_sources = stats.rejected_sources.saturating_add(1);
                        continue;
                    }
                    match self.receiver.decode_packet(&datagram) {
                        Ok(packet) => {
                            if downlink.send(packet).await.is_err() {
                                return Ok(stats);
                            }
                            stats.received_frames = stats.received_frames.saturating_add(1);
                        }
                        Err(_) => {
                            stats.rejected_frames = stats.rejected_frames.saturating_add(1);
                        }
                    }
                }
                packet = uplink.recv() => {
                    let Some(packet) = packet else {
                        return Ok(stats);
                    };
                    let datagram = self.sender.encode_packet(&packet)
                        .context("encode protected TURN uplink frame")?;
                    self.actor.send_datagram(datagram).await
                        .context("send protected TURN uplink frame")?;
                    stats.sent_frames = stats.sent_frames.saturating_add(1);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ghulakh_protocol::{
        secure_frame::{FrameDirection, FrameOpener, FrameSealer},
        turn_channel_data::decode_channel_data,
        IpPacketKind,
    };
    use crate::{turn_socket_actor::TurnSocketActor, turn_udp::TurnUdpSocket};
    use tokio::{net::UdpSocket, time::{timeout, Duration}};

    const CHANNEL: u16 = 0x4001;
    const SESSION: [u8; 8] = [0x31; 8];
    const CLIENT_KEY: [u8; 32] = [0x11; 32];
    const SERVER_KEY: [u8; 32] = [0x22; 32];
    const CLIENT_PREFIX: [u8; 4] = [0x41; 4];
    const SERVER_PREFIX: [u8; 4] = [0x52; 4];

    fn packet() -> DataDatagram {
        let mut bytes = vec![0u8; 20];
        bytes[0] = 0x45;
        bytes[2..4].copy_from_slice(&20u16.to_be_bytes());
        bytes[8] = 64;
        bytes[9] = 17;
        bytes[12..16].copy_from_slice(&[10, 77, 0, 2]);
        bytes[16..20].copy_from_slice(&[10, 77, 0, 3]);
        DataDatagram { kind: IpPacketKind::Ipv4, packet: bytes }
    }

    #[tokio::test]
    async fn sends_and_receives_authenticated_packets_through_actor() {
        let relay = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let relay_addr = relay.local_addr().unwrap();
        let socket = TurnUdpSocket::bind("127.0.0.1:0".parse().unwrap(), relay_addr)
            .await.unwrap();
        let (actor, mut receivers) = TurnSocketActor::spawn(socket);
        let (uplink_tx, uplink_rx) = mpsc::channel(4);
        let (downlink_tx, mut downlink_rx) = mpsc::channel(4);

        let plane = TurnDataPlane::new(
            actor.clone(),
            receivers.data,
            relay_addr,
            TurnDataSender::new(
                CHANNEL,
                FrameSealer::new(CLIENT_KEY, CLIENT_PREFIX, SESSION, FrameDirection::ClientToServer),
            ),
            TurnDataReceiver::new(
                CHANNEL,
                FrameOpener::new(SERVER_KEY, SERVER_PREFIX, SESSION, FrameDirection::ServerToClient),
            ),
        );

        let relay_task = tokio::spawn(async move {
            let mut buffer = [0u8; 2048];
            let (length, client_addr) = timeout(Duration::from_secs(2), relay.recv_from(&mut buffer))
                .await.unwrap().unwrap();
            let channel = decode_channel_data(&buffer[..length]).unwrap();
            assert_eq!(channel.channel_number, CHANNEL);
            let mut gateway_rx = TurnDataReceiver::new(
                CHANNEL,
                FrameOpener::new(CLIENT_KEY, CLIENT_PREFIX, SESSION, FrameDirection::ClientToServer),
            );
            let uplink_packet = gateway_rx.decode_packet(&buffer[..length]).unwrap();
            assert_eq!(uplink_packet, packet());

            let mut gateway_tx = TurnDataSender::new(
                CHANNEL,
                FrameSealer::new(SERVER_KEY, SERVER_PREFIX, SESSION, FrameDirection::ServerToClient),
            );
            let response = gateway_tx.encode_packet(&uplink_packet).unwrap();
            relay.send_to(&response, client_addr).await.unwrap();
        });

        let plane_task = tokio::spawn(plane.run(uplink_rx, downlink_tx));
        uplink_tx.send(packet()).await.unwrap();
        let returned = timeout(Duration::from_secs(2), downlink_rx.recv())
            .await.unwrap().unwrap();
        assert_eq!(returned, packet());
        drop(uplink_tx);
        let stats = plane_task.await.unwrap().unwrap();
        assert_eq!(stats.sent_frames, 1);
        assert_eq!(stats.received_frames, 1);
        assert_eq!(stats.rejected_frames, 0);
        relay_task.await.unwrap();
        drop(receivers.control);
    }


}
