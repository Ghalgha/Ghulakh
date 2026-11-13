//! Bidirectional protected IP datagram path over an established TURN ChannelBind.
//!
//! The dataplane owns only frame codecs and bounded application queues. TURN
//! allocation, peer permission, channel binding, credentials and key agreement
//! remain owned by their dedicated control/session layers.

use std::net::SocketAddr;

use anyhow::{Context, Result};
use ghulakh_protocol::ordered_datagram::SequencedDataDatagram;
use tokio::{
    sync::mpsc,
    time::{interval_at, Duration, Instant},
};

const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(15);
const KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(45);

fn keepalive_expired(last_ack: Instant, now: Instant) -> bool {
    now.saturating_duration_since(last_ack) >= KEEPALIVE_TIMEOUT
}

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
    pub keepalives_sent: u64,
    pub keepalive_acks_received: u64,
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
        Self {
            actor,
            inbound,
            relay_endpoint,
            sender,
            receiver,
        }
    }

    /// Pump packets until either application queue or the socket actor closes.
    /// Invalid/authentication-failed frames are dropped and counted, not fatal.
    pub async fn run(
        mut self,
        mut uplink: mpsc::Receiver<SequencedDataDatagram>,
        downlink: mpsc::Sender<SequencedDataDatagram>,
    ) -> Result<TurnDataPlaneStats> {
        let mut stats = TurnDataPlaneStats::default();
        let mut keepalive = interval_at(Instant::now() + KEEPALIVE_INTERVAL, KEEPALIVE_INTERVAL);
        let mut next_keepalive_nonce = 0u64;
        let mut last_acked_nonce: Option<u64> = None;
        let mut last_keepalive_ack = Instant::now();
        enum Event {
            Inbound(Option<TurnInbound>),
            Uplink(Option<SequencedDataDatagram>),
            Keepalive,
            KeepaliveTimeout,
        }
        loop {
            let event = tokio::select! {
                inbound = self.inbound.recv() => Event::Inbound(inbound),
                packet = uplink.recv() => Event::Uplink(packet),
                _ = keepalive.tick() => Event::Keepalive,
                _ = tokio::time::sleep_until(last_keepalive_ack + KEEPALIVE_TIMEOUT) => Event::KeepaliveTimeout,
            };
            match event {
                Event::Inbound(inbound) => {
                    let Some(TurnInbound::Data { datagram, source }) = inbound else {
                        return Ok(stats);
                    };
                    if source != self.relay_endpoint {
                        stats.rejected_sources = stats.rejected_sources.saturating_add(1);
                        continue;
                    }
                    match self.receiver.decode_payload(&datagram) {
                        Ok(crate::turn_data::TurnDataPayload::Packet(packet)) => {
                            if downlink.send(packet).await.is_err() {
                                return Ok(stats);
                            }
                            stats.received_frames = stats.received_frames.saturating_add(1);
                        }
                        Ok(crate::turn_data::TurnDataPayload::KeepaliveAck(nonce)) => {
                            if nonce < next_keepalive_nonce
                                && last_acked_nonce.is_none_or(|last| nonce > last)
                            {
                                last_acked_nonce = Some(nonce);
                                last_keepalive_ack = Instant::now();
                                stats.keepalive_acks_received =
                                    stats.keepalive_acks_received.saturating_add(1);
                            }
                        }
                        Err(_) => {
                            stats.rejected_frames = stats.rejected_frames.saturating_add(1);
                        }
                    }
                }
                Event::Uplink(packet) => {
                    let Some(packet) = packet else {
                        return Ok(stats);
                    };
                    let datagram = self
                        .sender
                        .encode_sequenced_packet(&packet)
                        .context("encode sequenced protected TURN uplink frame")?;
                    self.actor
                        .send_datagram(datagram)
                        .await
                        .context("send protected TURN uplink frame")?;
                    stats.sent_frames = stats.sent_frames.saturating_add(1);
                }
                Event::Keepalive => {
                    let nonce = next_keepalive_nonce;
                    next_keepalive_nonce = next_keepalive_nonce
                        .checked_add(1)
                        .context("TURN keepalive nonce space exhausted")?;
                    let datagram = self
                        .sender
                        .encode_keepalive(nonce)
                        .context("encode authenticated TURN path-health probe")?;
                    self.actor
                        .send_datagram(datagram)
                        .await
                        .context("send authenticated TURN path-health probe")?;
                    stats.keepalives_sent = stats.keepalives_sent.saturating_add(1);
                }
                Event::KeepaliveTimeout => {
                    if keepalive_expired(last_keepalive_ack, Instant::now()) {
                        anyhow::bail!("authenticated TURN path-health acknowledgements timed out");
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{turn_socket_actor::TurnSocketActor, turn_udp::TurnUdpSocket};
    use ghulakh_protocol::{
        secure_frame::{FrameDirection, FrameOpener, FrameSealer},
        turn_channel_data::decode_channel_data,
        DataDatagram, IpPacketKind,
    };
    use tokio::{
        net::UdpSocket,
        time::{timeout, Duration},
    };

    const CHANNEL: u16 = 0x4001;
    const SESSION: [u8; 8] = [0x31; 8];
    const CLIENT_KEY: [u8; 32] = [0x11; 32];
    const SERVER_KEY: [u8; 32] = [0x22; 32];
    const CLIENT_PREFIX: [u8; 4] = [0x41; 4];
    const SERVER_PREFIX: [u8; 4] = [0x52; 4];

    #[test]
    fn path_is_marked_failed_only_after_keepalive_ack_deadline() {
        let sent = Instant::now();
        assert!(!keepalive_expired(
            sent,
            sent + KEEPALIVE_TIMEOUT - Duration::from_secs(1)
        ));
        assert!(keepalive_expired(sent, sent + KEEPALIVE_TIMEOUT));
    }

    fn packet() -> DataDatagram {
        let mut bytes = vec![0u8; 20];
        bytes[0] = 0x45;
        bytes[2..4].copy_from_slice(&20u16.to_be_bytes());
        bytes[8] = 64;
        bytes[9] = 17;
        bytes[12..16].copy_from_slice(&[10, 77, 0, 2]);
        bytes[16..20].copy_from_slice(&[10, 77, 0, 3]);
        DataDatagram {
            kind: IpPacketKind::Ipv4,
            packet: bytes,
        }
    }

    #[tokio::test]
    async fn sends_and_receives_authenticated_packets_through_actor() {
        let relay = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let relay_addr = relay.local_addr().unwrap();
        let socket = TurnUdpSocket::bind("127.0.0.1:0".parse().unwrap(), relay_addr)
            .await
            .unwrap();
        let (actor, receivers) = TurnSocketActor::spawn(socket);
        let (uplink_tx, uplink_rx) = mpsc::channel::<SequencedDataDatagram>(4);
        let (downlink_tx, mut downlink_rx) = mpsc::channel(4);

        let plane = TurnDataPlane::new(
            actor.clone(),
            receivers.data,
            relay_addr,
            TurnDataSender::new(
                CHANNEL,
                FrameSealer::new(
                    CLIENT_KEY,
                    CLIENT_PREFIX,
                    SESSION,
                    FrameDirection::ClientToServer,
                ),
            ),
            TurnDataReceiver::new(
                CHANNEL,
                FrameOpener::new(
                    SERVER_KEY,
                    SERVER_PREFIX,
                    SESSION,
                    FrameDirection::ServerToClient,
                ),
            ),
        );

        let relay_task = tokio::spawn(async move {
            let mut buffer = [0u8; 2048];
            let (length, client_addr) =
                timeout(Duration::from_secs(2), relay.recv_from(&mut buffer))
                    .await
                    .unwrap()
                    .unwrap();
            let channel = decode_channel_data(&buffer[..length]).unwrap();
            assert_eq!(channel.channel_number, CHANNEL);
            let mut gateway_rx = TurnDataReceiver::new(
                CHANNEL,
                FrameOpener::new(
                    CLIENT_KEY,
                    CLIENT_PREFIX,
                    SESSION,
                    FrameDirection::ClientToServer,
                ),
            );
            let uplink_payload = gateway_rx.decode_payload(&buffer[..length]).unwrap();
            let uplink_packet = match uplink_payload {
                crate::turn_data::TurnDataPayload::Packet(packet) => {
                    assert_eq!(packet.sequence, Some(0));
                    packet.datagram
                }
                crate::turn_data::TurnDataPayload::KeepaliveAck(_) => {
                    panic!("unexpected keepalive acknowledgement")
                }
            };
            assert_eq!(uplink_packet, packet());

            let mut gateway_tx = TurnDataSender::new(
                CHANNEL,
                FrameSealer::new(
                    SERVER_KEY,
                    SERVER_PREFIX,
                    SESSION,
                    FrameDirection::ServerToClient,
                ),
            );
            let response = gateway_tx.encode_packet(&uplink_packet).unwrap();
            relay.send_to(&response, client_addr).await.unwrap();
        });

        let plane_task = tokio::spawn(plane.run(uplink_rx, downlink_tx));
        uplink_tx
            .send(SequencedDataDatagram::new(0, packet()))
            .await
            .unwrap();
        let returned = timeout(Duration::from_secs(2), downlink_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(returned.datagram, packet());
        drop(uplink_tx);
        let stats = plane_task.await.unwrap().unwrap();
        assert_eq!(stats.sent_frames, 1);
        assert_eq!(stats.received_frames, 1);
        assert_eq!(stats.rejected_frames, 0);
        relay_task.await.unwrap();
        drop(receivers.control);
    }
}

#[cfg(test)]
mod keepalive_fault_injection_tests {
    use super::*;

    const CHANNEL: u16 = 0x4001;
    const SESSION: [u8; 8] = [0x31; 8];
    const CLIENT_KEY: [u8; 32] = [0x11; 32];
    const SERVER_KEY: [u8; 32] = [0x22; 32];
    const CLIENT_PREFIX: [u8; 4] = [0x41; 4];
    const SERVER_PREFIX: [u8; 4] = [0x52; 4];
    use crate::{turn_socket_actor::TurnSocketActor, turn_udp::TurnUdpSocket};
    use ghulakh_protocol::{
        secure_frame::{keepalive_request, FrameDirection, FrameOpener, FrameSealer},
        turn_channel_data::decode_channel_data,
    };
    use tokio::{
        net::UdpSocket,
        sync::mpsc,
        time::{advance, Duration},
    };

    #[tokio::test(start_paused = true)]
    async fn missing_authenticated_keepalive_ack_marks_path_failed_at_deadline() {
        let relay = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let relay_addr = relay.local_addr().unwrap();
        let socket = TurnUdpSocket::bind("127.0.0.1:0".parse().unwrap(), relay_addr)
            .await
            .unwrap();
        let (actor, receivers) = TurnSocketActor::spawn(socket);
        let (uplink_tx, uplink_rx) = mpsc::channel::<SequencedDataDatagram>(1);
        let (downlink_tx, _downlink_rx) = mpsc::channel(1);
        let (observed_tx, mut observed_rx) = mpsc::channel::<Vec<u8>>(4);

        let relay_task = tokio::spawn(async move {
            let mut buffer = [0u8; 2048];
            loop {
                let (length, _) = relay.recv_from(&mut buffer).await.unwrap();
                let frame = decode_channel_data(&buffer[..length]).unwrap();
                observed_tx.send(frame.data.to_vec()).await.unwrap();
            }
        });

        let plane = TurnDataPlane::new(
            actor,
            receivers.data,
            relay_addr,
            TurnDataSender::new(
                CHANNEL,
                FrameSealer::new(
                    CLIENT_KEY,
                    CLIENT_PREFIX,
                    SESSION,
                    FrameDirection::ClientToServer,
                ),
            ),
            TurnDataReceiver::new(
                CHANNEL,
                FrameOpener::new(
                    SERVER_KEY,
                    SERVER_PREFIX,
                    SESSION,
                    FrameDirection::ServerToClient,
                ),
            ),
        );
        let plane_task = tokio::spawn(plane.run(uplink_rx, downlink_tx));

        let mut gateway_opener = FrameOpener::new(
            CLIENT_KEY,
            CLIENT_PREFIX,
            SESSION,
            FrameDirection::ClientToServer,
        );
        advance(KEEPALIVE_INTERVAL).await;
        let first = observed_rx.recv().await.unwrap();
        assert_eq!(
            gateway_opener.open(&first).unwrap(),
            keepalive_request(0).as_slice(),
        );

        advance(KEEPALIVE_INTERVAL).await;
        let second = observed_rx.recv().await.unwrap();
        assert_eq!(
            gateway_opener.open(&second).unwrap(),
            keepalive_request(1).as_slice(),
        );

        advance(KEEPALIVE_TIMEOUT - KEEPALIVE_INTERVAL * 2 - Duration::from_secs(1)).await;
        tokio::task::yield_now().await;
        assert!(
            !plane_task.is_finished(),
            "path failed before the acknowledgement deadline"
        );

        advance(Duration::from_secs(1)).await;
        let error = plane_task.await.unwrap().unwrap_err();
        assert!(
            error.to_string().contains("acknowledgements timed out"),
            "unexpected dataplane error: {error:#}",
        );

        relay_task.abort();
        drop(uplink_tx);
    }
}
