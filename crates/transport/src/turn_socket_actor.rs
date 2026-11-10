//! Single-reader UDP actor for one TURN relay socket.
//!
//! The actor is the only task that reads the socket. It separates STUN control
//! traffic from ChannelData and TURN Data indications, uses bounded queues,
//! and applies an explicit drop-newest policy to data when its consumer is slow.
//! STUN control delivery applies backpressure rather than silently dropping a
//! response. Transaction matching and MESSAGE-INTEGRITY verification remain
//! the responsibility of the control-plane owner.

use std::{
    net::SocketAddr,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};

use anyhow::{Context, Result};
use ghulakh_protocol::{
    stun::{StunClass, StunMessage, METHOD_DATA},
    turn_channel_data::decode_channel_data,
};
use tokio::{
    net::UdpSocket,
    sync::{mpsc, oneshot},
};

use crate::turn_udp::{TurnUdpSocket, MAX_UDP_DATAGRAM_SIZE};

const COMMAND_CAPACITY: usize = 32;
const CONTROL_CAPACITY: usize = 32;
const DATA_CAPACITY: usize = 128;

#[derive(Debug)]
pub enum TurnInbound {
    /// A decoded STUN message and its actual UDP source endpoint.
    Control { message: StunMessage, source: SocketAddr },
    /// A complete ChannelData or Data-indication datagram from the relay.
    Data { datagram: Vec<u8>, source: SocketAddr },
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TurnSocketActorStats {
    pub malformed_datagrams: u64,
    pub dropped_data_datagrams: u64,
}

#[derive(Default)]
struct Counters {
    malformed_datagrams: AtomicU64,
    dropped_data_datagrams: AtomicU64,
}

enum Command {
    Send {
        datagram: Vec<u8>,
        response: oneshot::Sender<Result<usize, String>>,
    },
}

/// Cloneable bounded command handle. All writes are serialized by the socket actor.
#[derive(Clone)]
pub struct TurnSocketHandle {
    commands: mpsc::Sender<Command>,
    counters: Arc<Counters>,
}

impl TurnSocketHandle {
    pub async fn send_datagram(&self, datagram: Vec<u8>) -> Result<usize> {
        anyhow::ensure!(
            datagram.len() <= MAX_UDP_DATAGRAM_SIZE,
            "TURN UDP datagram exceeds maximum size"
        );
        let (response, result) = oneshot::channel();
        self.commands
            .send(Command::Send { datagram, response })
            .await
            .context("TURN socket actor command queue closed")?;
        result
            .await
            .context("TURN socket actor dropped send result")?
            .map_err(anyhow::Error::msg)
    }

    pub fn stats(&self) -> TurnSocketActorStats {
        TurnSocketActorStats {
            malformed_datagrams: self.counters.malformed_datagrams.load(Ordering::Relaxed),
            dropped_data_datagrams: self.counters.dropped_data_datagrams.load(Ordering::Relaxed),
        }
    }
}

pub struct TurnSocketActorReceivers {
    /// Bounded, lossless-under-backpressure control event stream.
    pub control: mpsc::Receiver<TurnInbound>,
    /// Bounded data stream; overload drops the newest data datagram.
    pub data: mpsc::Receiver<TurnInbound>,
}

pub struct TurnSocketActor;

impl TurnSocketActor {
    /// Start the sole reader/writer task for this TURN UDP socket.
    /// Must be called from an active Tokio runtime.
    pub fn spawn(socket: TurnUdpSocket) -> (TurnSocketHandle, TurnSocketActorReceivers) {
        let (command_tx, mut command_rx) = mpsc::channel(COMMAND_CAPACITY);
        let (control_tx, control_rx) = mpsc::channel(CONTROL_CAPACITY);
        let (data_tx, data_rx) = mpsc::channel(DATA_CAPACITY);
        let counters = Arc::new(Counters::default());
        let task_counters = Arc::clone(&counters);

        tokio::spawn(async move {
            let mut buffer = vec![0u8; MAX_UDP_DATAGRAM_SIZE];
            loop {
                tokio::select! {
                    command = command_rx.recv() => {
                        let Some(Command::Send { datagram, response }) = command else {
                            break;
                        };
                        let result = socket.send_datagram(&datagram).await
                            .map_err(|error| format!("{error:#}"));
                        let _ = response.send(result);
                    }
                    received = socket.receive_datagram(&mut buffer) => {
                        let (length, source) = match received {
                            Ok(received) => received,
                            Err(_) => break,
                        };
                        let packet = &buffer[..length];
                        if packet.first().is_some_and(|byte| byte & 0xC0 == 0x40) {
                            if decode_channel_data(packet).is_err() {
                                task_counters.malformed_datagrams.fetch_add(1, Ordering::Relaxed);
                                continue;
                            }
                            let event = TurnInbound::Data {
                                datagram: packet.to_vec(),
                                source,
                            };
                            if data_tx.try_send(event).is_err() {
                                task_counters.dropped_data_datagrams.fetch_add(1, Ordering::Relaxed);
                            }
                            continue;
                        }

                        match StunMessage::decode(packet) {
                            Ok(message) if message.class == StunClass::Indication
                                && message.method == METHOD_DATA => {
                                let event = TurnInbound::Data {
                                    datagram: packet.to_vec(),
                                    source,
                                };
                                if data_tx.try_send(event).is_err() {
                                    task_counters.dropped_data_datagrams.fetch_add(1, Ordering::Relaxed);
                                }
                            }
                            Ok(message) => {
                                // Control traffic is not silently dropped. If the consumer
                                // stalls, bounded backpressure eventually reaches the UDP socket.
                                if control_tx.send(TurnInbound::Control { message, source }).await.is_err() {
                                    break;
                                }
                            }
                            Err(_) => {
                                task_counters.malformed_datagrams.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                    }
                }
            }
        });

        (
            TurnSocketHandle {
                commands: command_tx,
                counters,
            },
            TurnSocketActorReceivers {
                control: control_rx,
                data: data_rx,
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ghulakh_protocol::stun::{StunAttribute, ATTR_DATA, METHOD_ALLOCATE};
    use tokio::{net::UdpSocket, time::{timeout, Duration}};

    async fn pair() -> (TurnSocketHandle, TurnSocketActorReceivers, UdpSocket, SocketAddr) {
        let relay = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let relay_addr = relay.local_addr().unwrap();
        let socket = TurnUdpSocket::bind("127.0.0.1:0".parse().unwrap(), relay_addr)
            .await.unwrap();
        let (handle, receivers) = TurnSocketActor::spawn(socket);
        (handle, receivers, relay, relay_addr)
    }

    #[tokio::test]
    async fn one_reader_routes_control_and_channel_data_concurrently() {
        let (handle, mut receivers, relay, relay_addr) = pair().await;
        let client_addr = handle.clone();
        let relay_task = tokio::spawn(async move {
            let mut buffer = [0u8; 256];
            let (_, source) = relay.recv_from(&mut buffer).await.unwrap();
            let control = StunMessage {
                method: METHOD_ALLOCATE,
                class: StunClass::SuccessResponse,
                transaction_id: [8; 12],
                attributes: vec![],
            }.encode().unwrap();
            relay.send_to(&control, source).await.unwrap();
            relay.send_to(&[0x40, 0x01, 0, 3, 1, 2, 3], source).await.unwrap();
        });
        client_addr.send_datagram(vec![1]).await.unwrap();

        let control = timeout(Duration::from_secs(2), receivers.control.recv())
            .await.unwrap().unwrap();
        assert!(matches!(control, TurnInbound::Control { message, source }
            if message.transaction_id == [8; 12] && source == relay_addr));
        let data = timeout(Duration::from_secs(2), receivers.data.recv())
            .await.unwrap().unwrap();
        assert!(matches!(data, TurnInbound::Data { datagram, source }
            if datagram == [0x40, 0x01, 0, 3, 1, 2, 3] && source == relay_addr));
        relay_task.await.unwrap();
    }

    #[tokio::test]
    async fn routes_turn_data_indication_to_data_queue() {
        let (handle, mut receivers, relay, _) = pair().await;
        let relay_task = tokio::spawn(async move {
            let mut buffer = [0u8; 64];
            let (_, source) = relay.recv_from(&mut buffer).await.unwrap();
            let indication = StunMessage {
                method: METHOD_DATA,
                class: StunClass::Indication,
                transaction_id: [4; 12],
                attributes: vec![StunAttribute { kind: ATTR_DATA, value: b"payload".to_vec() }],
            }.encode().unwrap();
            relay.send_to(&indication, source).await.unwrap();
        });
        handle.send_datagram(vec![1]).await.unwrap();
        let event = timeout(Duration::from_secs(2), receivers.data.recv())
            .await.unwrap().unwrap();
        assert!(matches!(event, TurnInbound::Data { .. }));
        assert!(receivers.control.try_recv().is_err());
        relay_task.await.unwrap();
    }

    #[tokio::test]
    async fn malformed_channel_data_is_counted_and_not_forwarded() {
        let (handle, mut receivers, relay, _) = pair().await;
        let relay_task = tokio::spawn(async move {
            let mut buffer = [0u8; 64];
            let (_, source) = relay.recv_from(&mut buffer).await.unwrap();
            relay.send_to(&[0x40, 0x01, 0, 9, 1], source).await.unwrap();
        });
        handle.send_datagram(vec![1]).await.unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(receivers.data.try_recv().is_err());
        assert_eq!(handle.stats().malformed_datagrams, 1);
        relay_task.await.unwrap();
    }
}
