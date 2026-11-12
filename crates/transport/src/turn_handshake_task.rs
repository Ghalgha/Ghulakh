//! Client handshake task tying TURN socket actor, retry delivery and Noise XX.
//!
//! A single task owns Noise state and retry state. The actor remains the sole
//! UDP reader/writer. Incoming messages are accepted only from the configured
//! TURN server endpoint; the retry transaction is completed only after Noise
//! accepts the corresponding phase.

use std::{
    net::SocketAddr,
    time::{Duration, Instant},
};

use anyhow::{bail, Context, Result};
use ghulakh_protocol::{
    handshake_datagram::{
        HandshakeDatagramDriver, HandshakeDriverEvent, HandshakePhase, HandshakeRetryPolicy,
    },
    session_handshake::{SessionFrameKeys, TurnSessionConfig},
    turn_handshake::TurnHandshakeClient,
    turn_path_context::TurnPathContext,
};
use rand::{rngs::OsRng, RngCore};
use tokio::{sync::mpsc, time::MissedTickBehavior};

use crate::turn_socket_actor::{TurnInbound, TurnSocketHandle};

const RETRY_POLL_INTERVAL: Duration = Duration::from_millis(25);
const MAX_HANDSHAKE_DURATION: Duration = Duration::from_secs(30);

/// Client-side authenticated parameters and directional frame keys.
pub struct TurnClientSession {
    pub frame_keys: SessionFrameKeys,
    pub config: TurnSessionConfig,
}

/// Run the complete client Noise XX exchange over an already allocated and
/// ChannelBound TURN peer. The caller must protect the UDP socket before
/// constructing the actor and must keep the allocation alive for this task.
///
/// This function returns frame keys only after verifying the encrypted
/// ServerAck. It does not register a VPN session or install a TUN dataplane.
pub async fn run_turn_client_handshake(
    socket: TurnSocketHandle,
    inbound: mpsc::Receiver<TurnInbound>,
    relay_endpoint: SocketAddr,
    channel_number: u16,
    pinned_server_key: &[u8],
    credential: &[u8],
) -> Result<TurnClientSession> {
    run_turn_client_handshake_inner(
        socket, inbound, relay_endpoint, channel_number, pinned_server_key, credential, None,
    ).await
}

pub async fn run_turn_client_handshake_with_path_context(
    socket: TurnSocketHandle,
    inbound: mpsc::Receiver<TurnInbound>,
    relay_endpoint: SocketAddr,
    channel_number: u16,
    pinned_server_key: &[u8],
    credential: &[u8],
    path_context: TurnPathContext,
) -> Result<TurnClientSession> {
    run_turn_client_handshake_inner(
        socket,
        inbound,
        relay_endpoint,
        channel_number,
        pinned_server_key,
        credential,
        Some(path_context),
    ).await
}

async fn run_turn_client_handshake_inner(
    socket: TurnSocketHandle,
    mut inbound: mpsc::Receiver<TurnInbound>,
    relay_endpoint: SocketAddr,
    channel_number: u16,
    pinned_server_key: &[u8],
    credential: &[u8],
    path_context: Option<TurnPathContext>,
) -> Result<TurnClientSession> {
    anyhow::ensure!(
        (0x4000..=0x7fff).contains(&channel_number),
        "TURN channel number is outside the valid range"
    );
    let mut handshake_id = [0u8; 16];
    OsRng.fill_bytes(&mut handshake_id);
    anyhow::ensure!(handshake_id.iter().any(|byte| *byte != 0), "invalid random handshake ID");

    let (mut noise, first_message) = match path_context {
        Some(context) => TurnHandshakeClient::new_with_path_context(
            pinned_server_key, credential, context, handshake_id,
        ),
        None => TurnHandshakeClient::new(pinned_server_key, credential, handshake_id),
    }.context("initialize client Noise handshake")?;

    let mut delivery = HandshakeDatagramDriver::new(
        1,
        1,
        8,
        2,
        Duration::from_secs(30),
        HandshakeRetryPolicy::default(),
    ).context("initialize handshake retry manager")?;

    let started = Instant::now();
    let mut expected_response = HandshakePhase::ServerResponse;
    let mut pending_message = first_message;
    register_and_send(
        &socket,
        &mut delivery,
        pending_message,
        relay_endpoint,
        channel_number,
        expected_response,
    ).await?;

    let mut retry_tick = tokio::time::interval(RETRY_POLL_INTERVAL);
    retry_tick.set_missed_tick_behavior(MissedTickBehavior::Skip);
    retry_tick.tick().await;

    loop {
        if started.elapsed() >= MAX_HANDSHAKE_DURATION {
            bail!("TURN Noise handshake exceeded its overall deadline");
        }

        tokio::select! {
            inbound_event = inbound.recv() => {
                let Some(TurnInbound::Handshake { datagram, source }) = inbound_event else {
                    bail!("TURN handshake event queue closed");
                };
                if source != relay_endpoint {
                    continue;
                }
                if !delivery.match_response(&datagram, source)
                    .context("match TURN handshake response")?
                {
                    continue;
                }

                let response = ghulakh_protocol::handshake_datagram::HandshakeEnvelope::decode(&datagram)
                    .context("decode TURN handshake response")?;
                anyhow::ensure!(
                    response.phase == expected_response,
                    "TURN handshake response phase changed unexpectedly"
                );

                match expected_response {
                    HandshakePhase::ServerResponse => {
                        let next = noise.receive_server_response(&datagram)
                            .context("authenticate Noise server response")?;
                        anyhow::ensure!(
                            delivery.complete_response(&handshake_id, HandshakePhase::ServerResponse, source),
                            "could not complete authenticated ServerResponse transaction"
                        );
                        expected_response = HandshakePhase::ServerAck;
                        pending_message = next;
                        register_and_send(
                            &socket,
                            &mut delivery,
                            pending_message,
                            relay_endpoint,
                            channel_number,
                            expected_response,
                        ).await?;
                    }
                    HandshakePhase::ServerAck => {
                        let (keys, config_payload) = noise.receive_server_ack_with_payload(&datagram)
                            .context("verify encrypted Noise server acknowledgement")?;
                        let config = TurnSessionConfig::decode(&config_payload)
                            .context("decode authenticated server tunnel configuration")?;
                        anyhow::ensure!(
                            delivery.complete_response(&handshake_id, HandshakePhase::ServerAck, source),
                            "could not complete authenticated ServerAck transaction"
                        );
                        return Ok(TurnClientSession {
                            frame_keys: keys,
                            config,
                        });
                    }
                    _ => bail!("unexpected response phase in client handshake task"),
                }
            }
            _ = retry_tick.tick() => {
                for event in delivery.poll(Instant::now()) {
                    match event {
                        HandshakeDriverEvent::Retransmit {
                            datagram,
                            destination,
                            ..
                        } => {
                            anyhow::ensure!(destination == relay_endpoint, "handshake retry destination changed");
                            socket.send_handshake(channel_number, &datagram)
                                .await
                                .context("retransmit TURN handshake envelope")?;
                        }
                        HandshakeDriverEvent::TimedOut { .. } => {
                            bail!("TURN Noise handshake phase timed out");
                        }
                    }
                }
            }
        }
    }
}

async fn register_and_send(
    socket: &TurnSocketHandle,
    delivery: &mut HandshakeDatagramDriver,
    datagram: Vec<u8>,
    relay_endpoint: SocketAddr,
    channel_number: u16,
    expected_response: HandshakePhase,
) -> Result<()> {
    delivery.register_request(
        datagram.clone(),
        relay_endpoint,
        expected_response,
        Instant::now(),
    ).context("register TURN handshake retry transaction")?;
    socket.send_handshake(channel_number, &datagram)
        .await
        .context("send TURN handshake envelope")?;
    Ok(())
}
