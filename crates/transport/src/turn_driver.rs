//! Asynchronous TURN control driver for one VK Calls relay allocation.
//!
//! The driver owns a single-reader socket actor and serializes control transactions. It does
//! not derive TURN keys: callers supply an authenticated context after obtaining
//! and validating a 401 challenge. A challenge is returned as structured data so
//! the credential/profile layer can construct the next context without guessing.

use std::{
    net::SocketAddr,
    time::{Duration, Instant},
};

use anyhow::{Context, Result};
use ghulakh_protocol::{
    stun::{StunClass, StunMessage},
    turn_allocation::{AllocationLease, AllocationManager},
    turn_auth::parse_turn_challenge,
    turn_peer::TurnPeerRegistry,
    turn_request::{
        allocate_request_for_family, channel_bind_request, create_permission_request,
        parse_success_response, refresh_request,
    },
    turn_transaction::{TransactionEvent, TransactionManager, TransactionPolicy},
};
use crate::{
    turn_auth::TurnAuthContext,
    turn_socket_actor::{TurnInbound, TurnSocketActor, TurnSocketHandle},
    turn_udp::TurnUdpSocket,
};
use tokio::sync::mpsc;

const POLL_INTERVAL: Duration = Duration::from_millis(25);
const DEFAULT_REFRESH_LIFETIME: u32 = 600;

#[derive(Debug, thiserror::Error)]
pub enum TurnDriverError {
    #[error("TURN transaction timed out")]
    Timeout,
    #[error("TURN server returned an authentication challenge")]
    Challenge(ghulakh_protocol::turn_auth::TurnChallenge),
    #[error("TURN server returned an error response (code {code})")]
    ServerError { code: u16 },
    #[error("TURN rejected the active credentials (STUN error 401, 438, or 441)")]
    CredentialsRejected,
    #[error("TURN response was not authenticated")]
    MissingAuthentication,
    #[error("TURN response source or transaction did not match")]
    UnmatchedResponse,
    #[error("TURN operation requires an active allocation")]
    NoAllocation,
    #[error("TURN socket actor is no longer available")]
    SocketActorClosed,
    #[error("TURN operation failed: {0}")]
    Operation(String),
}

pub struct TurnClientDriver {
    socket: Option<TurnSocketHandle>,
    control_rx: mpsc::Receiver<TurnInbound>,
    data_rx: Option<mpsc::Receiver<TurnInbound>>,
    handshake_rx: Option<mpsc::Receiver<TurnInbound>>,
    relay_endpoint: SocketAddr,
    requested_relay_ipv4: bool,
    transactions: TransactionManager,
    allocations: AllocationManager,
    peers: Option<TurnPeerRegistry>,
    transaction_policy: TransactionPolicy,
}

impl TurnClientDriver {
    pub fn new(socket: TurnUdpSocket) -> Self {
        let relay_endpoint = socket.server_addr();
        let (actor, receivers) = TurnSocketActor::spawn(socket);
        Self {
            socket: Some(actor),
            control_rx: receivers.control,
            data_rx: Some(receivers.data),
            handshake_rx: Some(receivers.handshake),
            relay_endpoint,
            requested_relay_ipv4: relay_endpoint.is_ipv4(),
            transactions: TransactionManager::new(),
            allocations: AllocationManager::new(),
            peers: None,
            transaction_policy: TransactionPolicy::default(),
        }
    }

    pub fn with_transaction_policy(mut self, policy: TransactionPolicy) -> Self {
        self.transaction_policy = policy;
        self
    }

    pub fn relay_endpoint(&self) -> SocketAddr {
        self.relay_endpoint
    }

    /// Select the relayed-address family to match the VPN gateway peer.
    /// TURN may use a different address family for its server-facing socket.
    pub fn with_requested_relay_family(mut self, ipv4: bool) -> Self {
        self.requested_relay_ipv4 = ipv4;
        self
    }

    /// Transfer the bounded data-event receiver to the dataplane consumer.
    /// It can run concurrently with serialized control operations.
    pub fn take_data_receiver(&mut self) -> Option<mpsc::Receiver<TurnInbound>> {
        self.data_rx.take()
    }

    /// Transfer the data receiver and a clone of the actor send handle to the
    /// dataplane. Control transactions retain their own actor handle.
    pub fn take_data_plane_parts(
        &mut self,
    ) -> Option<(TurnSocketHandle, mpsc::Receiver<TurnInbound>)> {
        Some((self.socket.as_ref()?.clone(), self.data_rx.take()?))
    }

    /// Transfer the isolated handshake event stream and actor sender. This
    /// shares the same protected TURN socket without adding a second reader.
    pub fn take_handshake_plane_parts(
        &mut self,
    ) -> Option<(TurnSocketHandle, mpsc::Receiver<TurnInbound>)> {
        Some((self.socket.as_ref()?.clone(), self.handshake_rx.take()?))
    }

    pub fn allocation(&self) -> Option<&AllocationLease> {
        self.allocations.lease()
    }

    pub fn peer_registry(&self) -> Option<&TurnPeerRegistry> {
        self.peers.as_ref()
    }

    /// Expire local permission and channel state using the caller's monotonic clock.
    pub fn expire_peer_state(
        &mut self,
        now: Instant,
    ) -> Option<ghulakh_protocol::turn_peer::ExpiredPeerState> {
        self.peers.as_mut().map(|registry| registry.expire(now))
    }

    /// Perform an unauthenticated Allocate. A 401 challenge is returned to the
    /// caller; retry by calling allocate again with the newly built auth context.
    pub async fn allocate(
        &mut self,
        auth: Option<&TurnAuthContext>,
    ) -> Result<AllocationLease> {
        anyhow::ensure!(self.allocations.lease().is_none(), "TURN allocation already active");
        let id = TransactionManager::random_transaction_id()
            .map_err(|e| anyhow::anyhow!("generate TURN transaction ID: {e}"))?;
        self.allocations.begin_allocate(id)
            .map_err(|e| anyhow::anyhow!("begin allocation state: {e}"))?;
        let request = allocate_request_for_family(id, self.requested_relay_ipv4);
        let response = match self.transact(request, auth).await {
            Ok(response) => response,
            Err(error) => {
                let _ = self.allocations.abort_allocate(id);
                return Err(error);
            }
        };
        let success = match parse_success_response(&response, response.method) {
            Ok(success) => success,
            Err(error) => {
                let _ = self.allocations.abort_allocate(id);
                return Err(error).context("parse TURN Allocate success");
            }
        };
        if let ghulakh_protocol::turn_request::TurnSuccess::Allocate { relayed_address, .. } = &success {
            if relayed_address.is_ipv4() != self.requested_relay_ipv4 {
                let _ = self.allocations.abort_allocate(id);
                anyhow::bail!("TURN Allocate returned a relayed address with the wrong IP family");
            }
        }
        let lease = match self.allocations.accept_allocate(id, success, Instant::now()) {
            Ok(lease) => lease.clone(),
            Err(error) => {
                let _ = self.allocations.abort_allocate(id);
                return Err(anyhow::anyhow!("accept allocation: {error}"));
            }
        };
        self.peers = Some(TurnPeerRegistry::new(lease.relayed_address.ip()));
        Ok(lease)
    }

    /// Install a TURN permission for one or more same-family peer addresses.
    pub async fn create_permission(
        &mut self,
        peers: &[SocketAddr],
        auth: &TurnAuthContext,
    ) -> Result<()> {
        self.require_live_allocation()?;
        let id = TransactionManager::random_transaction_id()
            .map_err(|e| anyhow::anyhow!("generate TURN transaction ID: {e}"))?;
        let request = create_permission_request(id, peers)
            .context("build TURN CreatePermission request")?;
        let response = self.transact(request, Some(auth)).await?;
        parse_success_response(&response, response.method)
            .context("parse TURN CreatePermission success")?;
        let now = Instant::now();
        let registry = self.peers.as_mut().ok_or(TurnDriverError::NoAllocation)?;
        for peer in peers {
            registry.install_permission(peer.ip(), now)
                .map_err(|e| anyhow::anyhow!("record TURN permission: {e}"))?;
        }
        Ok(())
    }

    /// Bind a peer to a caller-selected channel number in the RFC range.
    pub async fn channel_bind(
        &mut self,
        channel_number: u16,
        peer: SocketAddr,
        auth: &TurnAuthContext,
    ) -> Result<()> {
        self.require_live_allocation()?;
        let id = TransactionManager::random_transaction_id()
            .map_err(|e| anyhow::anyhow!("generate TURN transaction ID: {e}"))?;
        let request = channel_bind_request(id, channel_number, peer)
            .context("build TURN ChannelBind request")?;
        let response = self.transact(request, Some(auth)).await?;
        parse_success_response(&response, response.method)
            .context("parse TURN ChannelBind success")?;
        self.peers.as_mut().ok_or(TurnDriverError::NoAllocation)?
            .install_channel_binding(channel_number, peer, Instant::now())
            .map_err(|e| anyhow::anyhow!("record TURN channel binding: {e}"))?;
        Ok(())
    }

    /// Refresh the allocation before its advertised refresh deadline.
    pub async fn refresh(
        &mut self,
        lifetime_seconds: u32,
        auth: &TurnAuthContext,
    ) -> Result<Option<AllocationLease>> {
        self.require_live_allocation()?;
        let id = TransactionManager::random_transaction_id()
            .map_err(|e| anyhow::anyhow!("generate TURN transaction ID: {e}"))?;
        let now = Instant::now();
        self.allocations.begin_refresh(id, now)
            .map_err(|e| anyhow::anyhow!("begin TURN refresh: {e}"))?;
        let request = refresh_request(id, lifetime_seconds);
        let response = match self.transact(request, Some(auth)).await {
            Ok(response) => response,
            Err(error) => {
                let _ = self.allocations.refresh_failed(id);
                return Err(error);
            }
        };
        let success = match parse_success_response(&response, response.method) {
            Ok(success) => success,
            Err(error) => {
                let _ = self.allocations.refresh_failed(id);
                return Err(error).context("parse TURN Refresh success");
            }
        };
        let lease = match self.allocations.accept_refresh(id, success, Instant::now()) {
            Ok(lease) => lease.cloned(),
            Err(error) => {
                let _ = self.allocations.refresh_failed(id);
                return Err(anyhow::anyhow!("accept TURN refresh: {error}"));
            }
        };
        if lease.is_none() {
            self.peers = None;
        }
        Ok(lease)
    }

    /// Refresh with the conservative default lifetime used by this driver.
    pub async fn refresh_default(
        &mut self,
        auth: &TurnAuthContext,
    ) -> Result<Option<AllocationLease>> {
        self.refresh(DEFAULT_REFRESH_LIFETIME, auth).await
    }

    /// Retire local allocation state. The caller may send Refresh(0) first if
    /// orderly relay-side deletion is required.
    pub fn close(&mut self) {
        self.peers = None;
        self.allocations = AllocationManager::new();
        self.data_rx = None;
        self.handshake_rx = None;
        self.socket = None;
    }

    fn require_live_allocation(&self) -> Result<()> {
        let lease = self.allocations.lease().ok_or(TurnDriverError::NoAllocation)?;
        anyhow::ensure!(Instant::now() < lease.expires_at, "TURN allocation has expired");
        Ok(())
    }

    async fn transact(
        &mut self,
        request: StunMessage,
        auth: Option<&TurnAuthContext>,
    ) -> Result<StunMessage> {
        let destination = self.relay_endpoint;
        let actor = self.socket.as_ref().cloned().ok_or(TurnDriverError::SocketActorClosed)?;
        let wire = match auth {
            Some(context) => context.sign_request(&request).context("authenticate TURN request")?,
            None => request.encode().context("encode unauthenticated TURN request")?,
        };
        let id = self.transactions.register(
            wire.clone(),
            destination,
            Instant::now(),
            self.transaction_policy,
        ).map_err(|e| anyhow::anyhow!("register TURN transaction: {e}"))?;
        if let Err(error) = actor.send_datagram(wire).await {
            self.transactions.cancel(&id);
            return Err(error).context("send TURN request");
        }

        loop {
            tokio::select! {
                inbound = self.control_rx.recv() => {
                    let Some(TurnInbound::Control { message, wire, source }) = inbound else {
                        self.transactions.cancel(&id);
                        return Err(TurnDriverError::SocketActorClosed.into());
                    };
                    let Some(matched) = self.transactions.accept_response(message, source) else {
                        continue;
                    };
                    if matched.transaction_id != id {
                        continue;
                    }
                    let response = matched.response;
                    if response.class == StunClass::ErrorResponse {
                        let challenge = parse_turn_challenge(&response, request.method).ok();
                        if let Some(challenge) = challenge {
                            let should_verify = challenge.code == 438 || auth.is_some();
                            if should_verify {
                                if let Some(context) = auth {
                                    if context.verify_response(&wire).is_err() {
                                        // An unauthenticated datagram must not consume a
                                        // live transaction; keep waiting for a valid response
                                        // or let the normal retransmission deadline expire.
                                        continue;
                                    }
                                } else {
                                    self.transactions.complete(&id);
                                    return Err(TurnDriverError::MissingAuthentication.into());
                                }
                            }
                            if challenge.code == 401 && auth.is_some() {
                                self.transactions.complete(&id);
                                return Err(TurnDriverError::CredentialsRejected.into());
                            }
                            self.transactions.complete(&id);
                            return Err(TurnDriverError::Challenge(challenge).into());
                        }
                        if let Some(context) = auth {
                            if context.verify_response(&wire).is_err() {
                                continue;
                            }
                        }
                        let code = response.attributes.iter()
                            .find(|attribute| attribute.kind == ghulakh_protocol::stun::ATTR_ERROR_CODE)
                            .and_then(|attribute| (attribute.value.len() >= 4)
                                .then(|| u16::from(attribute.value[2] & 0x07) * 100 + u16::from(attribute.value[3])));
                        self.transactions.complete(&id);
                        if code == Some(441) && auth.is_some() {
                            return Err(TurnDriverError::CredentialsRejected.into());
                        }
                        return Err(TurnDriverError::ServerError { code: code.unwrap_or(0) }.into());
                    }
                    if let Some(context) = auth {
                        if context.verify_response(&wire).is_err() {
                            continue;
                        }
                    } else {
                        self.transactions.complete(&id);
                        return Err(TurnDriverError::MissingAuthentication.into());
                    }
                    self.transactions.complete(&id);
                    return Ok(response);
                }
                _ = tokio::time::sleep(POLL_INTERVAL) => {
                    for event in self.transactions.poll(Instant::now()) {
                        match event {
                            TransactionEvent::Retransmit { request, destination, .. } => {
                                if destination != self.relay_endpoint {
                                    self.transactions.cancel(&id);
                                    anyhow::bail!("TURN retry destination changed");
                                }
                                if let Err(error) = actor.send_datagram(request).await {
                                    self.transactions.cancel(&id);
                                    return Err(error).context("retransmit TURN request");
                                }
                            }
                            TransactionEvent::TimedOut { transaction_id, .. } if transaction_id == id => {
                                return Err(TurnDriverError::Timeout.into());
                            }
                            TransactionEvent::TimedOut { .. } => {}
                        }
                    }
                }
            }
        }
    }
}


#[cfg(test)]
mod socket_actor_integration_tests {
    use super::*;
    use ghulakh_protocol::stun::{
        StunAttribute, ATTR_ERROR_CODE, ATTR_NONCE, ATTR_REALM,
    };
    use tokio::{net::UdpSocket, time::{timeout, Duration}};

    #[tokio::test]
    async fn driver_receives_initial_challenge_through_single_socket_actor() {
        let relay = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let relay_addr = relay.local_addr().unwrap();
        let socket = TurnUdpSocket::bind("127.0.0.1:0".parse().unwrap(), relay_addr)
            .await.unwrap();
        let mut driver = TurnClientDriver::new(socket);
        assert!(driver.take_data_receiver().is_some());

        let relay_task = tokio::spawn(async move {
            let mut buffer = [0u8; 1024];
            let (length, source) = timeout(Duration::from_secs(2), relay.recv_from(&mut buffer))
                .await.unwrap().unwrap();
            let request = StunMessage::decode(&buffer[..length]).unwrap();
            let challenge = StunMessage {
                method: request.method,
                class: StunClass::ErrorResponse,
                transaction_id: request.transaction_id,
                attributes: vec![
                    StunAttribute { kind: ATTR_ERROR_CODE, value: vec![0, 0, 4, 1] },
                    StunAttribute { kind: ATTR_REALM, value: b"turn.example.invalid".to_vec() },
                    StunAttribute { kind: ATTR_NONCE, value: b"opaque-nonce".to_vec() },
                ],
            }.encode().unwrap();
            relay.send_to(&challenge, source).await.unwrap();
        });

        let error = driver.allocate(None).await.unwrap_err();
        let challenge = error.downcast_ref::<TurnDriverError>().unwrap();
        assert!(matches!(challenge, TurnDriverError::Challenge(value)
            if value.code == 401 && value.realm == "turn.example.invalid"));
        relay_task.await.unwrap();
        driver.close();
    }

    #[tokio::test]
    async fn invalid_authenticated_success_is_ignored_and_request_is_retransmitted() {
        use crate::turn_auth::TurnIntegrityAlgorithm;
        use ghulakh_protocol::stun::{
            append_message_integrity, encode_xor_address, StunAttribute,
            ATTR_LIFETIME, ATTR_XOR_RELAYED_ADDRESS,
        };

        let relay = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let relay_addr = relay.local_addr().unwrap();
        let socket = TurnUdpSocket::bind("127.0.0.1:0".parse().unwrap(), relay_addr)
            .await.unwrap();
        let policy = TransactionPolicy {
            initial_rto: Duration::from_millis(20),
            max_requests: 2,
            final_timeout_multiplier: 2,
        };
        let mut driver = TurnClientDriver::new(socket).with_transaction_policy(policy);
        let auth = TurnAuthContext::new(
            "test-user".into(),
            "turn.example.invalid".into(),
            "test-nonce".into(),
            vec![0x44; 32],
            TurnIntegrityAlgorithm::Sha1,
        ).unwrap();

        let relay_task = tokio::spawn(async move {
            let mut buffer = [0u8; 2048];
            let (first_len, client) = timeout(Duration::from_secs(2), relay.recv_from(&mut buffer))
                .await.unwrap().unwrap();
            let first_wire = buffer[..first_len].to_vec();
            let request = StunMessage::decode(&first_wire).unwrap();
            assert_eq!(request.method, METHOD_ALLOCATE);

            let relayed: SocketAddr = "198.51.100.30:50000".parse().unwrap();
            let response = StunMessage {
                method: METHOD_ALLOCATE,
                class: StunClass::SuccessResponse,
                transaction_id: request.transaction_id,
                attributes: vec![
                    StunAttribute {
                        kind: ATTR_XOR_RELAYED_ADDRESS,
                        value: encode_xor_address(relayed, &request.transaction_id),
                    },
                    StunAttribute { kind: ATTR_LIFETIME, value: 600u32.to_be_bytes().to_vec() },
                ],
            };

            // Correct transaction ID and source, but no MESSAGE-INTEGRITY.
            relay.send_to(&response.encode().unwrap(), client).await.unwrap();

            let (retry_len, retry_client) = timeout(Duration::from_secs(2), relay.recv_from(&mut buffer))
                .await.unwrap().unwrap();
            assert_eq!(retry_client, client);
            assert_eq!(
                &buffer[..retry_len],
                first_wire.as_slice(),
                "invalid integrity must not consume the transaction or alter retry bytes",
            );

            let authenticated = append_message_integrity(&response, &[0x44; 32]).unwrap();
            relay.send_to(&authenticated, client).await.unwrap();
            relayed
        });

        let lease = timeout(Duration::from_secs(2), driver.allocate(Some(&auth)))
            .await.unwrap().unwrap();
        assert_eq!(lease.relayed_address, relay_task.await.unwrap());
        assert!(driver.allocation().is_some());
        driver.close();
    }

    #[tokio::test]
    async fn lost_allocate_response_retransmits_identical_request_and_aborts_state() {
        let relay = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let relay_addr = relay.local_addr().unwrap();
        let socket = TurnUdpSocket::bind("127.0.0.1:0".parse().unwrap(), relay_addr)
            .await.unwrap();
        let policy = TransactionPolicy {
            initial_rto: Duration::from_millis(20),
            max_requests: 2,
            final_timeout_multiplier: 2,
        };
        let mut driver = TurnClientDriver::new(socket).with_transaction_policy(policy);

        let relay_task = tokio::spawn(async move {
            let mut buffer = [0u8; 1024];
            let (first_len, first_source) = timeout(Duration::from_secs(2), relay.recv_from(&mut buffer))
                .await.unwrap().unwrap();
            let first = buffer[..first_len].to_vec();
            let (second_len, second_source) = timeout(Duration::from_secs(2), relay.recv_from(&mut buffer))
                .await.unwrap().unwrap();
            let second = buffer[..second_len].to_vec();
            assert_eq!(first_source, second_source);
            assert_eq!(first, second, "retransmission must preserve exact request bytes");
        });

        let error = timeout(Duration::from_secs(2), driver.allocate(None))
            .await.unwrap().unwrap_err();
        assert!(matches!(error.downcast_ref::<TurnDriverError>(), Some(TurnDriverError::Timeout)));
        assert!(driver.allocation().is_none(), "failed Allocate must leave no active lease");
        assert_eq!(driver.transactions.len(), 0, "timed-out transaction must be removed");
        relay_task.await.unwrap();
        driver.close();
    }
}
