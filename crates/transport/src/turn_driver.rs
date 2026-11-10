//! Asynchronous TURN control driver for one VK Calls relay allocation.
//!
//! The driver owns the UDP adapter and serializes control transactions. It does
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
        allocate_request, channel_bind_request, create_permission_request,
        parse_success_response, refresh_request,
    },
    turn_transaction::{TransactionEvent, TransactionManager, TransactionPolicy},
};
use crate::{turn_auth::TurnAuthContext, turn_udp::TurnUdpSocket};

const POLL_INTERVAL: Duration = Duration::from_millis(25);
const RECEIVE_BUFFER_SIZE: usize = 65_507;
const DEFAULT_REFRESH_LIFETIME: u32 = 600;

#[derive(Debug, thiserror::Error)]
pub enum TurnDriverError {
    #[error("TURN transaction timed out")]
    Timeout,
    #[error("TURN server returned an authentication challenge")]
    Challenge(ghulakh_protocol::turn_auth::TurnChallenge),
    #[error("TURN server returned an error response (code {code})")]
    ServerError { code: u16 },
    #[error("TURN response was not authenticated")]
    MissingAuthentication,
    #[error("TURN response source or transaction did not match")]
    UnmatchedResponse,
    #[error("TURN operation requires an active allocation")]
    NoAllocation,
    #[error("TURN operation failed: {0}")]
    Operation(String),
}

pub struct TurnClientDriver {
    socket: TurnUdpSocket,
    transactions: TransactionManager,
    allocations: AllocationManager,
    peers: Option<TurnPeerRegistry>,
    transaction_policy: TransactionPolicy,
}

impl TurnClientDriver {
    pub fn new(socket: TurnUdpSocket) -> Self {
        Self {
            socket,
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
        self.socket.server_addr()
    }

    pub fn allocation(&self) -> Option<&AllocationLease> {
        self.allocations.lease()
    }

    pub fn peer_registry(&self) -> Option<&TurnPeerRegistry> {
        self.peers.as_ref()
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
        let request = allocate_request(id);
        let response = self.transact(request, auth).await?;
        let success = parse_success_response(&response, response.method)
            .context("parse TURN Allocate success")?;
        let now = Instant::now();
        self.allocations.begin_allocate(id)
            .map_err(|e| anyhow::anyhow!("begin allocation state: {e}"))?;
        let lease = self.allocations.accept_allocate(id, success, now)
            .map_err(|e| anyhow::anyhow!("accept allocation: {e}"))?
            .clone();
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
        let success = parse_success_response(&response, response.method)
            .context("parse TURN Refresh success")?;
        let lease = self.allocations.accept_refresh(id, success, Instant::now())
            .map_err(|e| anyhow::anyhow!("accept TURN refresh: {e}"))?
            .cloned();
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
        let destination = self.socket.server_addr();
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
        self.socket.send_datagram(&wire).await.context("send TURN request")?;

        let mut buffer = vec![0u8; RECEIVE_BUFFER_SIZE];
        loop {
            tokio::select! {
                received = self.socket.receive_datagram(&mut buffer) => {
                    let (length, source) = received.context("receive TURN response")?;
                    if source != destination {
                        continue;
                    }
                    let response = match StunMessage::decode(&buffer[..length]) {
                        Ok(response) => response,
                        Err(_) => continue,
                    };
                    let Some(matched) = self.transactions.accept_response(response, source) else {
                        continue;
                    };
                    let response = matched.response;
                    if response.class == StunClass::ErrorResponse {
                        let challenge = parse_turn_challenge(&response, request.method).ok();
                        if let Some(challenge) = challenge {
                            // A 438 stale-nonce response follows an authenticated
                            // request and must itself pass integrity verification.
                            if challenge.code == 438 {
                                if let Some(context) = auth {
                                    context.verify_response(&buffer[..length])
                                        .context("verify authenticated stale-nonce response")?;
                                } else {
                                    self.transactions.complete(&id);
                                    return Err(TurnDriverError::MissingAuthentication.into());
                                }
                            }
                            self.transactions.complete(&id);
                            return Err(TurnDriverError::Challenge(challenge).into());
                        }
                        if let Some(context) = auth {
                            context.verify_response(&buffer[..length])
                                .context("verify authenticated TURN error response")?;
                        }
                        let code = response.attributes.iter()
                            .find(|attribute| attribute.kind == ghulakh_protocol::stun::ATTR_ERROR_CODE)
                            .and_then(|attribute| (attribute.value.len() >= 4)
                                .then(|| u16::from(attribute.value[2] & 0x07) * 100 + u16::from(attribute.value[3])));
                        self.transactions.complete(&id);
                        return Err(TurnDriverError::ServerError { code: code.unwrap_or(0) }.into());
                    }
                    if let Some(context) = auth {
                        context.verify_response(&buffer[..length])
                            .context("verify TURN success response")?;
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
                                self.socket.send_datagram(&request).await
                                    .context("retransmit TURN request")?;
                                anyhow::ensure!(destination == self.socket.server_addr(), "TURN retry destination changed");
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
