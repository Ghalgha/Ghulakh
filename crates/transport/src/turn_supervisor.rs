//! TURN allocation session supervisor.
//!
//! Credentials and password-key derivation remain outside the transport. The
//! provider is called only when TURN returns an initial or stale-nonce challenge.
//! This supervisor serializes allocation and refresh and bounds challenge retries.

use std::{collections::BTreeMap, future::Future, net::{IpAddr, SocketAddr}, pin::Pin, time::{Duration, Instant}};

use anyhow::{Context, Result};
use ghulakh_protocol::turn_auth::TurnChallenge;

use crate::{
    turn_auth::TurnAuthContext,
    turn_driver::{TurnClientDriver, TurnDriverError},
};

pub const MAX_CHALLENGE_RETRIES: usize = 3;

/// Supplies an auth context for a specific server challenge. Implementations
/// must validate the challenge/profile and derive the integrity key according
/// to an explicitly configured service profile; this crate does not guess it.
pub trait TurnAuthProvider: Send {
    fn context_for_challenge<'a>(
        &'a mut self,
        challenge: TurnChallenge,
    ) -> Pin<Box<dyn Future<Output = Result<TurnAuthContext>> + Send + 'a>>;
}

/// Owns one driver and its current auth context. All TURN control operations
/// must go through this object to avoid competing receive loops on one socket.
pub struct TurnSessionSupervisor<P> {
    driver: TurnClientDriver,
    provider: P,
    auth: Option<TurnAuthContext>,
    max_challenge_retries: usize,
    permission_peers: BTreeMap<IpAddr, SocketAddr>,
    channel_bindings: BTreeMap<u16, SocketAddr>,
}

impl<P: TurnAuthProvider> TurnSessionSupervisor<P> {
    pub fn new(driver: TurnClientDriver, provider: P) -> Self {
        Self {
            driver,
            provider,
            auth: None,
            max_challenge_retries: MAX_CHALLENGE_RETRIES,
            permission_peers: BTreeMap::new(),
            channel_bindings: BTreeMap::new(),
        }
    }

    /// Override the challenge retry budget. Zero disables automatic retries.
    pub fn with_max_challenge_retries(mut self, retries: usize) -> Self {
        self.max_challenge_retries = retries.min(MAX_CHALLENGE_RETRIES);
        self
    }

    pub fn relay_endpoint(&self) -> SocketAddr {
        self.driver.relay_endpoint()
    }

    pub fn allocation(&self) -> Option<&ghulakh_protocol::turn_allocation::AllocationLease> {
        self.driver.allocation()
    }

    pub fn auth_context_available(&self) -> bool {
        self.auth.is_some()
    }

    /// Allocate and automatically handle the initial 401 challenge.
    pub async fn allocate(&mut self) -> Result<ghulakh_protocol::turn_allocation::AllocationLease> {
        let mut auth_ready = false;
        for attempt in 0..=self.max_challenge_retries {
            match self.driver.allocate(if auth_ready { self.auth.as_ref() } else { None }).await {
                Ok(lease) => return Ok(lease),
                Err(error) => {
                    let Some(challenge) = challenge_from_error(&error) else {
                        return Err(error).context("TURN Allocate");
                    };
                    if attempt == self.max_challenge_retries {
                        return Err(error).context("TURN Allocate challenge retry limit reached");
                    }
                    let next = self.provider.context_for_challenge(challenge).await
                        .context("obtain TURN auth context for Allocate challenge")?;
                    self.auth = Some(next);
                    auth_ready = true;
                }
            }
        }
        anyhow::bail!("TURN Allocate retry loop exhausted")
    }

    /// Refresh the active allocation and recover from a verified 438 response.
    pub async fn refresh(&mut self, lifetime_seconds: u32) -> Result<Option<ghulakh_protocol::turn_allocation::AllocationLease>> {
        for attempt in 0..=self.max_challenge_retries {
            let auth = self.auth.as_ref().context("TURN auth context is not initialized")?;
            match self.driver.refresh(lifetime_seconds, auth).await {
                Ok(lease) => return Ok(lease),
                Err(error) => {
                    let Some(challenge) = challenge_from_error(&error) else {
                        return Err(error).context("TURN Refresh");
                    };
                    if challenge.code != 438 {
                        return Err(error).context("unexpected TURN Refresh challenge");
                    }
                    if attempt == self.max_challenge_retries {
                        return Err(error).context("TURN Refresh stale-nonce retry limit reached");
                    }
                    let next = self.provider.context_for_challenge(challenge).await
                        .context("obtain TURN auth context for stale nonce")?;
                    self.auth = Some(next);
                }
            }
        }
        anyhow::bail!("TURN Refresh retry loop exhausted")
    }

    /// Sleep until the allocation refresh deadline, then refresh it.
    /// The same supervisor must remain the sole owner of the driver.
    pub async fn maintain_allocation(&mut self) -> Result<()> {
        loop {
            let now = Instant::now();
            let lease = self.driver.allocation().context("TURN allocation is not active")?;
            let mut next_deadline = lease.refresh_at;
            if let Some(registry) = self.driver.peer_registry() {
                for peer in self.permission_peers.keys() {
                    if let Some(expiry) = registry.permission_expires_at(*peer) {
                        next_deadline = next_deadline.min(expiry.checked_sub(Duration::from_secs(60)).unwrap_or(now));
                    }
                }
                for channel in self.channel_bindings.keys() {
                    if let Some(expiry) = registry.channel_expires_at(*channel) {
                        next_deadline = next_deadline.min(expiry.checked_sub(Duration::from_secs(120)).unwrap_or(now));
                    }
                }
            }
            let lifetime_seconds = lease.lifetime_seconds;
            tokio::time::sleep_until(tokio::time::Instant::from_std(next_deadline)).await;
            let now = Instant::now();
            let allocation_due = self.driver.allocation()
                .is_some_and(|active| now >= active.refresh_at);
            if allocation_due {
                self.refresh(lifetime_seconds).await.context("maintain TURN allocation")?;
            }

            let due_channels: Vec<(u16, SocketAddr)> = self.channel_bindings.iter()
                .filter_map(|(channel, peer)| {
                    let due = self.driver.peer_registry()
                        .and_then(|registry| registry.channel_expires_at(*channel))
                        .is_some_and(|expiry| now >= expiry.checked_sub(Duration::from_secs(120)).unwrap_or(now));
                    due.then_some((*channel, *peer))
                })
                .collect();
            for (channel, peer) in due_channels {
                self.channel_bind(channel, peer).await.context("refresh TURN channel binding")?;
            }

            let due_permissions: Vec<SocketAddr> = self.permission_peers.iter()
                .filter_map(|(ip, peer)| {
                    let due = self.driver.peer_registry()
                        .and_then(|registry| registry.permission_expires_at(*ip))
                        .is_some_and(|expiry| now >= expiry.checked_sub(Duration::from_secs(60)).unwrap_or(now));
                    due.then_some(*peer)
                })
                .collect();
            if !due_permissions.is_empty() {
                self.create_permission(&due_permissions).await.context("refresh TURN permissions")?;
            }

            self.expire_peer_state();
            if self.driver.allocation().is_none() {
                anyhow::bail!("TURN allocation was deallocated");
            }
        }
    }

    /// Expire local permission/channel state from the single owner loop.
    pub fn expire_peer_state(&mut self) -> Option<ghulakh_protocol::turn_peer::ExpiredPeerState> {
        self.driver.expire_peer_state(Instant::now())
    }

    pub async fn create_permission(&mut self, peers: &[SocketAddr]) -> Result<()> {
        for attempt in 0..=self.max_challenge_retries {
            let auth = self.auth.as_ref().context("TURN auth context is not initialized")?;
            match self.driver.create_permission(peers, auth).await {
                Ok(()) => {
                    for peer in peers {
                        self.permission_peers.insert(peer.ip(), *peer);
                    }
                    return Ok(());
                }
                Err(error) => {
                    let Some(challenge) = challenge_from_error(&error) else {
                        return Err(error).context("TURN CreatePermission");
                    };
                    if challenge.code != 438 || attempt == self.max_challenge_retries {
                        return Err(error).context("TURN CreatePermission challenge retry limit reached");
                    }
                    self.auth = Some(self.provider.context_for_challenge(challenge).await
                        .context("obtain TURN auth context for CreatePermission stale nonce")?);
                }
            }
        }
        anyhow::bail!("TURN CreatePermission retry loop exhausted")
    }

    pub async fn channel_bind(&mut self, channel_number: u16, peer: SocketAddr) -> Result<()> {
        for attempt in 0..=self.max_challenge_retries {
            let auth = self.auth.as_ref().context("TURN auth context is not initialized")?;
            match self.driver.channel_bind(channel_number, peer, auth).await {
                Ok(()) => {
                    self.permission_peers.insert(peer.ip(), peer);
                    self.channel_bindings.insert(channel_number, peer);
                    return Ok(());
                }
                Err(error) => {
                    let Some(challenge) = challenge_from_error(&error) else {
                        return Err(error).context("TURN ChannelBind");
                    };
                    if challenge.code != 438 || attempt == self.max_challenge_retries {
                        return Err(error).context("TURN ChannelBind challenge retry limit reached");
                    }
                    self.auth = Some(self.provider.context_for_challenge(challenge).await
                        .context("obtain TURN auth context for ChannelBind stale nonce")?);
                }
            }
        }
        anyhow::bail!("TURN ChannelBind retry loop exhausted")
    }

    /// Transfer the isolated handshake event stream and actor sender.
    /// TURN control and data-plane ownership remain with this supervisor.
    pub fn take_handshake_plane_parts(
        &mut self,
    ) -> Option<(crate::turn_socket_actor::TurnSocketHandle, tokio::sync::mpsc::Receiver<crate::turn_socket_actor::TurnInbound>)> {
        self.driver.take_handshake_plane_parts()
    }

    /// Transfer the TURN actor's bounded data receiver and send handle to the dataplane.
    /// Control-plane ownership remains with this supervisor.
    pub fn take_data_plane_parts(
        &mut self,
    ) -> Option<(crate::turn_socket_actor::TurnSocketHandle, tokio::sync::mpsc::Receiver<crate::turn_socket_actor::TurnInbound>)> {
        self.driver.take_data_plane_parts()
    }

    pub fn close(&mut self) {
        self.auth = None;
        self.permission_peers.clear();
        self.channel_bindings.clear();
        self.driver.close();
    }
}

fn challenge_from_error(error: &anyhow::Error) -> Option<TurnChallenge> {
    match error.downcast_ref::<TurnDriverError>() {
        Some(TurnDriverError::Challenge(challenge)) => Some(challenge.clone()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn challenge_retry_budget_is_bounded() {
        assert_eq!(MAX_CHALLENGE_RETRIES, 3);
    }
}



#[cfg(test)]
mod authenticated_stale_nonce_tests {
    use super::*;
    use crate::turn_auth::TurnIntegrityAlgorithm;
    use ghulakh_protocol::stun::{
        append_message_integrity, encode_xor_address, StunAttribute, StunClass, StunMessage,
        ATTR_ERROR_CODE, ATTR_LIFETIME, ATTR_NONCE, ATTR_REALM, ATTR_XOR_RELAYED_ADDRESS,
        METHOD_ALLOCATE, METHOD_REFRESH,
    };
    use std::net::SocketAddr;
    use tokio::{net::UdpSocket, time::{timeout, Duration}};

    struct TestProvider {
        challenges: Vec<(u16, String)>,
    }

    impl TurnAuthProvider for TestProvider {
        fn context_for_challenge<'a>(
            &'a mut self,
            challenge: TurnChallenge,
        ) -> Pin<Box<dyn Future<Output = Result<TurnAuthContext>> + Send + 'a>> {
            Box::pin(async move {
                self.challenges.push((challenge.code, challenge.nonce.clone()));
                let key = if challenge.nonce == "nonce-1" { vec![0x11; 32] } else { vec![0x22; 32] };
                TurnAuthContext::new(
                    "test-user".into(),
                    challenge.realm,
                    challenge.nonce,
                    key,
                    TurnIntegrityAlgorithm::Sha1,
                ).map_err(anyhow::Error::new)
            })
        }
    }

    fn error_response(request: &StunMessage, code: u16, nonce: &str) -> StunMessage {
        StunMessage {
            method: request.method,
            class: StunClass::ErrorResponse,
            transaction_id: request.transaction_id,
            attributes: vec![
                StunAttribute {
                    kind: ATTR_ERROR_CODE,
                    value: vec![0, 0, ((code / 100) as u8) & 0x07, (code % 100) as u8],
                },
                StunAttribute { kind: ATTR_REALM, value: b"turn.example.invalid".to_vec() },
                StunAttribute { kind: ATTR_NONCE, value: nonce.as_bytes().to_vec() },
            ],
        }
    }

    async fn receive_request(relay: &UdpSocket, buffer: &mut [u8]) -> (StunMessage, SocketAddr) {
        let (length, source) = timeout(Duration::from_secs(3), relay.recv_from(buffer))
            .await.unwrap().unwrap();
        (StunMessage::decode(&buffer[..length]).unwrap(), source)
    }

    #[tokio::test]
    async fn verified_stale_nonce_reauthenticates_and_retries_refresh() {
        let relay = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let relay_addr = relay.local_addr().unwrap();
        let socket = crate::turn_udp::TurnUdpSocket::bind(
            "127.0.0.1:0".parse().unwrap(), relay_addr,
        ).await.unwrap();

        let relay_task = tokio::spawn(async move {
            let mut buffer = [0u8; 2048];

            // Initial unauthenticated Allocate receives the 401 challenge.
            let (allocate_1, client) = receive_request(&relay, &mut buffer).await;
            assert_eq!(allocate_1.method, METHOD_ALLOCATE);
            let challenge_401 = error_response(&allocate_1, 401, "nonce-1").encode().unwrap();
            relay.send_to(&challenge_401, client).await.unwrap();

            // The authenticated Allocate uses the first nonce and key.
            let (allocate_2, client) = receive_request(&relay, &mut buffer).await;
            assert_eq!(
                allocate_2.attributes.iter().find(|a| a.kind == ATTR_NONCE).unwrap().value,
                b"nonce-1",
            );
            let relayed: SocketAddr = "198.51.100.10:50000".parse().unwrap();
            let allocate_success = StunMessage {
                method: METHOD_ALLOCATE,
                class: StunClass::SuccessResponse,
                transaction_id: allocate_2.transaction_id,
                attributes: vec![
                    StunAttribute {
                        kind: ATTR_XOR_RELAYED_ADDRESS,
                        value: encode_xor_address(relayed, &allocate_2.transaction_id),
                    },
                    StunAttribute { kind: ATTR_LIFETIME, value: 600u32.to_be_bytes().to_vec() },
                ],
            };
            let signed_allocate = append_message_integrity(&allocate_success, &[0x11; 32]).unwrap();
            relay.send_to(&signed_allocate, client).await.unwrap();

            // Refresh with the old nonce gets an authenticated 438 Stale Nonce.
            let (refresh_1, client) = receive_request(&relay, &mut buffer).await;
            assert_eq!(refresh_1.method, METHOD_REFRESH);
            assert_eq!(
                refresh_1.attributes.iter().find(|a| a.kind == ATTR_NONCE).unwrap().value,
                b"nonce-1",
            );
            let stale_nonce = error_response(&refresh_1, 438, "nonce-2");
            let signed_stale = append_message_integrity(&stale_nonce, &[0x11; 32]).unwrap();
            relay.send_to(&signed_stale, client).await.unwrap();

            // Retry must carry the new nonce and use the new integrity key.
            let (refresh_2, client) = receive_request(&relay, &mut buffer).await;
            assert_eq!(refresh_2.method, METHOD_REFRESH);
            assert_eq!(
                refresh_2.attributes.iter().find(|a| a.kind == ATTR_NONCE).unwrap().value,
                b"nonce-2",
            );
            let refresh_success = StunMessage {
                method: METHOD_REFRESH,
                class: StunClass::SuccessResponse,
                transaction_id: refresh_2.transaction_id,
                attributes: vec![StunAttribute {
                    kind: ATTR_LIFETIME,
                    value: 600u32.to_be_bytes().to_vec(),
                }],
            };
            let signed_refresh = append_message_integrity(&refresh_success, &[0x22; 32]).unwrap();
            relay.send_to(&signed_refresh, client).await.unwrap();
        });

        let provider = TestProvider { challenges: Vec::new() };
        let mut supervisor = TurnSessionSupervisor::new(
            crate::turn_driver::TurnClientDriver::new(socket),
            provider,
        );
        let lease = supervisor.allocate().await.unwrap();
        assert_eq!(lease.relayed_address, "198.51.100.10:50000".parse().unwrap());
        let refreshed = supervisor.refresh(600).await.unwrap().unwrap();
        assert_eq!(refreshed.lifetime_seconds, 600);
        assert_eq!(
            supervisor.provider.challenges,
            vec![(401, "nonce-1".into()), (438, "nonce-2".into())],
        );
        relay_task.await.unwrap();
        supervisor.close();
    }
}



#[cfg(test)]
mod server_error_state_tests {
    use super::*;
    use crate::turn_auth::TurnIntegrityAlgorithm;
    use ghulakh_protocol::stun::{
        append_message_integrity, encode_xor_address, StunAttribute, StunClass, StunMessage,
        ATTR_ERROR_CODE, ATTR_LIFETIME, ATTR_NONCE, ATTR_REALM, ATTR_XOR_RELAYED_ADDRESS,
        METHOD_ALLOCATE, METHOD_REFRESH,
    };
    use std::net::SocketAddr;
    use tokio::{net::UdpSocket, time::{timeout, Duration}};

    struct Provider {
        calls: usize,
    }

    impl TurnAuthProvider for Provider {
        fn context_for_challenge<'a>(
            &'a mut self,
            challenge: TurnChallenge,
        ) -> Pin<Box<dyn Future<Output = Result<TurnAuthContext>> + Send + 'a>> {
            Box::pin(async move {
                self.calls += 1;
                TurnAuthContext::new(
                    "test-user".into(),
                    challenge.realm,
                    challenge.nonce,
                    vec![0x44; 32],
                    TurnIntegrityAlgorithm::Sha1,
                ).map_err(anyhow::Error::new)
            })
        }
    }

    async fn receive(relay: &UdpSocket, buffer: &mut [u8]) -> (StunMessage, SocketAddr) {
        let (length, source) = timeout(Duration::from_secs(3), relay.recv_from(buffer))
            .await.unwrap().unwrap();
        (StunMessage::decode(&buffer[..length]).unwrap(), source)
    }

    fn challenge(request: &StunMessage, code: u16) -> StunMessage {
        StunMessage {
            method: request.method,
            class: StunClass::ErrorResponse,
            transaction_id: request.transaction_id,
            attributes: vec![
                StunAttribute {
                    kind: ATTR_ERROR_CODE,
                    value: vec![0, 0, ((code / 100) as u8) & 0x07, (code % 100) as u8],
                },
                StunAttribute { kind: ATTR_REALM, value: b"turn.example.invalid".to_vec() },
                StunAttribute { kind: ATTR_NONCE, value: b"nonce-1".to_vec() },
            ],
        }
    }

    fn allocate_success(request: &StunMessage) -> Vec<u8> {
        let relayed: SocketAddr = "198.51.100.20:50000".parse().unwrap();
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
        append_message_integrity(&response, &[0x44; 32]).unwrap()
    }

    #[tokio::test]
    async fn authenticated_allocate_server_error_aborts_provisional_state() {
        let relay = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let relay_addr = relay.local_addr().unwrap();
        let socket = crate::turn_udp::TurnUdpSocket::bind(
            "127.0.0.1:0".parse().unwrap(), relay_addr,
        ).await.unwrap();

        let relay_task = tokio::spawn(async move {
            let mut buffer = [0u8; 2048];
            let (initial, client) = receive(&relay, &mut buffer).await;
            assert_eq!(initial.method, METHOD_ALLOCATE);
            relay.send_to(&challenge(&initial, 401).encode().unwrap(), client).await.unwrap();

            let (authenticated, client) = receive(&relay, &mut buffer).await;
            assert_eq!(authenticated.method, METHOD_ALLOCATE);
            let denied = challenge(&authenticated, 437);
            let signed = append_message_integrity(&denied, &[0x44; 32]).unwrap();
            relay.send_to(&signed, client).await.unwrap();
        });

        let provider = Provider { calls: 0 };
        let mut supervisor = TurnSessionSupervisor::new(
            crate::turn_driver::TurnClientDriver::new(socket),
            provider,
        );
        let error = supervisor.allocate().await.unwrap_err();
        assert!(matches!(
            error.downcast_ref::<TurnDriverError>(),
            Some(TurnDriverError::ServerError { code: 437 })
        ));
        assert!(supervisor.allocation().is_none());
        assert_eq!(supervisor.provider.calls, 1);
        relay_task.await.unwrap();
        supervisor.close();
    }

    #[tokio::test]
    async fn authenticated_refresh_server_error_preserves_existing_allocation() {
        let relay = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let relay_addr = relay.local_addr().unwrap();
        let socket = crate::turn_udp::TurnUdpSocket::bind(
            "127.0.0.1:0".parse().unwrap(), relay_addr,
        ).await.unwrap();

        let relay_task = tokio::spawn(async move {
            let mut buffer = [0u8; 2048];
            let (initial, client) = receive(&relay, &mut buffer).await;
            relay.send_to(&challenge(&initial, 401).encode().unwrap(), client).await.unwrap();

            let (allocate, client) = receive(&relay, &mut buffer).await;
            let success = allocate_success(&allocate);
            relay.send_to(&success, client).await.unwrap();

            let (refresh, client) = receive(&relay, &mut buffer).await;
            assert_eq!(refresh.method, METHOD_REFRESH);
            let denied = challenge(&refresh, 437);
            let signed = append_message_integrity(&denied, &[0x44; 32]).unwrap();
            relay.send_to(&signed, client).await.unwrap();
        });

        let provider = Provider { calls: 0 };
        let mut supervisor = TurnSessionSupervisor::new(
            crate::turn_driver::TurnClientDriver::new(socket),
            provider,
        );
        let before = supervisor.allocate().await.unwrap();
        let error = supervisor.refresh(600).await.unwrap_err();
        assert!(matches!(
            error.downcast_ref::<TurnDriverError>(),
            Some(TurnDriverError::ServerError { code: 437 })
        ));
        let after = supervisor.allocation().expect("failed refresh must preserve lease");
        assert_eq!(after.relayed_address, before.relayed_address);
        assert_eq!(after.lifetime_seconds, before.lifetime_seconds);
        assert_eq!(supervisor.provider.calls, 1);
        relay_task.await.unwrap();
        supervisor.close();
    }
}
