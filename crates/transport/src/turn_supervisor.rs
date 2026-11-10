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
