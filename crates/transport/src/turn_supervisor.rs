//! TURN allocation session supervisor.
//!
//! Credentials and password-key derivation remain outside the transport. The
//! provider is called only when TURN returns an initial or stale-nonce challenge.
//! This supervisor serializes allocation and refresh and bounds challenge retries.

use std::{future::Future, net::SocketAddr, pin::Pin, time::Instant};

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
}

impl<P: TurnAuthProvider> TurnSessionSupervisor<P> {
    pub fn new(driver: TurnClientDriver, provider: P) -> Self {
        Self {
            driver,
            provider,
            auth: None,
            max_challenge_retries: MAX_CHALLENGE_RETRIES,
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
            let (refresh_at, lifetime_seconds) = {
                let lease = self.driver.allocation()
                    .context("TURN allocation is not active")?;
                (lease.refresh_at, lease.lifetime_seconds)
            };
            tokio::time::sleep_until(tokio::time::Instant::from_std(refresh_at)).await;
            if self.driver.allocation().is_none() {
                anyhow::bail!("TURN allocation ended before refresh deadline");
            }
            self.refresh(lifetime_seconds).await.context("maintain TURN allocation")?;
            if self.driver.allocation().is_none() {
                anyhow::bail!("TURN allocation was deallocated");
            }
            self.expire_peer_state();
        }
    }

    /// Expire local permission/channel state from the single owner loop.
    pub fn expire_peer_state(&mut self) -> Option<ghulakh_protocol::turn_peer::ExpiredPeerState> {
        self.driver.expire_peer_state(Instant::now())
    }

    pub async fn create_permission(&mut self, peers: &[SocketAddr]) -> Result<()> {
        let auth = self.auth.as_ref().context("TURN auth context is not initialized")?;
        self.driver.create_permission(peers, auth).await
    }

    pub async fn channel_bind(&mut self, channel_number: u16, peer: SocketAddr) -> Result<()> {
        let auth = self.auth.as_ref().context("TURN auth context is not initialized")?;
        self.driver.channel_bind(channel_number, peer, auth).await
    }

    pub fn close(&mut self) {
        self.auth = None;
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
