//! Event-driven TURN allocation lifecycle state machine.
//!
//! This module owns no sockets or timers. The transport driver supplies matched,
//! integrity-verified TURN responses and calls expire() from its scheduler.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use crate::turn_request::TurnSuccess;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AllocationLease {
    pub relayed_address: SocketAddr,
    pub lifetime_seconds: u32,
    pub acquired_at: Instant,
    pub expires_at: Instant,
    pub refresh_at: Instant,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AllocationState {
    Idle,
    AwaitingAllocate {
        transaction_id: [u8; 12],
    },
    Active(AllocationLease),
    AwaitingRefresh {
        transaction_id: [u8; 12],
        lease: AllocationLease,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AllocationError {
    #[error("allocation operation is invalid in the current state")]
    InvalidState,
    #[error("TURN response does not match the pending transaction")]
    TransactionMismatch,
    #[error("TURN response method or result does not match the pending operation")]
    UnexpectedResponse,
    #[error("TURN allocation lifetime must be non-zero")]
    ZeroLifetime,
    #[error("TURN allocation lifetime overflows the monotonic clock")]
    LifetimeOverflow,
    #[error("TURN allocation has expired")]
    Expired,
}

#[derive(Debug, Default)]
pub struct AllocationManager {
    state: AllocationState,
}

impl Default for AllocationState {
    fn default() -> Self {
        Self::Idle
    }
}

impl AllocationManager {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn state(&self) -> &AllocationState {
        &self.state
    }

    pub fn begin_allocate(&mut self, transaction_id: [u8; 12]) -> Result<(), AllocationError> {
        if !matches!(&self.state, AllocationState::Idle) {
            return Err(AllocationError::InvalidState);
        }
        self.state = AllocationState::AwaitingAllocate { transaction_id };
        Ok(())
    }

    pub fn accept_allocate(
        &mut self,
        transaction_id: [u8; 12],
        result: TurnSuccess,
        now: Instant,
    ) -> Result<&AllocationLease, AllocationError> {
        let expected = match self.state {
            AllocationState::AwaitingAllocate { transaction_id } => transaction_id,
            _ => return Err(AllocationError::InvalidState),
        };
        if expected != transaction_id {
            return Err(AllocationError::TransactionMismatch);
        }
        let (relayed_address, lifetime_seconds) = match result {
            TurnSuccess::Allocate { relayed_address, lifetime_seconds } => {
                (relayed_address, lifetime_seconds)
            }
            _ => return Err(AllocationError::UnexpectedResponse),
        };
        let lease = make_lease(relayed_address, lifetime_seconds, now)?;
        self.state = AllocationState::Active(lease);
        match &self.state {
            AllocationState::Active(lease) => Ok(lease),
            _ => unreachable!(),
        }
    }

    pub fn begin_refresh(
        &mut self,
        transaction_id: [u8; 12],
        now: Instant,
    ) -> Result<(), AllocationError> {
        let lease = match &self.state {
            AllocationState::Active(lease) => lease.clone(),
            _ => return Err(AllocationError::InvalidState),
        };
        if now >= lease.expires_at {
            self.state = AllocationState::Idle;
            return Err(AllocationError::Expired);
        }
        self.state = AllocationState::AwaitingRefresh { transaction_id, lease };
        Ok(())
    }

    pub fn accept_refresh(
        &mut self,
        transaction_id: [u8; 12],
        result: TurnSuccess,
        now: Instant,
    ) -> Result<Option<&AllocationLease>, AllocationError> {
        let (expected, old_lease) = match &self.state {
            AllocationState::AwaitingRefresh { transaction_id, lease } => (*transaction_id, lease.clone()),
            _ => return Err(AllocationError::InvalidState),
        };
        if expected != transaction_id {
            return Err(AllocationError::TransactionMismatch);
        }
        let lifetime_seconds = match result {
            TurnSuccess::Refresh { lifetime_seconds } => lifetime_seconds,
            _ => return Err(AllocationError::UnexpectedResponse),
        };
        if lifetime_seconds == 0 {
            self.state = AllocationState::Idle;
            return Ok(None);
        }
        let lease = make_lease(old_lease.relayed_address, lifetime_seconds, now)?;
        self.state = AllocationState::Active(lease);
        match &self.state {
            AllocationState::Active(lease) => Ok(Some(lease)),
            _ => unreachable!(),
        }
    }

    /// Restore the existing lease after a failed refresh attempt. The caller
    /// must still retry before expires_at or let expire() retire the lease.
    pub fn refresh_failed(&mut self, transaction_id: [u8; 12]) -> Result<(), AllocationError> {
        let (expected, lease) = match &self.state {
            AllocationState::AwaitingRefresh { transaction_id, lease } => (*transaction_id, lease.clone()),
            _ => return Err(AllocationError::InvalidState),
        };
        if expected != transaction_id {
            return Err(AllocationError::TransactionMismatch);
        }
        self.state = AllocationState::Active(lease);
        Ok(())
    }

    /// Retire an allocation whose granted lifetime has elapsed.
    pub fn expire(&mut self, now: Instant) -> bool {
        let expired = match &self.state {
            AllocationState::Active(lease)
            | AllocationState::AwaitingRefresh { lease, .. } => now >= lease.expires_at,
            _ => false,
        };
        if expired {
            self.state = AllocationState::Idle;
        }
        expired
    }

    pub fn lease(&self) -> Option<&AllocationLease> {
        match &self.state {
            AllocationState::Active(lease)
            | AllocationState::AwaitingRefresh { lease, .. } => Some(lease),
            _ => None,
        }
    }
}

fn make_lease(
    relayed_address: SocketAddr,
    lifetime_seconds: u32,
    now: Instant,
) -> Result<AllocationLease, AllocationError> {
    if lifetime_seconds == 0 {
        return Err(AllocationError::ZeroLifetime);
    }
    let lifetime = Duration::from_secs(u64::from(lifetime_seconds));
    let expires_at = now.checked_add(lifetime).ok_or(AllocationError::LifetimeOverflow)?;
    // Refresh at 80% of the granted lifetime, leaving a recovery window.
    let refresh_after = lifetime.mul_f64(0.8);
    let refresh_at = now.checked_add(refresh_after).ok_or(AllocationError::LifetimeOverflow)?;
    Ok(AllocationLease {
        relayed_address,
        lifetime_seconds,
        acquired_at: now,
        expires_at,
        refresh_at,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn relayed() -> SocketAddr {
        "198.51.100.10:50000".parse().unwrap()
    }

    fn allocate_result(lifetime_seconds: u32) -> TurnSuccess {
        TurnSuccess::Allocate { relayed_address: relayed(), lifetime_seconds }
    }

    #[test]
    fn allocation_lifecycle_and_refresh_deadline() {
        let now = Instant::now();
        let mut manager = AllocationManager::new();
        manager.begin_allocate([1; 12]).unwrap();
        let lease = manager.accept_allocate([1; 12], allocate_result(600), now).unwrap();
        assert_eq!(lease.relayed_address, relayed());
        assert_eq!(lease.expires_at.duration_since(now), Duration::from_secs(600));
        assert_eq!(lease.refresh_at.duration_since(now), Duration::from_secs(480));

        manager.begin_refresh([2; 12], now + Duration::from_secs(480)).unwrap();
        let refreshed = manager.accept_refresh(
            [2; 12],
            TurnSuccess::Refresh { lifetime_seconds: 300 },
            now + Duration::from_secs(480),
        ).unwrap().unwrap();
        assert_eq!(refreshed.lifetime_seconds, 300);
        assert_eq!(refreshed.expires_at.duration_since(now), Duration::from_secs(780));
    }

    #[test]
    fn rejects_wrong_transaction_and_wrong_result() {
        let now = Instant::now();
        let mut manager = AllocationManager::new();
        manager.begin_allocate([1; 12]).unwrap();
        assert_eq!(
            manager.accept_allocate([2; 12], allocate_result(600), now),
            Err(AllocationError::TransactionMismatch)
        );
        assert_eq!(
            manager.accept_allocate([1; 12], TurnSuccess::Refresh { lifetime_seconds: 600 }, now),
            Err(AllocationError::UnexpectedResponse)
        );
        assert!(matches!(manager.state(), AllocationState::AwaitingAllocate { .. }));
    }

    #[test]
    fn zero_lifetime_refresh_deletes_allocation() {
        let now = Instant::now();
        let mut manager = AllocationManager::new();
        manager.begin_allocate([1; 12]).unwrap();
        manager.accept_allocate([1; 12], allocate_result(600), now).unwrap();
        manager.begin_refresh([2; 12], now).unwrap();
        assert_eq!(
            manager.accept_refresh([2; 12], TurnSuccess::Refresh { lifetime_seconds: 0 }, now),
            Ok(None)
        );
        assert_eq!(manager.state(), &AllocationState::Idle);
    }

    #[test]
    fn failed_refresh_restores_lease_and_expiry_retires_it() {
        let now = Instant::now();
        let mut manager = AllocationManager::new();
        manager.begin_allocate([1; 12]).unwrap();
        manager.accept_allocate([1; 12], allocate_result(10), now).unwrap();
        manager.begin_refresh([2; 12], now + Duration::from_secs(8)).unwrap();
        manager.refresh_failed([2; 12]).unwrap();
        assert!(manager.lease().is_some());
        assert!(!manager.expire(now + Duration::from_secs(9)));
        assert!(manager.expire(now + Duration::from_secs(10)));
        assert_eq!(manager.state(), &AllocationState::Idle);
    }

    #[test]
    fn refuses_refresh_after_expiry() {
        let now = Instant::now();
        let mut manager = AllocationManager::new();
        manager.begin_allocate([1; 12]).unwrap();
        manager.accept_allocate([1; 12], allocate_result(5), now).unwrap();
        assert_eq!(
            manager.begin_refresh([2; 12], now + Duration::from_secs(5)),
            Err(AllocationError::Expired)
        );
        assert_eq!(manager.state(), &AllocationState::Idle);
    }
}
