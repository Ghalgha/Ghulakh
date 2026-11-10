//! TURN permission and channel-binding state scoped to one allocation.
//!
//! State is updated only after authenticated success responses. This registry
//! does not send requests or infer that a ChannelBind succeeded.

use std::{
    collections::BTreeMap,
    net::{IpAddr, SocketAddr},
    time::{Duration, Instant},
};

pub const PERMISSION_LIFETIME: Duration = Duration::from_secs(300);
pub const CHANNEL_BINDING_LIFETIME: Duration = Duration::from_secs(600);
pub const CHANNEL_REUSE_DELAY: Duration = Duration::from_secs(300);
pub const CHANNEL_NUMBER_MIN: u16 = 0x4000;
pub const CHANNEL_NUMBER_MAX: u16 = 0x4fff;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelBinding {
    pub channel_number: u16,
    pub peer: SocketAddr,
    pub expires_at: Instant,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ExpiredPeerState {
    pub permissions: usize,
    pub channels: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PeerStateError {
    #[error("peer address family does not match the relayed address family")]
    AddressFamilyMismatch,
    #[error("channel number is outside the RFC 8656 range 0x4000..=0x4fff")]
    InvalidChannelNumber,
    #[error("channel number is already bound to another peer")]
    ChannelConflict,
    #[error("peer address is already bound to another channel")]
    PeerConflict,
    #[error("channel number or peer address is in the RFC reuse cooldown")]
    ReuseCooldown,
    #[error("monotonic deadline overflow")]
    DeadlineOverflow,
}

#[derive(Debug)]
pub struct TurnPeerRegistry {
    relayed_ip: IpAddr,
    permissions: BTreeMap<IpAddr, Instant>,
    channels: BTreeMap<u16, ChannelBinding>,
    peer_channels: BTreeMap<SocketAddr, u16>,
    channel_cooldowns: BTreeMap<u16, Instant>,
    peer_cooldowns: BTreeMap<SocketAddr, Instant>,
}

impl TurnPeerRegistry {
    pub fn new(relayed_ip: IpAddr) -> Self {
        Self {
            relayed_ip,
            permissions: BTreeMap::new(),
            channels: BTreeMap::new(),
            peer_channels: BTreeMap::new(),
            channel_cooldowns: BTreeMap::new(),
            peer_cooldowns: BTreeMap::new(),
        }
    }

    pub fn install_permission(
        &mut self,
        peer_ip: IpAddr,
        now: Instant,
    ) -> Result<(), PeerStateError> {
        self.expire(now);
        self.validate_family(peer_ip)?;
        let expires_at = now.checked_add(PERMISSION_LIFETIME)
            .ok_or(PeerStateError::DeadlineOverflow)?;
        self.permissions.insert(peer_ip, expires_at);
        Ok(())
    }

    /// Record a successful ChannelBind response. ChannelBind also installs or
    /// refreshes the permission for the peer IP address.
    pub fn install_channel_binding(
        &mut self,
        channel_number: u16,
        peer: SocketAddr,
        now: Instant,
    ) -> Result<(), PeerStateError> {
        self.expire(now);
        if !(CHANNEL_NUMBER_MIN..=CHANNEL_NUMBER_MAX).contains(&channel_number) {
            return Err(PeerStateError::InvalidChannelNumber);
        }
        self.validate_family(peer.ip())?;

        if let Some(existing) = self.channels.get(&channel_number) {
            if existing.peer != peer {
                return Err(PeerStateError::ChannelConflict);
            }
        }
        if let Some(existing_channel) = self.peer_channels.get(&peer) {
            if *existing_channel != channel_number {
                return Err(PeerStateError::PeerConflict);
            }
        }
        if self.channel_cooldowns.get(&channel_number).is_some_and(|until| now < *until)
            || self.peer_cooldowns.get(&peer).is_some_and(|until| now < *until)
        {
            return Err(PeerStateError::ReuseCooldown);
        }

        let permission_expiry = now.checked_add(PERMISSION_LIFETIME)
            .ok_or(PeerStateError::DeadlineOverflow)?;
        let channel_expiry = now.checked_add(CHANNEL_BINDING_LIFETIME)
            .ok_or(PeerStateError::DeadlineOverflow)?;

        self.permissions.insert(peer.ip(), permission_expiry);
        self.peer_channels.insert(peer, channel_number);
        self.channels.insert(channel_number, ChannelBinding {
            channel_number,
            peer,
            expires_at: channel_expiry,
        });
        Ok(())
    }

    pub fn permission_active(&self, peer_ip: IpAddr, now: Instant) -> bool {
        self.permissions.get(&peer_ip).is_some_and(|expires_at| now < *expires_at)
    }

    pub fn channel_for_peer(&mut self, peer: SocketAddr, now: Instant) -> Option<u16> {
        self.expire(now);
        self.peer_channels.get(&peer).copied()
    }

    pub fn peer_for_channel(&mut self, channel_number: u16, now: Instant) -> Option<SocketAddr> {
        self.expire(now);
        self.channels.get(&channel_number).map(|binding| binding.peer)
    }

    pub fn expire(&mut self, now: Instant) -> ExpiredPeerState {
        let expired_permissions: Vec<IpAddr> = self.permissions.iter()
            .filter_map(|(ip, expiry)| (now >= *expiry).then_some(*ip))
            .collect();
        for ip in &expired_permissions {
            self.permissions.remove(ip);
        }

        let expired_channels: Vec<ChannelBinding> = self.channels.values()
            .filter(|binding| now >= binding.expires_at)
            .cloned()
            .collect();
        for binding in &expired_channels {
            self.channels.remove(&binding.channel_number);
            self.peer_channels.remove(&binding.peer);

            let cooldown_until = binding.expires_at.checked_add(CHANNEL_REUSE_DELAY)
                .unwrap_or(now);
            if cooldown_until > now {
                self.channel_cooldowns.insert(binding.channel_number, cooldown_until);
                self.peer_cooldowns.insert(binding.peer, cooldown_until);
            }
        }

        self.channel_cooldowns.retain(|_, until| now < *until);
        self.peer_cooldowns.retain(|_, until| now < *until);

        ExpiredPeerState {
            permissions: expired_permissions.len(),
            channels: expired_channels.len(),
        }
    }

    /// Clear all permission, channel and cooldown state when the allocation ends.
    pub fn clear(&mut self) {
        self.permissions.clear();
        self.channels.clear();
        self.peer_channels.clear();
        self.channel_cooldowns.clear();
        self.peer_cooldowns.clear();
    }

    pub fn permission_count(&self) -> usize {
        self.permissions.len()
    }

    pub fn channel_count(&self) -> usize {
        self.channels.len()
    }

    fn validate_family(&self, peer_ip: IpAddr) -> Result<(), PeerStateError> {
        if self.relayed_ip.is_ipv4() != peer_ip.is_ipv4() {
            return Err(PeerStateError::AddressFamilyMismatch);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn registry() -> TurnPeerRegistry {
        TurnPeerRegistry::new("198.51.100.10".parse().unwrap())
    }

    fn peer() -> SocketAddr {
        "203.0.113.20:443".parse().unwrap()
    }

    #[test]
    fn permission_expires_after_five_minutes() {
        let now = Instant::now();
        let mut registry = registry();
        registry.install_permission(peer().ip(), now).unwrap();
        assert!(registry.permission_active(peer().ip(), now + Duration::from_secs(299)));
        assert!(!registry.permission_active(peer().ip(), now + PERMISSION_LIFETIME));
        assert_eq!(
            registry.expire(now + PERMISSION_LIFETIME),
            ExpiredPeerState { permissions: 1, channels: 0 }
        );
    }

    #[test]
    fn channel_bind_installs_permission_and_tracks_both_directions() {
        let now = Instant::now();
        let mut registry = registry();
        registry.install_channel_binding(0x4001, peer(), now).unwrap();
        assert_eq!(registry.channel_for_peer(peer(), now), Some(0x4001));
        assert_eq!(registry.peer_for_channel(0x4001, now), Some(peer()));
        assert!(registry.permission_active(peer().ip(), now + Duration::from_secs(299)));
        assert!(!registry.permission_active(peer().ip(), now + PERMISSION_LIFETIME));
    }

    #[test]
    fn enforces_channel_and_peer_uniqueness() {
        let now = Instant::now();
        let mut registry = registry();
        registry.install_channel_binding(0x4001, peer(), now).unwrap();
        assert_eq!(
            registry.install_channel_binding(0x4001, "203.0.113.21:443".parse().unwrap(), now),
            Err(PeerStateError::ChannelConflict)
        );
        assert_eq!(
            registry.install_channel_binding(0x4002, peer(), now),
            Err(PeerStateError::PeerConflict)
        );
    }

    #[test]
    fn channel_and_peer_reuse_wait_five_minutes_after_expiry() {
        let now = Instant::now();
        let mut registry = registry();
        registry.install_channel_binding(0x4001, peer(), now).unwrap();
        let binding_expiry = now + CHANNEL_BINDING_LIFETIME;
        assert_eq!(
            registry.expire(binding_expiry),
            ExpiredPeerState { permissions: 1, channels: 1 }
        );
        assert_eq!(
            registry.install_channel_binding(
                0x4001,
                "203.0.113.21:443".parse().unwrap(),
                binding_expiry + Duration::from_secs(299),
            ),
            Err(PeerStateError::ReuseCooldown)
        );
        registry.install_channel_binding(
            0x4001,
            "203.0.113.21:443".parse().unwrap(),
            binding_expiry + CHANNEL_REUSE_DELAY,
        ).unwrap();
    }

    #[test]
    fn rejects_wrong_family_and_invalid_channel() {
        let now = Instant::now();
        let mut registry = registry();
        assert_eq!(
            registry.install_permission("2001:db8::1".parse().unwrap(), now),
            Err(PeerStateError::AddressFamilyMismatch)
        );
        assert_eq!(
            registry.install_channel_binding(0x5000, peer(), now),
            Err(PeerStateError::InvalidChannelNumber)
        );
    }

    #[test]
    fn clear_removes_allocation_scoped_state() {
        let now = Instant::now();
        let mut registry = registry();
        registry.install_channel_binding(0x4001, peer(), now).unwrap();
        registry.clear();
        assert_eq!(registry.permission_count(), 0);
        assert_eq!(registry.channel_count(), 0);
        assert_eq!(registry.channel_for_peer(peer(), now), None);
    }
}
