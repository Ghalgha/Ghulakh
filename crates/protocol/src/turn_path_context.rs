//! Authenticated metadata for grouping independent TURN allocations into one VPN tunnel.
use zeroize::Zeroizing;

use crate::MAX_CREDENTIAL_LEN;

const MAGIC: &[u8; 4] = b"GHMP";
const VERSION: u8 = 1;
const HEADER_LEN: usize = 27;
pub const MAX_TURN_PATHS: u16 = 10;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TurnPathContext {
    pub group_id: [u8; 16],
    pub path_id: u16,
    pub path_count: u16,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum TurnPathContextError {
    #[error("invalid multipath context magic or version")]
    InvalidHeader,
    #[error("multipath group identifier must not be zero")]
    InvalidGroupId,
    #[error("multipath path count is outside the supported range")]
    InvalidPathCount,
    #[error("multipath path identifier is outside the declared group")]
    InvalidPathId,
    #[error("multipath credential length is invalid")]
    InvalidCredentialLength,
    #[error("multipath payload length is invalid")]
    InvalidLength,
}

impl TurnPathContext {
    pub fn validate(self) -> Result<Self, TurnPathContextError> {
        if self.group_id.iter().all(|byte| *byte == 0) {
            return Err(TurnPathContextError::InvalidGroupId);
        }
        if !(2..=MAX_TURN_PATHS).contains(&self.path_count) {
            return Err(TurnPathContextError::InvalidPathCount);
        }
        if self.path_id >= self.path_count {
            return Err(TurnPathContextError::InvalidPathId);
        }
        Ok(self)
    }
}

/// Credential and path metadata are encoded together and must be carried only
/// inside the encrypted third message of the Noise handshake.
pub struct TurnClientAuthPayload {
    pub context: TurnPathContext,
    credential: Zeroizing<Vec<u8>>,
}

impl TurnClientAuthPayload {
    pub fn new(
        context: TurnPathContext,
        credential: &[u8],
    ) -> Result<Self, TurnPathContextError> {
        context.validate()?;
        if credential.is_empty() || credential.len() > MAX_CREDENTIAL_LEN {
            return Err(TurnPathContextError::InvalidCredentialLength);
        }
        Ok(Self {
            context,
            credential: Zeroizing::new(credential.to_vec()),
        })
    }

    pub fn credential(&self) -> &[u8] {
        &self.credential
    }

    pub fn encode(&self) -> Result<Zeroizing<Vec<u8>>, TurnPathContextError> {
        self.context.validate()?;
        if self.credential.is_empty() || self.credential.len() > MAX_CREDENTIAL_LEN {
            return Err(TurnPathContextError::InvalidCredentialLength);
        }
        let length = u16::try_from(self.credential.len())
            .map_err(|_| TurnPathContextError::InvalidCredentialLength)?;
        let mut encoded = Zeroizing::new(Vec::with_capacity(HEADER_LEN + self.credential.len()));
        encoded.extend_from_slice(MAGIC);
        encoded.push(VERSION);
        encoded.extend_from_slice(&self.context.group_id);
        encoded.extend_from_slice(&self.context.path_id.to_be_bytes());
        encoded.extend_from_slice(&self.context.path_count.to_be_bytes());
        encoded.extend_from_slice(&length.to_be_bytes());
        encoded.extend_from_slice(&self.credential);
        Ok(encoded)
    }

    pub fn decode(encoded: &[u8]) -> Result<Self, TurnPathContextError> {
        if encoded.len() < HEADER_LEN || &encoded[..4] != MAGIC || encoded[4] != VERSION {
            return Err(TurnPathContextError::InvalidHeader);
        }
        let mut group_id = [0u8; 16];
        group_id.copy_from_slice(&encoded[5..21]);
        let context = TurnPathContext {
            group_id,
            path_id: u16::from_be_bytes([encoded[21], encoded[22]]),
            path_count: u16::from_be_bytes([encoded[23], encoded[24]]),
        }.validate()?;
        let credential_len = usize::from(u16::from_be_bytes([encoded[25], encoded[26]]));
        if credential_len == 0 || credential_len > MAX_CREDENTIAL_LEN {
            return Err(TurnPathContextError::InvalidCredentialLength);
        }
        if encoded.len() != HEADER_LEN + credential_len {
            return Err(TurnPathContextError::InvalidLength);
        }
        Ok(Self {
            context,
            credential: Zeroizing::new(encoded[HEADER_LEN..].to_vec()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn context(path_id: u16) -> TurnPathContext {
        TurnPathContext {
            group_id: [0x42; 16],
            path_id,
            path_count: 3,
        }
    }

    #[test]
    fn round_trip_keeps_group_and_path_metadata_inside_payload() {
        let payload = TurnClientAuthPayload::new(context(2), b"tunnel-secret").unwrap();
        let encoded = payload.encode().unwrap();
        let decoded = TurnClientAuthPayload::decode(&encoded).unwrap();
        assert_eq!(decoded.context, context(2));
        assert_eq!(decoded.credential(), b"tunnel-secret");
    }

    #[test]
    fn rejects_zero_group_identifier() {
        let mut value = context(0);
        value.group_id = [0; 16];
        assert_eq!(value.validate(), Err(TurnPathContextError::InvalidGroupId));
    }

    #[test]
    fn rejects_path_count_below_multipath_minimum() {
        let mut value = context(0);
        value.path_count = 1;
        assert_eq!(value.validate(), Err(TurnPathContextError::InvalidPathCount));
    }

    #[test]
    fn rejects_path_count_above_limit() {
        let mut value = context(0);
        value.path_count = MAX_TURN_PATHS + 1;
        assert_eq!(value.validate(), Err(TurnPathContextError::InvalidPathCount));
    }

    #[test]
    fn rejects_path_id_outside_group() {
        let mut value = context(0);
        value.path_id = value.path_count;
        assert_eq!(value.validate(), Err(TurnPathContextError::InvalidPathId));
    }

    #[test]
    fn rejects_empty_and_oversized_credentials() {
        assert_eq!(
            TurnClientAuthPayload::new(context(0), b"").err(),
            Some(TurnPathContextError::InvalidCredentialLength)
        );
        assert_eq!(
            TurnClientAuthPayload::new(context(0), &vec![1; MAX_CREDENTIAL_LEN + 1]).err(),
            Some(TurnPathContextError::InvalidCredentialLength)
        );
    }

    #[test]
    fn rejects_trailing_or_truncated_payload_bytes() {
        let payload = TurnClientAuthPayload::new(context(0), b"secret").unwrap();
        let mut encoded = payload.encode().unwrap().to_vec();
        encoded.push(0);
        assert_eq!(
            TurnClientAuthPayload::decode(&encoded).err(),
            Some(TurnPathContextError::InvalidLength)
        );
        encoded.pop();
        encoded.pop();
        assert_eq!(
            TurnClientAuthPayload::decode(&encoded).err(),
            Some(TurnPathContextError::InvalidLength)
        );
    }
}
