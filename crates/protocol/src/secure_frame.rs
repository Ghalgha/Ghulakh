//! Authenticated, replay-protected data frames for the TURN relay path.
//!
//! Keys and nonce prefixes are supplied by the authenticated session key
//! agreement. This module never derives keys from TURN passwords or credentials.
//! Use independent directional keys and nonce prefixes for each session.

use chacha20poly1305::{
    aead::{AeadInPlace, KeyInit},
    ChaCha20Poly1305, Key, Nonce, Tag,
};

pub const FRAME_HEADER_LEN: usize = 23;
pub const FRAME_TAG_LEN: usize = 16;
pub const MAX_PROTECTED_FRAME_SIZE: usize = crate::MAX_DATAGRAM_SIZE;
pub const MAX_PROTECTED_PAYLOAD_SIZE: usize =
    MAX_PROTECTED_FRAME_SIZE - FRAME_HEADER_LEN - FRAME_TAG_LEN;
const FRAME_MAGIC: &[u8; 4] = b"GHF1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FrameDirection {
    ClientToServer = 0,
    ServerToClient = 1,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FrameError {
    #[error("protected frame header is invalid")]
    InvalidHeader,
    #[error("protected frame length is invalid")]
    InvalidLength,
    #[error("protected frame exceeds the configured datagram limit")]
    PayloadTooLarge,
    #[error("protected frame belongs to another session")]
    SessionMismatch,
    #[error("protected frame has the wrong direction")]
    DirectionMismatch,
    #[error("protected frame authentication failed")]
    AuthenticationFailed,
    #[error("protected frame sequence number was already received")]
    DuplicateSequence,
    #[error("protected frame sequence number is outside the replay window")]
    SequenceTooOld,
    #[error("outbound frame sequence space is exhausted")]
    SequenceExhausted,
}

#[derive(Debug, Default)]
struct ReplayWindow {
    highest: Option<u64>,
    bitmap: u128,
}

impl ReplayWindow {
    fn check(&self, sequence: u64) -> Result<(), FrameError> {
        let Some(highest) = self.highest else {
            return Ok(());
        };
        if sequence > highest {
            return Ok(());
        }
        let distance = highest - sequence;
        if distance >= 128 {
            return Err(FrameError::SequenceTooOld);
        }
        if self.bitmap & (1u128 << distance) != 0 {
            return Err(FrameError::DuplicateSequence);
        }
        Ok(())
    }

    fn commit(&mut self, sequence: u64) {
        match self.highest {
            None => {
                self.highest = Some(sequence);
                self.bitmap = 1;
            }
            Some(highest) if sequence > highest => {
                let shift = sequence - highest;
                self.bitmap = if shift >= 128 {
                    1
                } else {
                    (self.bitmap << shift) | 1
                };
                self.highest = Some(sequence);
            }
            Some(highest) => {
                let distance = highest - sequence;
                if distance < 128 {
                    self.bitmap |= 1u128 << distance;
                }
            }
        }
    }
}

/// Read the public session identifier from a structurally valid protected frame.
/// This is only a bounded lookup hint; it does not authenticate the frame.
pub fn protected_frame_session_id(frame: &[u8]) -> Result<[u8; 8], FrameError> {
    if frame.len() < FRAME_HEADER_LEN + FRAME_TAG_LEN {
        return Err(FrameError::InvalidLength);
    }
    if &frame[..4] != FRAME_MAGIC {
        return Err(FrameError::InvalidHeader);
    }
    Ok(frame[4..12].try_into().map_err(|_| FrameError::InvalidHeader)?)
}

/// Encrypts outbound frames. A sequence number is consumed for every seal call.
pub struct FrameSealer {
    cipher: ChaCha20Poly1305,
    nonce_prefix: [u8; 4],
    session_id: [u8; 8],
    direction: FrameDirection,
    next_sequence: Option<u64>,
}

impl FrameSealer {
    pub fn session_id(&self) -> [u8; 8] {
        self.session_id
    }

    pub fn new(
        key: [u8; 32],
        nonce_prefix: [u8; 4],
        session_id: [u8; 8],
        direction: FrameDirection,
    ) -> Self {
        Self {
            cipher: ChaCha20Poly1305::new(Key::from_slice(&key)),
            nonce_prefix,
            session_id,
            direction,
            next_sequence: Some(0),
        }
    }

    pub fn seal(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, FrameError> {
        if plaintext.len() > MAX_PROTECTED_PAYLOAD_SIZE || plaintext.len() > u16::MAX as usize {
            return Err(FrameError::PayloadTooLarge);
        }
        let sequence = self.next_sequence.ok_or(FrameError::SequenceExhausted)?;
        self.next_sequence = sequence.checked_add(1);

        let mut header = Vec::with_capacity(FRAME_HEADER_LEN);
        header.extend_from_slice(FRAME_MAGIC);
        header.extend_from_slice(&self.session_id);
        header.push(self.direction as u8);
        header.extend_from_slice(&sequence.to_be_bytes());
        header.extend_from_slice(&(plaintext.len() as u16).to_be_bytes());

        let nonce = make_nonce(self.nonce_prefix, sequence);
        let mut ciphertext = plaintext.to_vec();
        let tag = self.cipher
            .encrypt_in_place_detached(Nonce::from_slice(&nonce), &header, &mut ciphertext)
            .map_err(|_| FrameError::AuthenticationFailed)?;

        let mut frame = header;
        frame.extend_from_slice(&ciphertext);
        frame.extend_from_slice(&tag);
        Ok(frame)
    }
}

/// Authenticates inbound frames and rejects duplicates/frames outside a 128-packet window.
pub struct FrameOpener {
    cipher: ChaCha20Poly1305,
    nonce_prefix: [u8; 4],
    session_id: [u8; 8],
    expected_direction: FrameDirection,
    replay: ReplayWindow,
}

impl FrameOpener {
    pub fn session_id(&self) -> [u8; 8] {
        self.session_id
    }

    pub fn new(
        key: [u8; 32],
        nonce_prefix: [u8; 4],
        session_id: [u8; 8],
        expected_direction: FrameDirection,
    ) -> Self {
        Self {
            cipher: ChaCha20Poly1305::new(Key::from_slice(&key)),
            nonce_prefix,
            session_id,
            expected_direction,
            replay: ReplayWindow::default(),
        }
    }

    pub fn open(&mut self, frame: &[u8]) -> Result<Vec<u8>, FrameError> {
        if frame.len() < FRAME_HEADER_LEN + FRAME_TAG_LEN {
            return Err(FrameError::InvalidLength);
        }
        if &frame[..4] != FRAME_MAGIC {
            return Err(FrameError::InvalidHeader);
        }
        if frame[4..12] != self.session_id {
            return Err(FrameError::SessionMismatch);
        }
        if frame[12] != self.expected_direction as u8 {
            return Err(FrameError::DirectionMismatch);
        }
        let sequence = u64::from_be_bytes(
            frame[13..21].try_into().map_err(|_| FrameError::InvalidHeader)?
        );
        let payload_len = usize::from(u16::from_be_bytes([frame[21], frame[22]]));
        if payload_len > MAX_PROTECTED_PAYLOAD_SIZE {
            return Err(FrameError::PayloadTooLarge);
        }
        let expected_len = FRAME_HEADER_LEN + payload_len + FRAME_TAG_LEN;
        if frame.len() != expected_len {
            return Err(FrameError::InvalidLength);
        }
        self.replay.check(sequence)?;

        let nonce = make_nonce(self.nonce_prefix, sequence);
        let mut plaintext = frame[FRAME_HEADER_LEN..FRAME_HEADER_LEN + payload_len].to_vec();
        let tag = Tag::from_slice(&frame[FRAME_HEADER_LEN + payload_len..]);
        self.cipher
            .decrypt_in_place_detached(
                Nonce::from_slice(&nonce),
                &frame[..FRAME_HEADER_LEN],
                &mut plaintext,
                tag,
            )
            .map_err(|_| FrameError::AuthenticationFailed)?;

        // Commit replay state only after successful AEAD authentication.
        self.replay.commit(sequence);
        Ok(plaintext)
    }
}

fn make_nonce(prefix: [u8; 4], sequence: u64) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[..4].copy_from_slice(&prefix);
    nonce[4..].copy_from_slice(&sequence.to_be_bytes());
    nonce
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; 32] = [0x42; 32];
    const PREFIX: [u8; 4] = [0x24; 4];
    const SESSION: [u8; 8] = [0x91; 8];

    fn pair() -> (FrameSealer, FrameOpener) {
        (
            FrameSealer::new(KEY, PREFIX, SESSION, FrameDirection::ClientToServer),
            FrameOpener::new(KEY, PREFIX, SESSION, FrameDirection::ClientToServer),
        )
    }

    #[test]
    fn round_trip_and_replay_rejection() {
        let (mut sealer, mut opener) = pair();
        let frame = sealer.seal(b"ip packet payload").unwrap();
        assert_eq!(opener.open(&frame).unwrap(), b"ip packet payload");
        assert_eq!(opener.open(&frame), Err(FrameError::DuplicateSequence));
    }

    #[test]
    fn rejects_modified_header_and_ciphertext() {
        let (mut sealer, _) = pair();
        let frame = sealer.seal(b"payload").unwrap();

        let mut bad_header = frame.clone();
        bad_header[13] ^= 1;
        let mut opener = pair().1;
        assert_eq!(opener.open(&bad_header), Err(FrameError::AuthenticationFailed));

        let mut bad_ciphertext = frame;
        bad_ciphertext[FRAME_HEADER_LEN] ^= 1;
        let mut opener = pair().1;
        assert_eq!(opener.open(&bad_ciphertext), Err(FrameError::AuthenticationFailed));
    }

    #[test]
    fn rejects_wrong_session_and_direction() {
        let (mut sealer, _) = pair();
        let frame = sealer.seal(b"payload").unwrap();

        let mut wrong_session = FrameOpener::new(KEY, PREFIX, [0; 8], FrameDirection::ClientToServer);
        assert_eq!(wrong_session.open(&frame), Err(FrameError::SessionMismatch));

        let mut wrong_direction = FrameOpener::new(KEY, PREFIX, SESSION, FrameDirection::ServerToClient);
        assert_eq!(wrong_direction.open(&frame), Err(FrameError::DirectionMismatch));
    }

    #[test]
    fn accepts_out_of_order_packets_inside_window() {
        let (mut sealer, mut opener) = pair();
        let frames: Vec<_> = (0..4).map(|_| sealer.seal(b"x").unwrap()).collect();
        assert_eq!(opener.open(&frames[3]).unwrap(), b"x");
        assert_eq!(opener.open(&frames[0]).unwrap(), b"x");
        assert_eq!(opener.open(&frames[2]).unwrap(), b"x");
        assert_eq!(opener.open(&frames[1]).unwrap(), b"x");
    }

    #[test]
    fn authentication_failure_does_not_consume_sequence() {
        let (mut sealer, _) = pair();
        let frame = sealer.seal(b"payload").unwrap();
        let mut opener = pair().1;
        let mut corrupt = frame.clone();
        *corrupt.last_mut().unwrap() ^= 0x80;
        assert_eq!(opener.open(&corrupt), Err(FrameError::AuthenticationFailed));
        assert_eq!(opener.open(&frame).unwrap(), b"payload");
    }

    #[test]
    fn rejects_oversized_payload() {
        let (mut sealer, _) = pair();
        let payload = vec![0; MAX_PROTECTED_PAYLOAD_SIZE + 1];
        assert_eq!(sealer.seal(&payload), Err(FrameError::PayloadTooLarge));
    }
}
