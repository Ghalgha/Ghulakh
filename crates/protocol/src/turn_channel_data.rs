//! UDP TURN ChannelData framing (RFC 8656).
//!
//! This codec handles only the ChannelData envelope. Channel-to-peer binding,
//! allocation state, and authenticated ChannelBind transactions are managed
//! separately.

pub const CHANNEL_NUMBER_MIN: u16 = 0x4000;
pub const CHANNEL_NUMBER_MAX: u16 = 0x4fff;
pub const CHANNEL_DATA_HEADER_LEN: usize = 4;
pub const MAX_UDP_CHANNEL_DATA_PAYLOAD: usize = 65_503;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChannelData<'a> {
    pub channel_number: u16,
    pub data: &'a [u8],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ChannelDataError {
    #[error("channel number is outside 0x4000..=0x4fff")]
    InvalidChannelNumber,
    #[error("ChannelData header is truncated")]
    Truncated,
    #[error("ChannelData payload length does not match the datagram")]
    InvalidLength,
    #[error("ChannelData payload exceeds the UDP datagram limit")]
    PayloadTooLarge,
}

/// Encode a ChannelData message for UDP. UDP ChannelData is not padded.
pub fn encode_channel_data(channel_number: u16, data: &[u8]) -> Result<Vec<u8>, ChannelDataError> {
    if !(CHANNEL_NUMBER_MIN..=CHANNEL_NUMBER_MAX).contains(&channel_number) {
        return Err(ChannelDataError::InvalidChannelNumber);
    }
    if data.len() > MAX_UDP_CHANNEL_DATA_PAYLOAD || data.len() > u16::MAX as usize {
        return Err(ChannelDataError::PayloadTooLarge);
    }
    let mut output = Vec::with_capacity(CHANNEL_DATA_HEADER_LEN + data.len());
    output.extend_from_slice(&channel_number.to_be_bytes());
    output.extend_from_slice(&(data.len() as u16).to_be_bytes());
    output.extend_from_slice(data);
    Ok(output)
}

/// Decode a complete UDP ChannelData datagram, allowing optional 0–3 byte padding.
pub fn decode_channel_data(input: &[u8]) -> Result<ChannelData<'_>, ChannelDataError> {
    if input.len() < CHANNEL_DATA_HEADER_LEN {
        return Err(ChannelDataError::Truncated);
    }
    let channel_number = u16::from_be_bytes([input[0], input[1]]);
    if !(CHANNEL_NUMBER_MIN..=CHANNEL_NUMBER_MAX).contains(&channel_number) {
        return Err(ChannelDataError::InvalidChannelNumber);
    }
    let declared_len = usize::from(u16::from_be_bytes([input[2], input[3]]));
    if declared_len > MAX_UDP_CHANNEL_DATA_PAYLOAD {
        return Err(ChannelDataError::PayloadTooLarge);
    }
    let unpadded_len = CHANNEL_DATA_HEADER_LEN + declared_len;
    let padded_len = (unpadded_len + 3) & !3;
    if input.len() != unpadded_len && input.len() != padded_len {
        return Err(ChannelDataError::InvalidLength);
    }
    Ok(ChannelData {
        channel_number,
        data: &input[CHANNEL_DATA_HEADER_LEN..],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_preserves_channel_and_payload() {
        let encoded = encode_channel_data(0x4001, b"protected tunnel frame").unwrap();
        let decoded = decode_channel_data(&encoded).unwrap();
        assert_eq!(decoded.channel_number, 0x4001);
        assert_eq!(decoded.data, b"protected tunnel frame");
    }

    #[test]
    fn accepts_empty_payload() {
        let encoded = encode_channel_data(0x4fff, &[]).unwrap();
        assert_eq!(decode_channel_data(&encoded).unwrap().data, &[]);
    }

    #[test]
    fn rejects_invalid_channel_numbers() {
        assert_eq!(encode_channel_data(0x3fff, b"x"), Err(ChannelDataError::InvalidChannelNumber));
        assert_eq!(decode_channel_data(&[0x3f, 0xff, 0, 1, 1]), Err(ChannelDataError::InvalidChannelNumber));
        assert_eq!(decode_channel_data(&[0x50, 0, 0, 1, 1]), Err(ChannelDataError::InvalidChannelNumber));
        assert_eq!(decode_channel_data(&[0x80, 0, 0, 1, 1]), Err(ChannelDataError::InvalidChannelNumber));
    }

    #[test]
    fn rejects_truncated_and_mismatched_lengths() {
        assert_eq!(decode_channel_data(&[0x40, 0, 0]), Err(ChannelDataError::Truncated));
        assert_eq!(decode_channel_data(&[0x40, 0, 0, 2, 1]), Err(ChannelDataError::InvalidLength));
        assert_eq!(decode_channel_data(&[0x40, 0, 0, 1, 1, 0]), Err(ChannelDataError::InvalidLength));
    }

    #[test]
    fn accepts_optional_udp_padding() {
        let encoded = [0x40, 0x01, 0, 1, 0xaa, 0, 0, 0];
        let decoded = decode_channel_data(&encoded).unwrap();
        assert_eq!(decoded.channel_number, 0x4001);
        assert_eq!(decoded.data, &[0xaa]);
    }

    #[test]
    fn rejects_payload_larger_than_udp_limit() {
        let oversized = vec![0; MAX_UDP_CHANNEL_DATA_PAYLOAD + 1];
        assert_eq!(
            encode_channel_data(0x4001, &oversized),
            Err(ChannelDataError::PayloadTooLarge)
        );
    }
}
