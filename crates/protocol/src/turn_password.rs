//! Bounded parsing and selection for RFC 8489 password-algorithm attributes.
//!
//! This module does not derive credential keys. The selected algorithm must be
//! explicitly confirmed by the TURN service profile before an auth provider uses it.

use std::collections::HashSet;

use crate::stun::{StunAttribute, ATTR_PASSWORD_ALGORITHM, ATTR_PASSWORD_ALGORITHMS};

pub const PASSWORD_ALGORITHM_MD5: u16 = 0x0001;
pub const PASSWORD_ALGORITHM_SHA256: u16 = 0x0002;
const MAX_ALGORITHMS: usize = 16;
const MAX_PARAMETERS_LEN: usize = 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasswordAlgorithm {
    pub id: u16,
    pub parameters: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasswordAlgorithmId {
    Md5,
    Sha256,
}

impl PasswordAlgorithmId {
    pub const fn wire_id(self) -> u16 {
        match self {
            Self::Md5 => PASSWORD_ALGORITHM_MD5,
            Self::Sha256 => PASSWORD_ALGORITHM_SHA256,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PasswordAlgorithmError {
    #[error("password algorithm attribute is empty or malformed")]
    InvalidEncoding,
    #[error("password algorithm list contains too many entries")]
    TooManyAlgorithms,
    #[error("password algorithm list contains a duplicate identifier")]
    DuplicateAlgorithm,
    #[error("password algorithm parameters exceed the configured limit")]
    ParametersTooLarge,
    #[error("server offered no mutually supported password algorithm")]
    NoCommonAlgorithm,
}

fn parse_entries(input: &[u8]) -> Result<Vec<PasswordAlgorithm>, PasswordAlgorithmError> {
    if input.is_empty() {
        return Err(PasswordAlgorithmError::InvalidEncoding);
    }
    let mut entries = Vec::new();
    let mut seen = HashSet::new();
    let mut offset = 0usize;
    while offset < input.len() {
        if input.len() - offset < 4 {
            return Err(PasswordAlgorithmError::InvalidEncoding);
        }
        if entries.len() == MAX_ALGORITHMS {
            return Err(PasswordAlgorithmError::TooManyAlgorithms);
        }
        let id = u16::from_be_bytes([input[offset], input[offset + 1]]);
        let parameter_len = usize::from(u16::from_be_bytes([input[offset + 2], input[offset + 3]]));
        if parameter_len > MAX_PARAMETERS_LEN {
            return Err(PasswordAlgorithmError::ParametersTooLarge);
        }
        let value_start = offset + 4;
        let value_end = value_start.checked_add(parameter_len)
            .ok_or(PasswordAlgorithmError::InvalidEncoding)?;
        let padded_end = value_start.checked_add((parameter_len + 3) & !3)
            .ok_or(PasswordAlgorithmError::InvalidEncoding)?;
        if padded_end > input.len() || value_end > input.len() {
            return Err(PasswordAlgorithmError::InvalidEncoding);
        }
        if !seen.insert(id) {
            return Err(PasswordAlgorithmError::DuplicateAlgorithm);
        }
        entries.push(PasswordAlgorithm {
            id,
            parameters: input[value_start..value_end].to_vec(),
        });
        offset = padded_end;
    }
    Ok(entries)
}

/// Parse PASSWORD-ALGORITHMS, preserving unknown algorithm IDs for safe negotiation.
pub fn parse_password_algorithms(input: &[u8]) -> Result<Vec<PasswordAlgorithm>, PasswordAlgorithmError> {
    parse_entries(input)
}

/// Parse the single PASSWORD-ALGORITHM value selected for an authenticated request.
pub fn parse_password_algorithm(input: &[u8]) -> Result<PasswordAlgorithm, PasswordAlgorithmError> {
    let mut entries = parse_entries(input)?;
    if entries.len() != 1 {
        return Err(PasswordAlgorithmError::InvalidEncoding);
    }
    Ok(entries.remove(0))
}

/// Select SHA-256 when offered; otherwise select MD5 if offered.
/// The caller must still validate that this profile is supported by its service.
pub fn select_password_algorithm(
    offered: &[PasswordAlgorithm],
) -> Result<PasswordAlgorithmId, PasswordAlgorithmError> {
    if offered.iter().any(|entry| entry.id == PASSWORD_ALGORITHM_SHA256) {
        return Ok(PasswordAlgorithmId::Sha256);
    }
    if offered.iter().any(|entry| entry.id == PASSWORD_ALGORITHM_MD5) {
        return Ok(PasswordAlgorithmId::Md5);
    }
    Err(PasswordAlgorithmError::NoCommonAlgorithm)
}

/// Encode a selected algorithm attribute with zero-length parameters.
pub fn password_algorithm_attribute(selected: PasswordAlgorithmId) -> StunAttribute {
    let mut value = Vec::with_capacity(4);
    value.extend_from_slice(&selected.wire_id().to_be_bytes());
    value.extend_from_slice(&0u16.to_be_bytes());
    StunAttribute { kind: ATTR_PASSWORD_ALGORITHM, value }
}

/// Build the attribute carrying the server's offered algorithm list.
pub fn password_algorithms_attribute(
    algorithms: &[PasswordAlgorithm],
) -> Result<StunAttribute, PasswordAlgorithmError> {
    if algorithms.is_empty() {
        return Err(PasswordAlgorithmError::InvalidEncoding);
    }
    if algorithms.len() > MAX_ALGORITHMS {
        return Err(PasswordAlgorithmError::TooManyAlgorithms);
    }
    let mut value = Vec::new();
    let mut seen = HashSet::new();
    for algorithm in algorithms {
        if algorithm.parameters.len() > MAX_PARAMETERS_LEN
            || algorithm.parameters.len() > u16::MAX as usize
        {
            return Err(PasswordAlgorithmError::ParametersTooLarge);
        }
        if !seen.insert(algorithm.id) {
            return Err(PasswordAlgorithmError::DuplicateAlgorithm);
        }
        value.extend_from_slice(&algorithm.id.to_be_bytes());
        value.extend_from_slice(&(algorithm.parameters.len() as u16).to_be_bytes());
        value.extend_from_slice(&algorithm.parameters);
        value.resize(value.len() + ((4 - algorithm.parameters.len() % 4) % 4), 0);
    }
    Ok(StunAttribute { kind: ATTR_PASSWORD_ALGORITHMS, value })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_known_and_unknown_algorithms() {
        let value = vec![
            0, 1, 0, 0,
            0, 2, 0, 0,
            0x7f, 0xff, 0, 2, 0xaa, 0xbb, 0, 0,
        ];
        let parsed = parse_password_algorithms(&value).unwrap();
        assert_eq!(parsed.len(), 3);
        assert_eq!(parsed[2].parameters, [0xaa, 0xbb]);
        assert_eq!(select_password_algorithm(&parsed), Ok(PasswordAlgorithmId::Sha256));
    }

    #[test]
    fn prefers_sha256_and_falls_back_to_md5() {
        assert_eq!(
            select_password_algorithm(&[PasswordAlgorithm { id: PASSWORD_ALGORITHM_MD5, parameters: vec![] }]),
            Ok(PasswordAlgorithmId::Md5)
        );
        assert_eq!(
            select_password_algorithm(&[
                PasswordAlgorithm { id: PASSWORD_ALGORITHM_MD5, parameters: vec![] },
                PasswordAlgorithm { id: PASSWORD_ALGORITHM_SHA256, parameters: vec![] },
            ]),
            Ok(PasswordAlgorithmId::Sha256)
        );
    }

    #[test]
    fn rejects_malformed_duplicate_and_oversized_lists() {
        assert_eq!(parse_password_algorithms(&[]), Err(PasswordAlgorithmError::InvalidEncoding));
        assert_eq!(parse_password_algorithms(&[0, 1, 0]), Err(PasswordAlgorithmError::InvalidEncoding));
        assert_eq!(
            parse_password_algorithms(&[0, 1, 0, 0, 0, 1, 0, 0]),
            Err(PasswordAlgorithmError::DuplicateAlgorithm)
        );
        assert_eq!(
            parse_password_algorithms(&[0, 1, 4, 1]),
            Err(PasswordAlgorithmError::ParametersTooLarge)
        );
    }

    #[test]
    fn round_trips_selected_attribute() {
        let attribute = password_algorithm_attribute(PasswordAlgorithmId::Sha256);
        assert_eq!(attribute.kind, ATTR_PASSWORD_ALGORITHM);
        assert_eq!(
            parse_password_algorithm(&attribute.value),
            Ok(PasswordAlgorithm { id: PASSWORD_ALGORITHM_SHA256, parameters: vec![] })
        );
    }

    #[test]
    fn encodes_offered_algorithm_list() {
        let attribute = password_algorithms_attribute(&[
            PasswordAlgorithm { id: PASSWORD_ALGORITHM_MD5, parameters: vec![] },
            PasswordAlgorithm { id: PASSWORD_ALGORITHM_SHA256, parameters: vec![] },
        ]).unwrap();
        assert_eq!(attribute.kind, ATTR_PASSWORD_ALGORITHMS);
        assert_eq!(parse_password_algorithms(&attribute.value).unwrap().len(), 2);
    }
}
