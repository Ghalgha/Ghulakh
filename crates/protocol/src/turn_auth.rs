//! Bounded parser for TURN long-term authentication challenges.
//!
//! This module only extracts a bounded 401/438 challenge. It deliberately does
//! not derive keys or decide which password algorithm a remote service uses.

use crate::stun::{
    StunAttribute, StunClass, StunMessage, ATTR_ERROR_CODE, ATTR_NONCE, ATTR_PASSWORD_ALGORITHMS, ATTR_REALM,
};
use crate::turn_password::parse_password_algorithms;

const MAX_CHALLENGE_TEXT: usize = 763;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TurnChallenge {
    pub code: u16,
    pub realm: String,
    pub nonce: String,
    /// Raw server offer retained for the authenticated follow-up request.
    /// RFC 8489 requires echoing this attribute to prevent algorithm downgrade.
    pub password_algorithms: Option<Vec<u8>>,
}

impl TurnChallenge {
    pub fn password_algorithms_attribute(&self) -> Option<StunAttribute> {
        self.password_algorithms.as_ref().map(|value| StunAttribute {
            kind: ATTR_PASSWORD_ALGORITHMS,
            value: value.clone(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TurnAuthError {
    #[error("challenge must be a TURN error response for the expected method")]
    UnexpectedResponse,
    #[error("challenge contains a duplicate required attribute")]
    DuplicateAttribute,
    #[error("challenge is missing a required attribute")]
    MissingAttribute,
    #[error("challenge error code is malformed")]
    InvalidErrorCode,
    #[error("challenge code is not 401 or 438")]
    UnsupportedChallengeCode,
    #[error("challenge text is empty, oversized, or not UTF-8")]
    InvalidChallengeText,
    #[error("PASSWORD-ALGORITHMS attribute is malformed or duplicated")]
    InvalidPasswordAlgorithms,
}

fn unique_attribute(message: &StunMessage, kind: u16) -> Result<&[u8], TurnAuthError> {
    let mut found = message.attributes.iter().filter(|attr| attr.kind == kind);
    let first = found.next().ok_or(TurnAuthError::MissingAttribute)?;
    if found.next().is_some() {
        return Err(TurnAuthError::DuplicateAttribute);
    }
    Ok(&first.value)
}

fn challenge_text(bytes: &[u8]) -> Result<String, TurnAuthError> {
    if bytes.is_empty() || bytes.len() > MAX_CHALLENGE_TEXT {
        return Err(TurnAuthError::InvalidChallengeText);
    }
    let text = std::str::from_utf8(bytes).map_err(|_| TurnAuthError::InvalidChallengeText)?;
    if text.chars().any(char::is_control) {
        return Err(TurnAuthError::InvalidChallengeText);
    }
    Ok(text.to_owned())
}

/// Parse a TURN 401 (initial authentication) or 438 (stale nonce) response.
/// The caller must additionally match the transaction ID and source endpoint
/// against the outstanding request before accepting this challenge.
pub fn parse_turn_challenge(
    message: &StunMessage,
    expected_method: u16,
) -> Result<TurnChallenge, TurnAuthError> {
    if message.class != StunClass::ErrorResponse || message.method != expected_method {
        return Err(TurnAuthError::UnexpectedResponse);
    }
    let error = unique_attribute(message, ATTR_ERROR_CODE)?;
    if error.len() < 4 || error[0] != 0 || error[1] != 0 || error[2] & 0xF8 != 0 {
        return Err(TurnAuthError::InvalidErrorCode);
    }
    let class = u16::from(error[2] & 0x07);
    let number = u16::from(error[3]);
    if !(3..=6).contains(&class) || number > 99 {
        return Err(TurnAuthError::InvalidErrorCode);
    }
    let code = class * 100 + number;
    if code != 401 && code != 438 {
        return Err(TurnAuthError::UnsupportedChallengeCode);
    }
    let realm = challenge_text(unique_attribute(message, ATTR_REALM)?)?;
    let nonce = challenge_text(unique_attribute(message, ATTR_NONCE)?)?;
    let password_algorithms = match message.attributes.iter()
        .filter(|attribute| attribute.kind == ATTR_PASSWORD_ALGORITHMS)
        .collect::<Vec<_>>().as_slice()
    {
        [] => None,
        [attribute] => {
            parse_password_algorithms(&attribute.value)
                .map_err(|_| TurnAuthError::InvalidPasswordAlgorithms)?;
            Some(attribute.value.clone())
        }
        _ => return Err(TurnAuthError::InvalidPasswordAlgorithms),
    };
    Ok(TurnChallenge { code, realm, nonce, password_algorithms })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stun::{StunAttribute, StunClass, METHOD_ALLOCATE};

    fn challenge(code: u16) -> StunMessage {
        StunMessage {
            method: METHOD_ALLOCATE,
            class: StunClass::ErrorResponse,
            transaction_id: [0x31; 12],
            attributes: vec![
                StunAttribute { kind: ATTR_ERROR_CODE, value: vec![0, 0, (code / 100) as u8, (code % 100) as u8] },
                StunAttribute { kind: ATTR_REALM, value: b"turn.example.invalid".to_vec() },
                StunAttribute { kind: ATTR_NONCE, value: b"opaque-server-nonce".to_vec() },
            ],
        }
    }

    #[test]
    fn parses_401_and_438_challenges() {
        for code in [401, 438] {
            let parsed = parse_turn_challenge(&challenge(code), METHOD_ALLOCATE).unwrap();
            assert_eq!(parsed.code, code);
            assert_eq!(parsed.realm, "turn.example.invalid");
            assert_eq!(parsed.nonce, "opaque-server-nonce");
            assert_eq!(parsed.password_algorithms, None);
        }
    }

    #[test]
    fn rejects_wrong_method_or_class() {
        assert_eq!(
            parse_turn_challenge(&challenge(401), crate::stun::METHOD_REFRESH),
            Err(TurnAuthError::UnexpectedResponse)
        );
        let mut response = challenge(401);
        response.class = StunClass::SuccessResponse;
        assert_eq!(
            parse_turn_challenge(&response, METHOD_ALLOCATE),
            Err(TurnAuthError::UnexpectedResponse)
        );
    }

    #[test]
    fn rejects_duplicate_and_missing_attributes() {
        let mut duplicate = challenge(401);
        duplicate.attributes.push(duplicate.attributes[1].clone());
        assert_eq!(
            parse_turn_challenge(&duplicate, METHOD_ALLOCATE),
            Err(TurnAuthError::DuplicateAttribute)
        );
        let mut missing = challenge(401);
        missing.attributes.pop();
        assert_eq!(
            parse_turn_challenge(&missing, METHOD_ALLOCATE),
            Err(TurnAuthError::MissingAttribute)
        );
    }

    #[test]
    fn rejects_malformed_or_unexpected_error_codes() {
        let mut malformed = challenge(401);
        malformed.attributes[0].value[0] = 1;
        assert_eq!(
            parse_turn_challenge(&malformed, METHOD_ALLOCATE),
            Err(TurnAuthError::InvalidErrorCode)
        );
        assert_eq!(
            parse_turn_challenge(&challenge(403), METHOD_ALLOCATE),
            Err(TurnAuthError::UnsupportedChallengeCode)
        );
    }

    #[test]
    fn rejects_invalid_challenge_text() {
        let mut invalid = challenge(401);
        invalid.attributes[1].value = vec![0xff];
        assert_eq!(
            parse_turn_challenge(&invalid, METHOD_ALLOCATE),
            Err(TurnAuthError::InvalidChallengeText)
        );
    }
}
