//! TURN long-term authentication message protection.
//!
//! This module deliberately accepts an integrity key from an explicitly
//! configured service profile. It does not derive that key from VK credentials.

use ghulakh_protocol::stun::{
    append_message_integrity, append_message_integrity_sha256,
    verify_message_integrity, verify_message_integrity_sha256,
    StunClass, StunMessage, StunAttribute,
    ATTR_USERNAME, ATTR_REALM, ATTR_NONCE, ATTR_MESSAGE_INTEGRITY,
    ATTR_MESSAGE_INTEGRITY_SHA256,
};
use ghulakh_protocol::turn_password::{
    parse_password_algorithms, password_algorithm_attribute, PasswordAlgorithmId,
};
use zeroize::Zeroizing;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TurnIntegrityAlgorithm {
    Sha1,
    Sha256,
}

#[derive(Debug, thiserror::Error)]
pub enum TurnAuthError {
    #[error("TURN auth field is empty, too long, or contains a control character")]
    InvalidField,
    #[error("TURN request has an invalid class or pre-existing auth attributes")]
    InvalidRequest,
    #[error("TURN response has an invalid class or integrity attribute layout")]
    InvalidResponse,
    #[error("TURN MESSAGE-INTEGRITY verification failed")]
    IntegrityFailure,
    #[error("TURN password-algorithm profile is inconsistent or unsupported")]
    InvalidPasswordProfile,
    #[error("TURN STUN codec failed: {0}")]
    Codec(#[from] ghulakh_protocol::stun::StunError),
}

/// Immutable authentication context for one credential/nonce generation.
/// Recreate it when VK Calls credentials or the TURN nonce changes.
pub struct TurnAuthContext {
    username: Zeroizing<String>,
    realm: Zeroizing<String>,
    nonce: Zeroizing<String>,
    integrity_key: Zeroizing<Vec<u8>>,
    algorithm: TurnIntegrityAlgorithm,
    password_algorithm: Option<PasswordAlgorithmId>,
    password_algorithms: Option<Vec<u8>>,
}

impl TurnAuthContext {
    /// Construct the legacy SHA-1 integrity profile without password-algorithm
    /// negotiation. RFC 8489 SHA-256 profiles must use new_with_password_profile.
    pub fn new(
        username: String,
        realm: String,
        nonce: String,
        integrity_key: Vec<u8>,
        algorithm: TurnIntegrityAlgorithm,
    ) -> Result<Self, TurnAuthError> {
        if algorithm != TurnIntegrityAlgorithm::Sha1 {
            return Err(TurnAuthError::InvalidPasswordProfile);
        }
        for value in [&username, &realm, &nonce] {
            if value.is_empty()
                || value.len() > 763
                || value.chars().any(char::is_control)
            {
                return Err(TurnAuthError::InvalidField);
            }
        }
        if integrity_key.is_empty() || integrity_key.len() > 1024 {
            return Err(TurnAuthError::InvalidField);
        }
        Self::new_with_password_profile(
            username, realm, nonce, integrity_key, algorithm, None, None,
        )
    }

    /// Construct an explicitly negotiated RFC 8489 long-term credential profile.
    ///
    /// The exact raw PASSWORD-ALGORITHMS value from the matching challenge is
    /// echoed unchanged to prevent algorithm-list downgrade. The selected
    /// password algorithm is separate from the MESSAGE-INTEGRITY HMAC algorithm.
    pub fn new_with_password_profile(
        username: String,
        realm: String,
        nonce: String,
        integrity_key: Vec<u8>,
        algorithm: TurnIntegrityAlgorithm,
        password_algorithm: Option<PasswordAlgorithmId>,
        password_algorithms: Option<Vec<u8>>,
    ) -> Result<Self, TurnAuthError> {
        for value in [&username, &realm, &nonce] {
            if value.is_empty()
                || value.len() > 763
                || value.chars().any(char::is_control)
            {
                return Err(TurnAuthError::InvalidField);
            }
        }
        if integrity_key.is_empty() || integrity_key.len() > 1024 {
            return Err(TurnAuthError::InvalidField);
        }
        match (&password_algorithm, &password_algorithms) {
            (Some(selected), Some(offered)) => {
                let parsed = parse_password_algorithms(offered)
                    .map_err(|_| TurnAuthError::InvalidPasswordProfile)?;
                if !parsed.iter().any(|entry| entry.id == selected.wire_id())
                    || algorithm != TurnIntegrityAlgorithm::Sha256
                {
                    return Err(TurnAuthError::InvalidPasswordProfile);
                }
            }
            (Some(_), None) if algorithm == TurnIntegrityAlgorithm::Sha256 => {}
            (Some(_), None) | (None, Some(_)) => {
                return Err(TurnAuthError::InvalidPasswordProfile);
            }
            (None, None) if algorithm == TurnIntegrityAlgorithm::Sha1 => {}
            (None, None) => return Err(TurnAuthError::InvalidPasswordProfile),
        }
        Ok(Self {
            username: Zeroizing::new(username),
            realm: Zeroizing::new(realm),
            nonce: Zeroizing::new(nonce),
            integrity_key: Zeroizing::new(integrity_key),
            algorithm,
            password_algorithm,
            password_algorithms,
        })
    }

    /// Add long-term credential attributes and append MESSAGE-INTEGRITY.
    /// The caller must register/send these exact bytes as a STUN transaction.
    pub fn sign_request(&self, request: &StunMessage) -> Result<Vec<u8>, TurnAuthError> {
        if request.class != StunClass::Request
            || request.attributes.iter().any(|attribute| matches!(
                attribute.kind,
                ATTR_USERNAME | ATTR_REALM | ATTR_NONCE
                    | ATTR_MESSAGE_INTEGRITY | ATTR_MESSAGE_INTEGRITY_SHA256
            ))
        {
            return Err(TurnAuthError::InvalidRequest);
        }
        let mut authenticated = request.clone();
        authenticated.attributes.extend([
            StunAttribute { kind: ATTR_USERNAME, value: self.username.as_bytes().to_vec() },
            StunAttribute { kind: ATTR_REALM, value: self.realm.as_bytes().to_vec() },
            StunAttribute { kind: ATTR_NONCE, value: self.nonce.as_bytes().to_vec() },
        ]);
        if let Some(selected) = self.password_algorithm {
            authenticated.attributes.push(password_algorithm_attribute(selected));
        }
        if let Some(offered) = &self.password_algorithms {
            authenticated.attributes.push(StunAttribute {
                kind: ghulakh_protocol::stun::ATTR_PASSWORD_ALGORITHMS,
                value: offered.clone(),
            });
        }
        match self.algorithm {
            TurnIntegrityAlgorithm::Sha1 => {
                append_message_integrity(&authenticated, &self.integrity_key).map_err(Into::into)
            }
            TurnIntegrityAlgorithm::Sha256 => {
                append_message_integrity_sha256(&authenticated, &self.integrity_key).map_err(Into::into)
            }
        }
    }

    /// Verify a response before the caller applies any state transition.
    pub fn verify_response(&self, wire: &[u8]) -> Result<StunMessage, TurnAuthError> {
        let response = StunMessage::decode(wire)?;
        if !matches!(response.class, StunClass::SuccessResponse | StunClass::ErrorResponse) {
            return Err(TurnAuthError::InvalidResponse);
        }
        let (expected, forbidden) = match self.algorithm {
            TurnIntegrityAlgorithm::Sha1 => (ATTR_MESSAGE_INTEGRITY, ATTR_MESSAGE_INTEGRITY_SHA256),
            TurnIntegrityAlgorithm::Sha256 => (ATTR_MESSAGE_INTEGRITY_SHA256, ATTR_MESSAGE_INTEGRITY),
        };
        if response.attributes.iter().filter(|attribute| attribute.kind == expected).count() != 1
            || response.attributes.iter().any(|attribute| attribute.kind == forbidden)
        {
            return Err(TurnAuthError::InvalidResponse);
        }
        let result = match self.algorithm {
            TurnIntegrityAlgorithm::Sha1 => verify_message_integrity(wire, &self.integrity_key),
            TurnIntegrityAlgorithm::Sha256 => verify_message_integrity_sha256(wire, &self.integrity_key),
        };
        result.map_err(|_| TurnAuthError::IntegrityFailure)?;
        Ok(response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ghulakh_protocol::stun::{StunClass, StunMessage, METHOD_ALLOCATE};

    fn request() -> StunMessage {
        StunMessage {
            method: METHOD_ALLOCATE,
            class: StunClass::Request,
            transaction_id: [0x31; 12],
            attributes: vec![],
        }
    }

    fn context(algorithm: TurnIntegrityAlgorithm) -> TurnAuthContext {
        match algorithm {
            TurnIntegrityAlgorithm::Sha1 => TurnAuthContext::new(
                "temporary-user".into(),
                "turn.example".into(),
                "nonce-value".into(),
                vec![0x5a; 32],
                algorithm,
            ).unwrap(),
            TurnIntegrityAlgorithm::Sha256 => TurnAuthContext::new_with_password_profile(
                "temporary-user".into(),
                "turn.example".into(),
                "nonce-value".into(),
                vec![0x5a; 32],
                algorithm,
                Some(PasswordAlgorithmId::Sha256),
                Some(vec![0, 1, 0, 0, 0, 2, 0, 0]),
            ).unwrap(),
        }
    }

    #[test]
    fn signs_and_verifies_sha1_response() {
        let auth = context(TurnIntegrityAlgorithm::Sha1);
        let wire = auth.sign_request(&request()).unwrap();
        let signed = StunMessage::decode(&wire).unwrap();
        let response = StunMessage {
            method: signed.method,
            class: StunClass::SuccessResponse,
            transaction_id: signed.transaction_id,
            attributes: vec![],
        };
        let response_wire = append_message_integrity(&response, &[0x5a; 32]).unwrap();
        assert_eq!(auth.verify_response(&response_wire).unwrap(), response);
    }

    #[test]
    fn signs_and_verifies_sha256_response() {
        let auth = context(TurnIntegrityAlgorithm::Sha256);
        let wire = auth.sign_request(&request()).unwrap();
        let signed = StunMessage::decode(&wire).unwrap();
        assert_eq!(
            signed.attribute(ghulakh_protocol::stun::ATTR_PASSWORD_ALGORITHM).unwrap(),
            &[0, 2, 0, 0]
        );
        assert_eq!(
            signed.attribute(ghulakh_protocol::stun::ATTR_PASSWORD_ALGORITHMS).unwrap(),
            &[0, 1, 0, 0, 0, 2, 0, 0]
        );
        let response = StunMessage {
            method: signed.method,
            class: StunClass::SuccessResponse,
            transaction_id: signed.transaction_id,
            attributes: vec![],
        };
        let response_wire = append_message_integrity_sha256(&response, &[0x5a; 32]).unwrap();
        assert_eq!(auth.verify_response(&response_wire).unwrap(), response);
    }


    #[test]
    fn rejects_password_algorithm_downgrade_or_mismatched_offer() {
        let offer = vec![0, 1, 0, 0, 0, 2, 0, 0];
        assert!(matches!(
            TurnAuthContext::new_with_password_profile(
                "user".into(), "realm".into(), "nonce".into(), vec![1; 32],
                TurnIntegrityAlgorithm::Sha1,
                Some(PasswordAlgorithmId::Sha256), Some(offer.clone()),
            ),
            Err(TurnAuthError::InvalidPasswordProfile)
        ));
        assert!(matches!(
            TurnAuthContext::new_with_password_profile(
                "user".into(), "realm".into(), "nonce".into(), vec![1; 32],
                TurnIntegrityAlgorithm::Sha256,
                Some(PasswordAlgorithmId::Md5), Some(vec![0, 2, 0, 0]),
            ),
            Err(TurnAuthError::InvalidPasswordProfile)
        ));
    }

    #[test]
    fn rejects_tampering_and_wrong_response_class() {
        let auth = context(TurnIntegrityAlgorithm::Sha1);
        let response = StunMessage {
            method: METHOD_ALLOCATE,
            class: StunClass::SuccessResponse,
            transaction_id: [0x31; 12],
            attributes: vec![],
        };
        let mut wire = append_message_integrity(&response, &[0x5a; 32]).unwrap();
        *wire.last_mut().unwrap() ^= 1;
        assert!(matches!(auth.verify_response(&wire), Err(TurnAuthError::IntegrityFailure)));
        let indication = StunMessage { class: StunClass::Indication, ..response };
        let indication_wire = indication.encode().unwrap();
        assert!(matches!(auth.verify_response(&indication_wire), Err(TurnAuthError::InvalidResponse)));
    }

    #[test]
    fn rejects_duplicate_or_preexisting_auth_attributes() {
        let auth = context(TurnIntegrityAlgorithm::Sha1);
        let mut invalid = request();
        invalid.attributes.push(StunAttribute { kind: ATTR_USERNAME, value: b"forged".to_vec() });
        assert!(matches!(auth.sign_request(&invalid), Err(TurnAuthError::InvalidRequest)));
    }

    #[test]
    fn requires_explicit_profile_for_sha256() {
        assert!(matches!(
            TurnAuthContext::new(
                "user".into(), "realm".into(), "nonce".into(), vec![1; 32],
                TurnIntegrityAlgorithm::Sha256,
            ),
            Err(TurnAuthError::InvalidPasswordProfile)
        ));
    }

    #[test]
    fn rejects_empty_and_control_character_fields() {
        assert!(TurnAuthContext::new("".into(), "realm".into(), "nonce".into(), vec![1], TurnIntegrityAlgorithm::Sha1).is_err());
        assert!(TurnAuthContext::new("user".into(), "realm".into(), "bad\nnonce".into(), vec![1], TurnIntegrityAlgorithm::Sha1).is_err());
    }
}
