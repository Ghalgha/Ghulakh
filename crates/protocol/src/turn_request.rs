//! TURN request construction and success-response parsing.
//!
//! Authentication is deliberately external: callers add the negotiated
//! USERNAME/REALM/NONCE and MESSAGE-INTEGRITY attributes after constructing
//! a request, and MUST verify response integrity before parsing success state.

use std::net::SocketAddr;

use crate::stun::{
    decode_xor_address, encode_xor_address, StunAttribute, StunClass, StunMessage,
    ATTR_CHANNEL_NUMBER, ATTR_LIFETIME, ATTR_REQUESTED_TRANSPORT,
    ATTR_XOR_PEER_ADDRESS, ATTR_XOR_RELAYED_ADDRESS,
    METHOD_ALLOCATE, METHOD_CHANNEL_BIND, METHOD_CREATE_PERMISSION, METHOD_REFRESH,
};

const UDP_PROTOCOL_NUMBER: u8 = 17;
const MIN_CHANNEL_NUMBER: u16 = 0x4000;
const MAX_CHANNEL_NUMBER: u16 = 0x4fff;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TurnRequestError {
    #[error("peer list must contain at least one address")]
    EmptyPeerList,
    #[error("peer addresses must use one address family")]
    MixedPeerFamilies,
    #[error("channel number is outside the TURN range 0x4000..=0x7fff")]
    InvalidChannelNumber,
    #[error("invalid STUN attribute length or value")]
    InvalidAttribute,
    #[error("response does not match the expected successful TURN method")]
    UnexpectedResponse,
    #[error("required response attribute is missing or duplicated")]
    MissingOrDuplicateAttribute,
    #[error("invalid XOR address in TURN response")]
    InvalidAddress,
    #[error("invalid lifetime value in TURN response")]
    InvalidLifetime,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TurnSuccess {
    Allocate {
        relayed_address: SocketAddr,
        lifetime_seconds: u32,
    },
    Refresh {
        lifetime_seconds: u32,
    },
    CreatePermission,
    ChannelBind,
}

fn request(method: u16, transaction_id: [u8; 12], attributes: Vec<StunAttribute>) -> StunMessage {
    StunMessage {
        method,
        class: StunClass::Request,
        transaction_id,
        attributes,
    }
}

fn attr(kind: u16, value: Vec<u8>) -> StunAttribute {
    StunAttribute { kind, value }
}

/// Construct the mandatory UDP Allocate request. Authentication attributes and
/// MESSAGE-INTEGRITY are added by the selected TURN authentication provider.
pub fn allocate_request(transaction_id: [u8; 12]) -> StunMessage {
    request(
        METHOD_ALLOCATE,
        transaction_id,
        vec![attr(
            ATTR_REQUESTED_TRANSPORT,
            vec![UDP_PROTOCOL_NUMBER, 0, 0, 0],
        )],
    )
}

/// Construct a Refresh request. A lifetime of zero requests allocation deletion.
pub fn refresh_request(transaction_id: [u8; 12], lifetime_seconds: u32) -> StunMessage {
    request(
        METHOD_REFRESH,
        transaction_id,
        vec![attr(ATTR_LIFETIME, lifetime_seconds.to_be_bytes().to_vec())],
    )
}

/// Construct a CreatePermission request for one or more peer IP addresses.
/// TURN permissions are IP-based; the peer port is ignored by the server.
pub fn create_permission_request(
    transaction_id: [u8; 12],
    peers: &[SocketAddr],
) -> Result<StunMessage, TurnRequestError> {
    let first = peers.first().ok_or(TurnRequestError::EmptyPeerList)?;
    let family = first.ip().is_ipv4();
    if peers.iter().any(|peer| peer.ip().is_ipv4() != family) {
        return Err(TurnRequestError::MixedPeerFamilies);
    }
    let attributes = peers
        .iter()
        .map(|peer| attr(ATTR_XOR_PEER_ADDRESS, encode_xor_address(SocketAddr::new(peer.ip(), 0), &transaction_id)))
        .collect();
    Ok(request(METHOD_CREATE_PERMISSION, transaction_id, attributes))
}

/// Construct a ChannelBind request. The channel number is allocated by the
/// client and must be in the range reserved by TURN for channel bindings.
pub fn channel_bind_request(
    transaction_id: [u8; 12],
    channel_number: u16,
    peer: SocketAddr,
) -> Result<StunMessage, TurnRequestError> {
    if !(MIN_CHANNEL_NUMBER..=MAX_CHANNEL_NUMBER).contains(&channel_number) {
        return Err(TurnRequestError::InvalidChannelNumber);
    }
    Ok(request(
        METHOD_CHANNEL_BIND,
        transaction_id,
        vec![
            attr(ATTR_CHANNEL_NUMBER, vec![
                (channel_number >> 8) as u8,
                channel_number as u8,
                0,
                0,
            ]),
            attr(ATTR_XOR_PEER_ADDRESS, encode_xor_address(peer, &transaction_id)),
        ],
    ))
}

fn unique_attribute(
    message: &StunMessage,
    kind: u16,
) -> Result<&[u8], TurnRequestError> {
    let mut matches = message.attributes.iter().filter(|a| a.kind == kind);
    let first = matches.next().ok_or(TurnRequestError::MissingOrDuplicateAttribute)?;
    if matches.next().is_some() {
        return Err(TurnRequestError::MissingOrDuplicateAttribute);
    }
    Ok(&first.value)
}

fn lifetime(message: &StunMessage) -> Result<u32, TurnRequestError> {
    let value = unique_attribute(message, ATTR_LIFETIME)?;
    if value.len() != 4 {
        return Err(TurnRequestError::InvalidLifetime);
    }
    Ok(u32::from_be_bytes(value.try_into().map_err(|_| TurnRequestError::InvalidLifetime)?))
}

/// Parse a successful response for a previously issued request.
///
/// The caller MUST first match transaction ID, method and source endpoint, and
/// verify MESSAGE-INTEGRITY using the negotiated TURN authentication profile.
/// This function is a structural parser, not an authentication boundary.
pub fn parse_success_response(
    response: &StunMessage,
    expected_method: u16,
) -> Result<TurnSuccess, TurnRequestError> {
    if response.class != StunClass::SuccessResponse || response.method != expected_method {
        return Err(TurnRequestError::UnexpectedResponse);
    }
    match expected_method {
        METHOD_ALLOCATE => {
            let relayed = unique_attribute(response, ATTR_XOR_RELAYED_ADDRESS)?;
            let relayed_address = decode_xor_address(relayed, &response.transaction_id)
                .map_err(|_| TurnRequestError::InvalidAddress)?;
            let lifetime_seconds = lifetime(response)?;
            Ok(TurnSuccess::Allocate { relayed_address, lifetime_seconds })
        }
        METHOD_REFRESH => Ok(TurnSuccess::Refresh {
            lifetime_seconds: lifetime(response)?,
        }),
        METHOD_CREATE_PERMISSION => Ok(TurnSuccess::CreatePermission),
        METHOD_CHANNEL_BIND => Ok(TurnSuccess::ChannelBind),
        _ => Err(TurnRequestError::UnexpectedResponse),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    fn id() -> [u8; 12] { [0xA5; 12] }

    #[test]
    fn allocate_requests_udp_peer_transport() {
        let message = allocate_request(id());
        assert_eq!(message.method, METHOD_ALLOCATE);
        assert_eq!(message.class, StunClass::Request);
        assert_eq!(message.attribute(ATTR_REQUESTED_TRANSPORT), Some(&[17, 0, 0, 0][..]));
    }

    #[test]
    fn refresh_supports_expiry_and_delete() {
        assert_eq!(refresh_request(id(), 600).attribute(ATTR_LIFETIME), Some(&600u32.to_be_bytes()[..]));
        assert_eq!(refresh_request(id(), 0).attribute(ATTR_LIFETIME), Some(&0u32.to_be_bytes()[..]));
    }

    #[test]
    fn create_permission_encodes_multiple_same_family_peers() {
        let peers: Vec<SocketAddr> = vec![
            "192.0.2.10:9000".parse().unwrap(),
            "192.0.2.11:9001".parse().unwrap(),
        ];
        let message = create_permission_request(id(), &peers).unwrap();
        assert_eq!(message.method, METHOD_CREATE_PERMISSION);
        assert_eq!(message.attributes.iter().filter(|a| a.kind == ATTR_XOR_PEER_ADDRESS).count(), 2);
        for (attribute, peer) in message.attributes.iter().zip(peers) {
            let decoded = decode_xor_address(&attribute.value, &id()).unwrap();
            assert_eq!(decoded.ip(), peer.ip());
            assert_eq!(decoded.port(), 0);
        }
    }

    #[test]
    fn create_permission_rejects_empty_or_mixed_families() {
        assert_eq!(create_permission_request(id(), &[]), Err(TurnRequestError::EmptyPeerList));
        let peers = vec![
            "192.0.2.1:1".parse().unwrap(),
            "[2001:db8::1]:1".parse().unwrap(),
        ];
        assert_eq!(create_permission_request(id(), &peers), Err(TurnRequestError::MixedPeerFamilies));
    }

    #[test]
    fn channel_bind_checks_range_and_encodes_channel() {
        assert_eq!(
            channel_bind_request(id(), 0x3fff, "192.0.2.1:3478".parse().unwrap()),
            Err(TurnRequestError::InvalidChannelNumber)
        );
        let message = channel_bind_request(id(), 0x4001, "192.0.2.1:3478".parse().unwrap()).unwrap();
        assert_eq!(message.method, METHOD_CHANNEL_BIND);
        assert_eq!(message.attribute(ATTR_CHANNEL_NUMBER), Some(&[0x40, 0x01, 0, 0][..]));
    }

    #[test]
    fn parses_allocate_and_refresh_success_responses() {
        let relayed: SocketAddr = "198.51.100.8:50000".parse().unwrap();
        let allocate = StunMessage {
            method: METHOD_ALLOCATE,
            class: StunClass::SuccessResponse,
            transaction_id: id(),
            attributes: vec![
                attr(ATTR_XOR_RELAYED_ADDRESS, encode_xor_address(relayed, &id())),
                attr(ATTR_LIFETIME, 600u32.to_be_bytes().to_vec()),
            ],
        };
        assert_eq!(
            parse_success_response(&allocate, METHOD_ALLOCATE),
            Ok(TurnSuccess::Allocate { relayed_address: relayed, lifetime_seconds: 600 })
        );
        let refresh = StunMessage {
            method: METHOD_REFRESH,
            class: StunClass::SuccessResponse,
            transaction_id: id(),
            attributes: vec![attr(ATTR_LIFETIME, 300u32.to_be_bytes().to_vec())],
        };
        assert_eq!(
            parse_success_response(&refresh, METHOD_REFRESH),
            Ok(TurnSuccess::Refresh { lifetime_seconds: 300 })
        );
    }

    #[test]
    fn rejects_malformed_or_unexpected_success_responses() {
        let malformed = StunMessage {
            method: METHOD_ALLOCATE,
            class: StunClass::SuccessResponse,
            transaction_id: id(),
            attributes: vec![attr(ATTR_LIFETIME, vec![1, 2])],
        };
        assert_eq!(
            parse_success_response(&malformed, METHOD_ALLOCATE),
            Err(TurnRequestError::MissingOrDuplicateAttribute)
        );
        let wrong_class = StunMessage {
            method: METHOD_ALLOCATE,
            class: StunClass::ErrorResponse,
            transaction_id: id(),
            attributes: vec![],
        };
        assert_eq!(
            parse_success_response(&wrong_class, METHOD_ALLOCATE),
            Err(TurnRequestError::UnexpectedResponse)
        );
    }

    #[test]
    fn peer_family_helper_is_stable_for_v4_v6() {
        let v4: IpAddr = "192.0.2.1".parse().unwrap();
        let v6: IpAddr = "2001:db8::1".parse().unwrap();
        assert!(v4.is_ipv4());
        assert!(v6.is_ipv6());
    }
}
