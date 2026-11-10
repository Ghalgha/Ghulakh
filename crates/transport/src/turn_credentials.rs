//! Parsing and short-lived storage for VK Calls TURN credentials.
//!
//! Credentials are deliberately separate from Ghulakh tunnel-session keys.
//! Debug output redacts both username and password; the strings are zeroized
//! when the credential object is dropped.

use std::{fmt, net::IpAddr, str::FromStr};
use zeroize::Zeroizing;

const MAX_CREDENTIAL_LEN: usize = 4096;
const MAX_TURN_URLS: usize = 16;
const MAX_URI_LEN: usize = 2048;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TurnScheme {
    Turn,
    Turns,
    Bare,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TurnWireTransport {
    Udp,
    Tcp,
    Tls,
}

#[derive(Clone, PartialEq, Eq)]
pub struct TurnEndpoint {
    pub scheme: TurnScheme,
    pub host: String,
    pub port: u16,
    pub transport: TurnWireTransport,
    /// Query parameters are retained verbatim, including unknown parameters.
    pub query: Vec<(String, String)>,
}

impl fmt::Debug for TurnEndpoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TurnEndpoint")
            .field("scheme", &self.scheme)
            .field("host", &self.host)
            .field("port", &self.port)
            .field("transport", &self.transport)
            .field("query", &"<redacted>")
            .finish()
    }
}

impl TurnEndpoint {
    pub fn socket_authority(&self) -> String {
        if self.host.contains(':') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }

    pub fn is_udp(&self) -> bool {
        self.transport == TurnWireTransport::Udp
    }

    pub fn tls_server_name(&self) -> Option<&str> {
        (self.transport == TurnWireTransport::Tls
            && IpAddr::from_str(&self.host).is_err())
        .then_some(self.host.as_str())
    }
}

pub struct TurnCredentials {
    username: Zeroizing<String>,
    password: Zeroizing<String>,
    endpoints: Vec<TurnEndpoint>,
}

impl TurnCredentials {
    pub fn username(&self) -> &str {
        self.username.as_str()
    }

    pub fn password(&self) -> &str {
        self.password.as_str()
    }

    pub fn endpoints(&self) -> &[TurnEndpoint] {
        &self.endpoints
    }

    pub fn first_udp_endpoint(&self) -> Option<&TurnEndpoint> {
        self.endpoints.iter().find(|endpoint| endpoint.is_udp())
    }

    /// Parse the VK Calls response object containing the turn_server member.
    pub fn from_vk_response_json(input: &str) -> Result<Self, TurnCredentialError> {
        if input.len() > 512 * 1024 {
            return Err(TurnCredentialError::ResponseTooLarge);
        }
        let root: serde_json::Value =
            serde_json::from_str(input).map_err(|_| TurnCredentialError::InvalidJson)?;
        let turn = root
            .get("turn_server")
            .ok_or(TurnCredentialError::MissingTurnServer)?;
        let username = turn
            .get("username")
            .and_then(serde_json::Value::as_str)
            .ok_or(TurnCredentialError::MissingUsername)?;
        let password = turn
            .get("credential")
            .and_then(serde_json::Value::as_str)
            .ok_or(TurnCredentialError::MissingCredential)?;
        validate_secret(username, TurnCredentialError::MissingUsername)?;
        validate_secret(password, TurnCredentialError::MissingCredential)?;

        let urls = turn
            .get("urls")
            .and_then(serde_json::Value::as_array)
            .ok_or(TurnCredentialError::MissingUrls)?;
        if urls.is_empty() || urls.len() > MAX_TURN_URLS {
            return Err(TurnCredentialError::InvalidUrlCount);
        }

        let mut endpoints = Vec::with_capacity(urls.len());
        for value in urls {
            let uri = value.as_str().ok_or(TurnCredentialError::InvalidTurnUri)?;
            let endpoint = parse_turn_uri(uri)?;
            if endpoints.contains(&endpoint) {
                continue;
            }
            endpoints.push(endpoint);
        }
        if endpoints.is_empty() {
            return Err(TurnCredentialError::InvalidUrlCount);
        }

        Ok(Self {
            username: Zeroizing::new(username.to_owned()),
            password: Zeroizing::new(password.to_owned()),
            endpoints,
        })
    }
}

impl fmt::Debug for TurnCredentials {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TurnCredentials")
            .field("username", &"<redacted>")
            .field("password", &"<redacted>")
            .field("endpoints", &self.endpoints)
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum TurnCredentialError {
    #[error("VK Calls response exceeds the configured size limit")]
    ResponseTooLarge,
    #[error("VK Calls response is not valid JSON")]
    InvalidJson,
    #[error("VK Calls response has no turn_server object")]
    MissingTurnServer,
    #[error("turn_server.username is missing or invalid")]
    MissingUsername,
    #[error("turn_server.credential is missing or invalid")]
    MissingCredential,
    #[error("turn_server.urls is missing")]
    MissingUrls,
    #[error("turn_server.urls has an invalid number of entries")]
    InvalidUrlCount,
    #[error("TURN URI is malformed or unsupported")]
    InvalidTurnUri,
    #[error("TURN URI has an invalid host or port")]
    InvalidAuthority,
    #[error("TURN URI contains an unsupported or duplicate transport parameter")]
    InvalidTransport,
    #[error("TURN URI contains unsupported path, userinfo or fragment components")]
    InvalidUriComponents,
}

fn validate_secret(value: &str, error: TurnCredentialError) -> Result<(), TurnCredentialError> {
    if value.is_empty() || value.len() > MAX_CREDENTIAL_LEN || value.chars().any(char::is_control) {
        return Err(error);
    }
    Ok(())
}

/// Parse RFC 7065 TURN/TURNS URIs and retain query parameters without rewriting them.
pub fn parse_turn_uri(input: &str) -> Result<TurnEndpoint, TurnCredentialError> {
    let value = input.trim();
    if value.is_empty() || value.len() > MAX_URI_LEN {
        return Err(TurnCredentialError::InvalidTurnUri);
    }

    let (scheme, mut remainder) = match value.split_once(':') {
        Some((scheme, remainder)) if scheme.eq_ignore_ascii_case("turn") => {
            (TurnScheme::Turn, remainder)
        }
        Some((scheme, remainder)) if scheme.eq_ignore_ascii_case("turns") => {
            (TurnScheme::Turns, remainder)
        }
        _ => (TurnScheme::Bare, value),
    };
    if let Some(rest) = remainder.strip_prefix("//") {
        remainder = rest;
    }

    let (authority, query) = remainder.split_once('?').unwrap_or((remainder, ""));
    if authority.is_empty()
        || authority.contains('/')
        || authority.contains('#')
        || authority.contains('@')
    {
        return Err(TurnCredentialError::InvalidUriComponents);
    }

    let (host, port) = parse_authority(authority, scheme)?;
    let mut parameters = Vec::new();
    let mut requested_transport = None;
    for part in query.split('&').filter(|part| !part.is_empty()) {
        let (key, value) = part.split_once('=').unwrap_or((part, ""));
        if key.eq_ignore_ascii_case("transport") {
            if requested_transport.is_some() {
                return Err(TurnCredentialError::InvalidTransport);
            }
            requested_transport = Some(match value.to_ascii_lowercase().as_str() {
                "udp" => TurnWireTransport::Udp,
                "tcp" => TurnWireTransport::Tcp,
                _ => return Err(TurnCredentialError::InvalidTransport),
            });
        }
        parameters.push((key.to_owned(), value.to_owned()));
    }

    let transport = match (scheme, requested_transport) {
        (TurnScheme::Turns, Some(TurnWireTransport::Udp)) => {
            return Err(TurnCredentialError::InvalidTransport);
        }
        (TurnScheme::Turns, _) => TurnWireTransport::Tls,
        (_, Some(transport)) => transport,
        (_, None) => TurnWireTransport::Udp,
    };

    Ok(TurnEndpoint {
        scheme,
        host,
        port,
        transport,
        query: parameters,
    })
}

fn parse_authority(
    authority: &str,
    scheme: TurnScheme,
) -> Result<(String, u16), TurnCredentialError> {
    let default_port = if scheme == TurnScheme::Turns { 5349 } else { 3478 };
    let (host, port) = if let Some(rest) = authority.strip_prefix('[') {
        let (host, suffix) = rest
            .split_once(']')
            .ok_or(TurnCredentialError::InvalidAuthority)?;
        if IpAddr::from_str(host).map_or(true, |address| !address.is_ipv6()) {
            return Err(TurnCredentialError::InvalidAuthority);
        }
        let port = if suffix.is_empty() {
            default_port
        } else {
            let value = suffix.strip_prefix(':').ok_or(TurnCredentialError::InvalidAuthority)?;
            parse_port(value)?
        };
        (host.to_owned(), port)
    } else {
        if authority.matches(':').count() > 1 {
            return Err(TurnCredentialError::InvalidAuthority);
        }
        match authority.rsplit_once(':') {
            Some((host, port)) => {
                if host.is_empty() {
                    return Err(TurnCredentialError::InvalidAuthority);
                }
                (host.to_owned(), parse_port(port)?)
            }
            None => (authority.to_owned(), default_port),
        }
    };

    if host.is_empty() || !valid_host(&host) {
        return Err(TurnCredentialError::InvalidAuthority);
    }
    Ok((host, port))
}

fn parse_port(value: &str) -> Result<u16, TurnCredentialError> {
    let port = value.parse::<u16>().map_err(|_| TurnCredentialError::InvalidAuthority)?;
    if port == 0 {
        return Err(TurnCredentialError::InvalidAuthority);
    }
    Ok(port)
}

fn valid_host(host: &str) -> bool {
    if host.parse::<IpAddr>().is_ok() {
        return true;
    }
    if host.len() > 253 || !host.is_ascii() {
        return false;
    }
    host.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const RESPONSE: &str = r#"{
        "turn_server": {
            "username": "temporary-user",
            "credential": "temporary-password",
            "urls": [
                "turn:relay.example:3478?transport=udp",
                "turns:relay-secure.example:5349?transport=tcp",
                "turn:[2001:db8::10]:3478?transport=udp"
            ]
        }
    }"#;

    #[test]
    fn parses_vk_calls_turn_server_and_redacts_secrets() {
        let credentials = TurnCredentials::from_vk_response_json(RESPONSE).unwrap();
        assert_eq!(credentials.username(), "temporary-user");
        assert_eq!(credentials.password(), "temporary-password");
        assert_eq!(credentials.endpoints().len(), 3);
        assert_eq!(credentials.first_udp_endpoint().unwrap().host, "relay.example");
        let debug = format!("{credentials:?}");
        assert!(!debug.contains("temporary-user"));
        assert!(!debug.contains("temporary-password"));
        assert!(debug.contains("<redacted>"));
    }

    #[test]
    fn parses_turn_and_turns_defaults_and_transport_parameters() {
        let udp = parse_turn_uri("turn:relay.example").unwrap();
        assert_eq!(udp.port, 3478);
        assert_eq!(udp.transport, TurnWireTransport::Udp);

        let tcp = parse_turn_uri("turn://relay.example:3479?transport=tcp").unwrap();
        assert_eq!(tcp.port, 3479);
        assert_eq!(tcp.transport, TurnWireTransport::Tcp);

        let tls = parse_turn_uri("turns:relay.example").unwrap();
        assert_eq!(tls.port, 5349);
        assert_eq!(tls.transport, TurnWireTransport::Tls);
        assert_eq!(tls.tls_server_name(), Some("relay.example"));
    }

    #[test]
    fn parses_bracketed_ipv6_and_rejects_unbracketed_ipv6() {
        let endpoint = parse_turn_uri("turn:[2001:db8::1]:3478?transport=udp").unwrap();
        assert_eq!(endpoint.host, "2001:db8::1");
        assert_eq!(endpoint.socket_authority(), "[2001:db8::1]:3478");
        assert_eq!(
            parse_turn_uri("turn:2001:db8::1:3478"),
            Err(TurnCredentialError::InvalidAuthority)
        );
    }

    #[test]
    fn endpoint_debug_redacts_query_parameters() {
        let endpoint = parse_turn_uri("turn:relay.example:3478?transport=udp&secret=not-logged")
            .unwrap();
        let debug = format!("{endpoint:?}");
        assert!(!debug.contains("not-logged"));
        assert!(debug.contains("<redacted>"));
    }

    #[test]
    fn rejects_invalid_transport_components_and_hosts() {
        for uri in [
            "turn:relay.example?transport=udp&transport=tcp",
            "turn:relay.example?transport=sctp",
            "turns:relay.example?transport=udp",
            "turn:user@relay.example:3478",
            "turn:relay.example/path",
            "turn:relay.example#fragment",
            "turn:-bad.example:3478",
            "turn:relay.example:0",
        ] {
            assert!(parse_turn_uri(uri).is_err(), "accepted {uri}");
        }
    }

    #[test]
    fn rejects_malformed_vk_response() {
        assert_eq!(
            TurnCredentials::from_vk_response_json("{}").unwrap_err(),
            TurnCredentialError::MissingTurnServer
        );
        let invalid = r#"{"turn_server":{"username":"u","credential":"p","urls":[]}}"#;
        assert_eq!(
            TurnCredentials::from_vk_response_json(invalid).unwrap_err(),
            TurnCredentialError::InvalidUrlCount
        );
    }
}
