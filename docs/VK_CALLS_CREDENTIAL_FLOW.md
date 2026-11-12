# VK Calls TURN credential flow

## Purpose

The client needs temporary TURN credentials and relay URLs from the VK Calls service. This provider is a control-plane component; it is separate from the TURN allocation state machine and from Ghulakh's tunnel-session authentication.

The expected response object is:

- `turn_server.username`
- `turn_server.credential`
- `turn_server.urls[]`

These values are relay-service credentials. They must not be reused as the AEAD key for Ghulakh data frames.

## Observed acquisition paths

The reviewed implementations contain two ways to obtain the `turn_server` object.

### Anonymous join-link flow

1. Request an anonymous VK token using `auth.getAnonymToken`, with a call join link, device identifier and display name.
2. Request call preview using `messages.getCallPreview`. The response provides a user identifier and a call secret.
3. Exchange those values with `messages.getAnonymCallToken` to obtain an anonymous token for the call service.
4. Open an OK CDN anonymous session using `auth.anonymLogin`; retain the returned session key.
5. Join the call using `vchat.joinConversationByLink`, passing the call link, anonymous token and session key.
6. Parse `turn_server.username`, `turn_server.credential` and `turn_server.urls` from the successful response.

This path requires a valid call join link. It does not by itself create a call.

### Authenticated account flow

1. Obtain a call token through `messages.getCallToken` using a VK account access token.
2. Open an OK CDN session through `auth.anonymLogin`.
3. Create a conversation with `vchat.startConversation` and retain its conversation identifier or join link.
4. Request conversation parameters through `vchat.getConversationParams`.
5. Parse the same `turn_server` object.

This path can create a call but requires an explicit VK account authorization flow and secure handling of the resulting access token.

### WebView interception

A separate Android approach joins a call in a user-authenticated WebView and observes JSON responses from `fetch` and `XMLHttpRequest`. When a response contains `turn_server`, it extracts the three fields above.

This approach avoids embedding account credentials in native networking code, but it still requires a user session and a call join link. Any WebView bridge must accept data only from the intended VK/OK origins, must not expose arbitrary JavaScript interfaces to unrelated pages, and must not weaken TLS certificate validation.

## Provider requirements for Ghulakh

- Keep credential acquisition behind a `TurnCredentialProvider` interface. TURN allocation code must not know whether credentials came from a join link, account authorization, or a future provider.
- Treat the username, credential and URL list as sensitive, ephemeral material. Do not log them, persist them in plaintext, or include them in diagnostics.
- Preserve each TURN URI's scheme, host, port and query parameters. Do not strip transport parameters or assume every URL is UDP.
- Parse and validate supported TURN URI schemes explicitly. Resolve endpoints before opening a socket and retain the selected endpoint for transaction source matching.
- Do not assume that a credential set remains valid for the full lifetime of a TURN allocation. Handle authentication failure and credential renewal through the provider.
- Never derive Ghulakh AEAD keys from the VK TURN username/password. Tunnel-session keys must come from a separate authenticated key agreement.
- Do not hardcode VK application credentials or rely on a copied browser fingerprint. Prefer a user-authorized WebView/OAuth flow and keep any service-specific protocol adapter isolated.
- A successful API response in a source implementation is not proof that the same API version, method parameters, TURN URI schemes or relay policy remain available. The provider needs fixture tests and later controlled integration tests.

## Unresolved integration decisions

1. Whether the first Android release should join a user-supplied existing call link or create a dedicated call through an authorized VK account.
2. Whether the app should use a WebView-based provider or a native authenticated API provider.
3. Which TURN URI schemes and transport parameters are actually returned for the target accounts and regions.
4. Whether the returned credential profile uses standard TURN long-term credentials and which password algorithm is negotiated by the relay.
5. Credential lifetime, refresh behavior, endpoint rotation and per-account relay quotas.

Until these points are confirmed, the VK Calls provider remains an interface and documented acquisition flow, not a claim of live service compatibility.
