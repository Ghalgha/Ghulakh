# Session authentication and directional key establishment

## Implemented handshake primitive

`crates/protocol/src/session_handshake.rs` implements Noise XX using the standard pattern name:

`Noise_XX_25519_ChaChaPoly_BLAKE2s`

The client pins the server's 32-byte static public key. The server's static key is persisted and must be distributed to clients through a trusted channel. The client sends its device credential only in Noise message 3, after the server static key has been authenticated and the payload is encrypted by the handshake state. The server verifies that credential before producing an encrypted authentication acknowledgement.

Both sides derive the same session identifier and independent client-to-server/server-to-client frame keys from the final Noise handshake hash using HKDF-SHA256 and a protocol-specific context label. The resulting keys initialize the existing protected-frame codecs. TURN credentials are not inputs to this key schedule.

Temporary key buffers are wrapped in zeroizing containers where owned by this module; frame codec constructors clear their temporary key-array copies after cipher initialization. This does not claim that every third-party cryptographic implementation's internal state has been formally audited or verified to be zeroized.

## Why this is separate from TURN

TURN allocation credentials authorize use of a relay. They do not authenticate a Ghulakh account/device to the gateway and must not become IP-traffic encryption keys. The Noise handshake establishes the application session independently of TURN's long-term credential mechanism. The handshake messages themselves still need to be transported through the established TURN allocation.

## Current integration and remaining limitations

- Client and server handshake tasks are integrated with the TURN runtime. The client validates the expected relay endpoint and encrypted ServerAck; the server applies bounded admission/rate limits and caches handshake responses before sending them. The authenticated session is registered before ServerAck delivery to avoid a first-uplink race.
- Handshake response matching and state advancement remain ordered: a matched but unauthenticated response must not complete a retry transaction.
- Retry scheduling is bounded and owned by the runtime task; retransmission and timeout behavior is covered by deterministic tests, not by live relay measurements.
- The response cache is bounded globally and per source, uses a fixed TTL, and rejects transaction-key reuse with different request bytes. Handshake queue overload drops the newest handshake datagram and increments a dedicated counter rather than blocking the sole TURN socket reader.
- Source tuple admission, rate limiting and response caching are implemented in the server handshake service; live traffic characteristics remain untested.
- Device credentials are checked against configured SHA-256 digests using constant-time comparison; credential revocation currently requires updating the digest file and restarting the server.
- Server static key persistence and keypair consistency checks are implemented. Secure distribution/rotation of the pinned public key remains an operator responsibility.
- Server TURN handshake service completes Noise XX, validates the device credential, creates the encrypted session acknowledgement, and registers the authenticated session before the acknowledgement is sent. The mock integration suite covers this ordering; live VK relay compatibility remains unverified.
- Snow 0.10.0 implements the Noise framework but its own project documentation states it has not received a formal security audit. Treat the integration as research-stage pending dependency review and protocol audit.
- The current implementation has unit tests for pinned server identity, credential rejection, encrypted server acknowledgement and both directional frame keys. These tests do not establish UDP handshake reliability or VK Calls compatibility.

## Remaining validation

1. Validate Noise handshake behavior across real VK TURN relay paths, including loss, duplication, reordering and reconnect.
2. Integrate the cache lookup before Noise state advancement and cache the exact response before sending it; never advance Noise state twice for a duplicate datagram.
3. Bind successful handshake results to the verified TURN relayed address, channel number and allocated virtual IPv4.
4. Register the resulting directional codecs in `TurnGateway` only after the client has received and authenticated the final acknowledgement.
5. Connect the client result to `TurnDataPlane` and the server result to `TurnGateway`.

## TURN datagram envelope primitives

`crates/protocol/src/handshake_datagram.rs` now defines a fixed, bounded envelope for the four Noise handshake phases. It carries a 128-bit handshake identifier, phase, version and explicit payload length; reserved bits, zero identifiers, empty payloads, unknown phases, truncation, trailing bytes and oversized payloads are rejected.

The module also provides a bounded response cache keyed by handshake identifier and phase. It fingerprints the exact request bytes and returns the exact cached response for a duplicate. Reusing the same key with different request bytes is rejected. Cache eviction is oldest-first and capacity is fixed at construction.

These are protocol primitives only. The following remain required before any production use over TURN:
- A network driver must implement bounded stop-and-wait retransmission with an explicit retry budget and backoff, and resend the exact previously encoded datagram.
- The driver must consult the response cache before advancing a Noise state machine, and cache a response before attempting to send it.
- The driver must expire handshake state and cache entries, limit concurrent handshakes, and enforce per-source admission/rate limits. The cache itself deliberately has no clock or implicit expiry.
- The driver must validate the TURN allocation/source tuple and bind the handshake identifier to that allocation.
- Tests must cover packet loss, duplication, reordering, timeout races, state exhaustion and reconnect behavior.

The envelope does not authenticate the first Noise messages by itself. Authentication remains the responsibility of the Noise handshake; untrusted envelope fields must only be used for bounded demultiplexing.
