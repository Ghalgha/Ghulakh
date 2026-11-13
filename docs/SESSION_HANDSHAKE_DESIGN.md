# Session authentication and directional key establishment

**Сверено с main на commit 611b4788c9b40dba29a82ed3011e8d6f0f5ae4f3 (2026-11-13).** Актуальный статус реализации и границы подтверждения — в [STATUS.md](STATUS.md).

## Implemented handshake primitive

`crates/protocol/src/session_handshake.rs` implements Noise XX using the standard pattern name:

`Noise_XX_25519_ChaChaPoly_BLAKE2s`

The client pins the server's 32-byte static public key. The server's static key is persisted and must be distributed to clients through a trusted channel. The client sends its device credential only in Noise message 3, after the server static key has been authenticated and the payload is encrypted by the handshake state. The server verifies that credential before producing an encrypted authentication acknowledgement.

Both sides derive the same session identifier and independent client-to-server/server-to-client frame keys from the final Noise handshake hash using HKDF-SHA256 and a protocol-specific context label. The resulting keys initialize the existing protected-frame codecs. TURN credentials are not inputs to this key schedule.

Temporary key buffers are wrapped in zeroizing containers where owned by this module; frame codec constructors clear their temporary key-array copies after cipher initialization. This does not claim that every third-party cryptographic implementation's internal state has been formally audited or verified to be zeroized.

## Why this is separate from TURN

TURN allocation credentials authorize use of a relay. They do not authenticate a Ghulakh account/device to the gateway and must not become IP-traffic encryption keys. The Noise handshake establishes the application session independently of TURN's long-term credential mechanism. The handshake messages themselves still need to be transported through the established TURN allocation.

## Current integration and remaining limitations

The handshake is integrated into the TURN client runtime and server session service. The client driver sends bounded handshake envelopes through the shared TURN socket actor, validates the configured relay endpoint, applies bounded stop-and-wait retry delivery, and returns frame keys only after the encrypted ServerAck is accepted. The server handshake service performs Noise XX authentication, validates the device credential, allocates virtual IPv4/IPv6 addresses, and registers the authenticated session with the TURN gateway.

The envelope remains a demultiplexing/retry container, not an authenticator. Authentication comes from Noise XX and subsequent directional AEAD frames. Mock integration tests exercise the client/server exchange and registration; they do not validate a live VK relay.

## Remaining validation

- Independently review the Noise library and complete handshake/session-key composition.
- Extend deterministic loss, duplication, reordering, timeout, cancellation and concurrent-handshake fault tests.
- Confirm behavior over a real VK Calls relay only during the late-stage controlled integration phase.

## TURN datagram envelope primitives

`crates/protocol/src/handshake_datagram.rs` defines the bounded envelope for Noise handshake phases: handshake identifier, phase, version and payload length. It rejects reserved bits, zero identifiers, empty payloads, unknown phases, truncation, trailing bytes and oversized payloads. The protocol module also provides a bounded exact-byte response cache.

The client TURN handshake task is integrated with the shared socket actor. It owns Noise and retry state, validates the configured relay endpoint, performs bounded stop-and-wait delivery and returns frame keys only after accepting the encrypted ServerAck. The server handshake service authenticates the device and registers the resulting session with the gateway. These paths are covered by mock tests, not by a live VK relay.

The envelope itself is not an authenticator. Noise XX provides peer authentication; directional AEAD protects data frames. Remaining work is independent cryptographic review and broader deterministic loss/duplication/reordering/cancellation tests.
