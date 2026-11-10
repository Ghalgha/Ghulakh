# Session authentication and directional key establishment

## Implemented handshake primitive

`crates/protocol/src/session_handshake.rs` implements Noise XX using the standard pattern name:

`Noise_XX_25519_ChaChaPoly_BLAKE2s`

The client pins the server's 32-byte static public key. The server's static key is persisted and must be distributed to clients through a trusted channel. The client sends its device credential only in Noise message 3, after the server static key has been authenticated and the payload is encrypted by the handshake state. The server verifies that credential before producing an encrypted authentication acknowledgement.

Both sides derive the same session identifier and independent client-to-server/server-to-client frame keys from the final Noise handshake hash using HKDF-SHA256 and a protocol-specific context label. The resulting keys initialize the existing protected-frame codecs. TURN credentials are not inputs to this key schedule.

Temporary key buffers are wrapped in zeroizing containers where owned by this module; frame codec constructors clear their temporary key-array copies after cipher initialization. This does not claim that every third-party cryptographic implementation's internal state has been formally audited or verified to be zeroized.

## Why this is separate from TURN

TURN allocation credentials authorize use of a relay. They do not authenticate a Ghulakh account/device to the gateway and must not become IP-traffic encryption keys. The Noise handshake establishes the application session independently of TURN's long-term credential mechanism. The handshake messages themselves still need to be transported through the established TURN allocation.

## Current limitations — not production-ready yet

- The module is a cryptographic handshake state machine, not a TURN datagram handshake driver.
- UDP loss/reordering/retransmission, duplicate message handling, handshake transaction IDs, rate limits and bounded pending-handshake state are not implemented. Do not send these messages over an unreliable relay until a stop-and-wait/replay-safe handshake envelope is implemented.
- The server credential verifier is supplied by the caller. It must use the existing credential store with constant-time digest comparison, expiry/revocation and rate limiting.
- The server static key pair persistence/rotation and secure client pin distribution are not integrated.
- The gateway session registry is not yet populated from a completed Noise handshake.
- Snow 0.10.0 implements the Noise framework but its own project documentation states it has not received a formal security audit. Treat the integration as research-stage pending dependency review and protocol audit.
- The current implementation has unit tests for pinned server identity, credential rejection, encrypted server acknowledgement and both directional frame keys. These tests do not establish UDP handshake reliability or VK Calls compatibility.

## Next integration steps

1. Add a bounded TURN handshake envelope with session/transaction identifiers and exact retransmission of already-generated Noise messages.
2. Add duplicate suppression and cached response replay for each handshake phase; never advance Noise state twice for a duplicate datagram.
3. Bind successful handshake results to the verified TURN relayed address, channel number and allocated virtual IPv4.
4. Register the resulting directional codecs in `TurnGateway` only after the client has received and authenticated the final acknowledgement.
5. Connect the client result to `TurnDataPlane` and the server result to `TurnGateway`.
