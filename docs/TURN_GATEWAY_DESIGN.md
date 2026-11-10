# TURN UDP gateway

## Scope

`server/src/turn_gateway.rs` adds a reusable gateway core for one authenticated TURN allocation per client. It is not yet wired into the production server TUN lifecycle or client session establishment.

## Registration trust boundary

A session registration contains:

- an unpredictable 64-bit session identifier used only for bounded lookup;
- the assigned client IPv4 address;
- the expected relay source tuple (the client's verified TURN relayed address);
- the negotiated TURN channel number;
- independent client-to-server and server-to-client frame opener/sealer state.

The caller must register a session only after an authenticated control exchange has verified the user/device, allocated virtual IP, obtained the TURN Allocate relayed address, completed CreatePermission and ChannelBind, and securely established directional frame keys. The gateway API accepts already-constructed crypto objects; it does not implement or imply that handshake. TURN username/password are never used as tunnel traffic keys.

## Uplink

1. Receive a UDP datagram on the gateway listener.
2. Decode TURN ChannelData and extract the public session identifier from the protected frame header for table lookup only.
3. Require the UDP source tuple to equal the relay tuple recorded during authenticated registration.
4. Require the expected ChannelData number.
5. Authenticate/decrypt with the session's client-to-server opener; enforce session ID, direction and replay window.
6. Decode the IP datagram, require IPv4 for the first vertical slice, and require the inner source IP to equal the registered virtual client address.
7. Submit to a bounded TUN-ingress queue. Queue saturation drops the newest packet and increments a counter.

The session identifier is not treated as an authenticator. AEAD verification is mandatory before accepting the packet. Inner source IP is checked only after authentication.

## Downlink

The server TUN consumer passes a complete IPv4 datagram to `send_downlink`. The gateway uses the inner destination IP to locate the registered session, protects the packet with that session's server-to-client sealer, wraps it in the negotiated ChannelData number, and sends it to the previously verified relay tuple. It never chooses a destination from unauthenticated client payload metadata.

## Limitations

- Session registration is not yet connected to an authenticated key agreement or VK Calls credential/session provider.
- The module is not yet connected to the production server TUN reader/writer.
- IPv6 routing, MTU/fragmentation policy, relay reconnect, allocation replacement and multi-allocation handling are not implemented.
- The UDP loopback tests exercise framing, source pinning, AEAD, virtual source validation and reverse relay-tuple delivery. They do not emulate a real TURN server or prove compatibility with VK Calls.
