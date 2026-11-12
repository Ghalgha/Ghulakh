# Server deployment notes

These steps describe the current TURN-only runtime. They are not a claim of live VK relay compatibility; the live VK API and TURN authentication profile still require validation.

## 1. Generate the persistent Noise keypair

Run the key generator once on the server. It refuses to overwrite existing files and creates the private key with mode 0600 on Unix:

    cargo run -p ghulakh-server -- --generate-noise-keypair /etc/ghulakh/noise_private.hex /etc/ghulakh/noise_public.hex

Keep noise_private.hex secret and readable only by the server service account. Copy the hex value from noise_public.hex into the Android profile as the pinned Noise public key. Do not regenerate the key during ordinary restarts.

## 2. Provision device credentials

Generate a high-entropy credential for each device. Store only its SHA-256 digest in the server credential file, one lowercase hexadecimal digest per line. The raw credential is entered into the Android profile and is never stored in the server digest file.

    printf '%s' "$DEVICE_CREDENTIAL" | sha256sum | awk '{print $1}'

Protect the credential file with filesystem permissions appropriate to the server service account. The credential is distinct from the VK access token and from temporary VK TURN credentials.

## 3. Configure the server

Required environment:

    GHULAKH_CREDENTIAL_HASHES=/etc/ghulakh/device-credentials.sha256
    GHULAKH_TUN_ENABLED=true
    GHULAKH_FORWARDING_ENABLED=true
    GHULAKH_TUN_NAME=ghulakh0
    GHULAKH_TURN_GATEWAY_BIND=0.0.0.0:4434
    GHULAKH_NOISE_PRIVATE_KEY=/etc/ghulakh/noise_private.hex
    GHULAKH_NOISE_PUBLIC_KEY=/etc/ghulakh/noise_public.hex

The TURN gateway listens for raw UDP payloads from VK TURN relays. Open the configured UDP port in the host firewall. The gateway validates relay source tuples and authenticated frames, but the actual VK relay address ranges have not yet been live-verified; do not invent an allowlist.

The server checks that Linux IPv4 forwarding, global IPv6 forwarding, and default IPv6 forwarding for newly created interfaces are enabled. Configure them persistently through the host's sysctl configuration:

    net.ipv4.ip_forward=1
    net.ipv6.conf.all.forwarding=1
    net.ipv6.conf.default.forwarding=1

The dual-stack TUN interface uses 10.77.0.1/16 and fd77:77::1/64 with MTU 1100. Authenticated sessions receive one IPv4 and one IPv6 address; the gateway validates both source addresses and routes downlink packets by their full IP address.

## 4. Configure egress routing

Configure the host firewall/NAT for the actual WAN interface. At minimum, IPv4 forwarding from the Ghulakh TUN subnet must be permitted and source-NATed toward the WAN; return traffic for 10.77.0.0/16 must route back through the Ghulakh TUN interface. The IPv6 client prefix is ULA (fd77:77::/64), so public IPv6 egress additionally requires either an upstream route for that prefix or IPv6 source NAT (NAT66) on the actual WAN interface. Permit the corresponding IPv6 forwarding and return traffic. The exact nftables/iptables rules depend on the host firewall and must be reviewed before deployment; IPv6 internet egress is not guaranteed by enabling forwarding alone.

Do not enable unrestricted forwarding to private, loopback, link-local, multicast or other non-public destinations. The server gateway already blocks several non-public IPv4 destination ranges, but host firewall policy remains required.

## 5. Configure Android

Enter the gateway hostname/IP and UDP port, the per-device tunnel credential, a VK access token with the permissions required by VK Calls, and the pinned Noise public key. The app obtains fresh temporary TURN credentials at connection time and attempts to close the VK Calls conversation when the VPN stops.

The VK access token is currently entered manually and encrypted with Android Keystore. An in-app OAuth flow is not implemented. The first real connection must be tested with a controlled VK account and a reachable gateway before general use.

## 6. Current limitations

- Only UDP TURN endpoints are supported; TCP and TURNS/TLS endpoints are rejected.
- IPv4 and IPv6 packet transport, source validation, and virtual-address routing are implemented. Public IPv6 egress still depends on the host's upstream route or NAT66 configuration; it has not been validated on a live server.
- The legacy VK TURN authentication candidate uses MD5(username:realm:password) and HMAC-SHA1. Vendor attribute 0x8021 and PASSWORD-ALGORITHMS behavior remain unverified.
- Real VK Calls API, relay allocation, credential expiry/rotation, Android device and VPS tests have not yet been completed.
- The server exposes only the TURN gateway; there is no alternative transport fallback.

Treat this configuration as a development deployment until the remaining integration and live-network tests pass.