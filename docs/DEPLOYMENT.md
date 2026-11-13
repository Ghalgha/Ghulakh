# Server deployment notes

These steps describe the current TURN-only runtime. Automated mock integration tests cover the client/server path, but live VK Calls API, relay allocation and TURN authentication compatibility remain unverified.

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

The server checks that Linux IPv4 forwarding, global IPv6 forwarding are enabled. Configure them persistently through the host's sysctl configuration:

    net.ipv4.ip_forward=1
    net.ipv6.conf.all.forwarding=1

The dual-stack TUN interface uses 10.77.0.1/16 and fd77:77::1/64 with MTU 1100. Authenticated sessions receive paired IPv4 and IPv6 addresses; the gateway validates both source addresses and routes downlink packets by their full IP address. Android configures both default routes and passes both packet families to the native TURN dataplane.

## 4. Configure egress routing

The server TUN uses `10.77.0.0/16` and `fd77:77::/64`. Configure the actual WAN interface and enable IPv4/IPv6 forwarding persistently. If the IPv6 default route is learned through Router Advertisements, set `net.ipv6.conf.<WAN_IF>.accept_ra=2` only for that WAN interface.

Install the scoped nftables policy after verifying the host's existing firewall:

```sh
sudo bash tools/configure-egress-nftables.sh ghulakh0 <WAN_IF> nat66
```

The script owns only `inet ghulakh_egress`, `ip ghulakh_nat4` and `ip6 ghulakh_nat6`. It restricts TUN source prefixes, blocks non-public destinations and unsolicited return-direction traffic, permits established replies, and applies IPv4 NAT plus NAT66. Use `routed` instead of `nat66` only when the upstream has an explicit working route and valid egress for the client IPv6 prefix. The default `fd77::/64` prefix is ULA; public IPv6 egress therefore normally requires NAT66 or a separately designed globally routable prefix.

The script does not change global FORWARD policy, INPUT rules, sysctls, routes or unrelated firewall tables. Its accept verdict does not override a drop in another nftables base chain: the host firewall must independently permit the intended traffic. It intentionally does not manage forwarding from unrelated interfaces. Inspect the complete ruleset and verify routing before setting `GHULAKH_FORWARDING_ENABLED=true`. Remove only its tables with `sudo bash tools/configure-egress-nftables.sh --remove`.

The server does not configure IP forwarding or firewall rules automatically. `GHULAKH_FORWARDING_ENABLED=true` is an administrator confirmation, not a firewall health check.

## 5. Configure Android

Enter the gateway hostname/IP and UDP port, the per-device tunnel credential, a VK access token with the permissions required by VK Calls, and the pinned Noise public key. The app obtains fresh temporary TURN credentials at connection time and attempts to close the VK Calls conversation when the VPN stops.

The VK access token is currently entered manually and encrypted with Android Keystore. An in-app OAuth flow is not implemented. The first real connection must be tested with a controlled VK account and a reachable gateway before general use.

## 6. Current limitations

- Only UDP TURN endpoints are supported; TCP and TURNS/TLS endpoints are rejected.
- IPv4 and IPv6 packet transport, source validation, dual-stack virtual-address allocation and routing are implemented in the client/server code and covered by automated tests. Public IPv6 egress still depends on the host's upstream route or NAT66 configuration and has not been validated on a live server.
- The legacy VK TURN authentication candidate uses MD5(username:realm:password) and HMAC-SHA1. Vendor attribute 0x8021 and PASSWORD-ALGORITHMS behavior remain unverified.
- Live VK Calls API and relay compatibility, real allocation quotas/expiry/rotation, and physical Android/VPS end-to-end tests have not yet been completed. Mock tests are not evidence of live relay compatibility.
- The server exposes only the TURN gateway; there is no alternative transport fallback.

Treat this configuration as a development deployment until the remaining integration and live-network tests pass.