#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
  echo "Run as root (requires iproute2, nftables, ping)." >&2
  exit 2
fi
for cmd in ip nft ping; do
  command -v "$cmd" >/dev/null || { echo "Missing dependency: $cmd" >&2; exit 2; }
done

test_id="${BASHPID}"
C="ghulakh-${test_id}-client"
R="ghulakh-${test_id}-router"
U="ghulakh-${test_id}-upstream"
X="ghulakh-${test_id}-rogue"
cleanup() {
  ip netns del "$C" 2>/dev/null || true
  ip netns del "$R" 2>/dev/null || true
  ip netns del "$U" 2>/dev/null || true
  ip netns del "$X" 2>/dev/null || true
}
for ns in "$C" "$R" "$U" "$X"; do
  if ip netns list | awk '{print $1}' | grep -Fxq "$ns"; then
    echo "Refusing to reuse existing network namespace: $ns" >&2
    exit 2
  fi
done
trap cleanup EXIT

ip netns add "$C"
ip netns add "$R"
ip netns add "$U"
ip netns add "$X"
ip link add c0 type veth peer name rc0
ip link set c0 netns "$C"
ip link set rc0 netns "$R"
ip link add ru0 type veth peer name u0
ip link set ru0 netns "$R"
ip link set u0 netns "$U"
ip link add x0 type veth peer name rx0
ip link set x0 netns "$X"
ip link set rx0 netns "$R"

for ns in "$C" "$R" "$U" "$X"; do ip -n "$ns" link set lo up; done
ip -n "$C" addr add 10.77.0.2/16 dev c0
ip -n "$R" addr add 10.77.0.1/16 dev rc0
ip -n "$R" addr add 1.1.1.254/30 dev ru0
ip -n "$U" addr add 1.1.1.253/30 dev u0
ip -n "$R" addr add 10.88.0.1/24 dev rx0
ip -n "$X" addr add 10.88.0.2/24 dev x0
ip -n "$C" -6 addr add fd77:77::2/64 dev c0
ip -n "$R" -6 addr add fd77:77::1/64 dev rc0
ip -n "$R" -6 addr add 2606:4700:4700::fffe/64 dev ru0
ip -n "$U" -6 addr add 2606:4700:4700::ffff/64 dev u0
ip -n "$R" -6 addr add fd88::1/64 dev rx0
ip -n "$X" -6 addr add fd88::2/64 dev x0
for pair in "$C c0" "$R rc0" "$R ru0" "$R rx0" "$U u0" "$X x0"; do
  read -r ns dev <<<"$pair"
  ip -n "$ns" link set "$dev" up
done
ip -n "$C" addr add 10.88.0.99/32 dev c0
ip -n "$C" route add default via 10.77.0.1
ip -n "$X" route add default via 10.88.0.1
ip -n "$U" route add 10.77.0.0/16 via 1.1.1.254
ip -n "$C" -6 addr add fd88::99/128 dev c0
ip -n "$C" -6 route add default via fd77:77::1
ip -n "$X" -6 route add default via fd88::1
ip -n "$U" -6 route add fd77:77::/64 via 2606:4700:4700::fffe
ip netns exec "$R" sysctl -q -w net.ipv6.conf.default.forwarding=1
ip netns exec "$R" ip link add v6probe0 type veth peer name v6probe1
if [[ "$(ip netns exec "$R" sysctl -n net.ipv6.conf.v6probe0.forwarding)" != "1" ]]; then
  echo "FAIL: a newly created interface did not inherit IPv6 router mode" >&2
  exit 1
fi
ip netns exec "$R" ip link del v6probe0

ip netns exec "$R" sysctl -q -w net.ipv4.ip_forward=1
ip netns exec "$R" sysctl -q -w net.ipv6.conf.all.forwarding=1
# Set forwarding explicitly on both routed interfaces; this avoids depending
# on kernel-specific propagation of the all.forwarding setting.
ip netns exec "$R" sysctl -q -w net.ipv6.conf.rc0.forwarding=1
ip netns exec "$R" sysctl -q -w net.ipv6.conf.ru0.forwarding=1
ip netns exec "$R" sysctl -q -w net.ipv6.conf.rx0.forwarding=1

ip netns exec "$R" nft -f - <<'NFT'
table inet filter {
  chain forward {
    type filter hook forward priority filter; policy drop;
    iifname "rc0" oifname "ru0" ip saddr 10.77.0.0/16 accept
    iifname "rc0" oifname "ru0" ip saddr != 10.77.0.0/16 counter drop
    iifname "rx0" oifname "ru0" counter drop
    iifname "ru0" oifname "rc0" ip daddr 10.77.0.0/16 ct state established,related accept
    iifname "ru0" oifname "rc0" ip daddr 10.77.0.0/16 counter drop
    iifname "rc0" oifname "ru0" ip6 saddr fd77:77::/64 accept
    iifname "rc0" oifname "ru0" ip6 saddr != fd77:77::/64 counter drop
    iifname "ru0" oifname "rc0" ip6 daddr fd77:77::/64 ct state established,related accept
    iifname "ru0" oifname "rc0" ip6 daddr fd77:77::/64 counter drop
  }
}
table ip nat4 {
  chain postrouting {
    type nat hook postrouting priority srcnat; policy accept;
    ip saddr 10.77.0.0/16 oifname "ru0" counter masquerade
  }
}
table ip6 nat6 {
  chain postrouting {
    type nat hook postrouting priority srcnat; policy accept;
    ip6 saddr fd77:77::/64 oifname "ru0" counter masquerade
  }
}
NFT

ip netns exec "$U" nft -f - <<'NFT'
table inet upstream_probe {
  chain input {
    type filter hook input priority filter; policy accept;
    ip saddr 1.1.1.254 icmp type echo-request counter
    ip6 saddr 2606:4700:4700::fffe icmpv6 type echo-request counter
    ip6 saddr fd77:77::2 icmpv6 type echo-request counter
  }
}
NFT

ip netns exec "$C" ping -c 2 -W 2 1.1.1.253

# Warm up IPv6 neighbor discovery using a client-originated packet through NAT66.
# A bounded retry handles the initial NDP resolution without weakening the
# subsequent packet-delivery assertion.
nat66_warmup_ok=0
for attempt in 1 2 3; do
  if ip netns exec "$C" ping -6 -c 1 -W 2 2606:4700:4700::ffff >/dev/null 2>&1; then
    nat66_warmup_ok=1
    break
  fi
done
if [[ "$nat66_warmup_ok" != "1" ]]; then
  echo "FAIL: IPv6 NAT66 warm-up did not receive an echo reply after 3 attempts" >&2
  exit 1
fi

# Require every probe packet to return. ping's exit status alone is insufficient:
# iputils returns success when at least one reply arrives.
nat66_ping_output="$(LC_ALL=C ip netns exec "$C" ping -6 -c 2 -W 2 2606:4700:4700::ffff 2>&1)" || {
  printf '%s\n' "$nat66_ping_output" >&2
  echo "FAIL: strict IPv6 NAT66 probe command failed" >&2
  exit 1
}
printf '%s\n' "$nat66_ping_output"
if ! grep -Eq '^2 packets transmitted, 2 received, 0% packet loss(, .*)?$' <<<"$nat66_ping_output"; then
  echo "FAIL: IPv6 NAT66 probe must receive exactly 2 of 2 replies" >&2
  exit 1
fi

if ip netns exec "$U" ping -c 1 -W 1 10.77.0.2; then
  echo "FAIL: unsolicited IPv4 forwarding was not blocked" >&2
  exit 1
fi
if ip netns exec "$U" ping -6 -c 1 -W 1 fd77:77::2; then
  echo "FAIL: unsolicited IPv6 forwarding was not blocked" >&2
  exit 1
fi
# Reject spoofed source prefixes on the tunnel interface and unrelated ingress.
if ip netns exec "$C" ping -I 10.88.0.99 -c 1 -W 1 1.1.1.253; then
  echo "FAIL: spoofed IPv4 source escaped the tunnel egress policy" >&2
  exit 1
fi
if ip netns exec "$C" ping -6 -I fd88::99 -c 1 -W 1 2606:4700:4700::ffff; then
  echo "FAIL: spoofed IPv6 source escaped the tunnel egress policy" >&2
  exit 1
fi
if ip netns exec "$X" ping -c 1 -W 1 1.1.1.253; then
  echo "FAIL: unrelated IPv4 ingress reached the upstream" >&2
  exit 1
fi
if ip netns exec "$X" ping -6 -c 1 -W 1 2606:4700:4700::ffff; then
  echo "FAIL: unrelated IPv6 ingress reached the upstream" >&2
  exit 1
fi
ip netns exec "$R" nft list chain ip nat4 postrouting | grep -Eq 'counter packets [1-9][0-9]*'
ip netns exec "$R" nft list chain ip6 nat6 postrouting | grep -Eq 'counter packets [1-9][0-9]*'

# Confirm the upstream sees translated source addresses, not merely successful pings.
ip netns exec "$U" nft list chain inet upstream_probe input \
  | grep -F 'ip saddr 1.1.1.254' | grep -Eq 'counter packets [1-9][0-9]*'
ip netns exec "$U" nft list chain inet upstream_probe input \
  | grep -F 'ip6 saddr 2606:4700:4700::fffe' | grep -Eq 'counter packets [1-9][0-9]*'

# Verify routed IPv6 without NAT66: the upstream has an explicit route to
# the client prefix, so the original fd77:: source must remain routable.
ip netns exec "$R" nft delete table ip6 nat6
ip netns exec "$C" ping -6 -c 2 -W 2 2606:4700:4700::ffff
ip netns exec "$U" nft list chain inet upstream_probe input \
  | grep -F 'ip6 saddr fd77:77::2' | grep -Eq 'counter packets [1-9][0-9]*'

# Anti-spoofing and unrelated-ingress denials must hit explicit drop rules.
ip netns exec "$R" nft list chain inet filter forward | grep -F 'ip saddr != 10.77.0.0/16 counter packets' | grep -Eq 'counter packets [1-9][0-9]*'
ip netns exec "$R" nft list chain inet filter forward | grep -F 'ip6 saddr != fd77:77::/64 counter packets' | grep -Eq 'counter packets [1-9][0-9]*'
ip netns exec "$R" nft list chain inet filter forward | grep -F 'iifname "rx0" oifname "ru0" counter packets' | grep -Eq 'counter packets [1-9][0-9]*'

# Both reverse-direction probes must hit explicit drop rules, not merely time out.
ip netns exec "$R" nft list chain inet filter forward \
  | grep -F 'ip daddr 10.77.0.0/16 counter packets' | grep -Eq 'counter packets [1-9][0-9]*'
ip netns exec "$R" nft list chain inet filter forward \
  | grep -F 'ip6 daddr fd77:77::/64 counter packets' | grep -Eq 'counter packets [1-9][0-9]*'

echo "PASS: IPv4 NAT, IPv6 NAT66/routing, stateful return traffic, source anti-spoofing, unrelated-ingress isolation and unsolicited-forward drops"
