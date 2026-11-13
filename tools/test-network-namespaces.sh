#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
  echo "Run as root (requires iproute2, nftables, ping)." >&2
  exit 2
fi
for cmd in ip nft ping; do
  command -v "$cmd" >/dev/null || { echo "Missing dependency: $cmd" >&2; exit 2; }
done

test_id="$"
C="ghulakh-${test_id}-client"
R="ghulakh-${test_id}-router"
U="ghulakh-${test_id}-upstream"
cleanup() {
  ip netns del "$C" 2>/dev/null || true
  ip netns del "$R" 2>/dev/null || true
  ip netns del "$U" 2>/dev/null || true
}
for ns in "$C" "$R" "$U"; do
  if ip netns list | awk '{print $1}' | grep -Fxq "$ns"; then
    echo "Refusing to reuse existing network namespace: $ns" >&2
    exit 2
  fi
done
trap cleanup EXIT

ip netns add "$C"
ip netns add "$R"
ip netns add "$U"
ip link add c0 type veth peer name rc0
ip link set c0 netns "$C"
ip link set rc0 netns "$R"
ip link add ru0 type veth peer name u0
ip link set ru0 netns "$R"
ip link set u0 netns "$U"

for ns in "$C" "$R" "$U"; do ip -n "$ns" link set lo up; done
ip -n "$C" addr add 10.77.0.2/16 dev c0
ip -n "$R" addr add 10.77.0.1/16 dev rc0
ip -n "$R" addr add 1.1.1.254/30 dev ru0
ip -n "$U" addr add 1.1.1.253/30 dev u0
ip -n "$C" -6 addr add fd77:77::2/64 dev c0
ip -n "$R" -6 addr add fd77:77::1/64 dev rc0
ip -n "$R" -6 addr add 2606:4700:4700::fffe/64 dev ru0
ip -n "$U" -6 addr add 2606:4700:4700::ffff/64 dev u0
for pair in "$C c0" "$R rc0" "$R ru0" "$U u0"; do
  read -r ns dev <<<"$pair"
  ip -n "$ns" link set "$dev" up
done
ip -n "$C" route add default via 10.77.0.1
ip -n "$U" route add 10.77.0.0/16 via 1.1.1.254
ip -n "$C" -6 route add default via fd77:77::1
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

ip netns exec "$R" nft -f - <<'NFT'
table inet filter {
  chain forward {
    type filter hook forward priority filter; policy drop;
    iifname "rc0" oifname "ru0" ip saddr 10.77.0.0/16 accept
    iifname "ru0" oifname "rc0" ip daddr 10.77.0.0/16 ct state established,related accept
    iifname "ru0" oifname "rc0" ip daddr 10.77.0.0/16 counter drop
    iifname "rc0" oifname "ru0" ip6 saddr fd77:77::/64 accept
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
ip netns exec "$C" ping -6 -c 2 -W 2 2606:4700:4700::ffff
if ip netns exec "$U" ping -c 1 -W 1 10.77.0.2; then
  echo "FAIL: unsolicited IPv4 forwarding was not blocked" >&2
  exit 1
fi
if ip netns exec "$U" ping -6 -c 1 -W 1 fd77:77::2; then
  echo "FAIL: unsolicited IPv6 forwarding was not blocked" >&2
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

# Both reverse-direction probes must hit explicit drop rules, not merely time out.
ip netns exec "$R" nft list chain inet filter forward \
  | grep -F 'ip daddr 10.77.0.0/16 counter packets' | grep -Eq 'counter packets [1-9][0-9]*'
ip netns exec "$R" nft list chain inet filter forward \
  | grep -F 'ip6 daddr fd77:77::/64 counter packets' | grep -Eq 'counter packets [1-9][0-9]*'

echo "PASS: IPv4 NAT source translation, IPv6 NAT66 source translation, native IPv6 routing, stateful return traffic and unsolicited-forward drops"
