#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'USAGE'
Usage:
  configure-egress-nftables.sh <tun-interface> <wan-interface> [nat66|routed]
  configure-egress-nftables.sh --remove

Installs only Ghulakh-owned nftables tables. It does not change global
FORWARD policy, sysctls, routes, INPUT rules, or unrelated firewall tables.
USAGE
  exit 2
}

if [[ ${EUID} -ne 0 ]]; then
  echo "Run as root (requires nftables)." >&2
  exit 2
fi
command -v nft >/dev/null || { echo "Missing dependency: nft" >&2; exit 2; }
command -v ip >/dev/null || { echo "Missing dependency: ip" >&2; exit 2; }

table_is_present() {
  nft list table "$1" "$2" >/dev/null 2>&1
}

table_is_owned() {
  nft list table "$1" "$2" 2>/dev/null | grep -Fq 'comment "ghulakh-egress-v1"'
}

if [[ ${1:-} == "--remove" ]]; then
  [[ $# -eq 1 ]] || usage
  remove_commands=()
  for table in "inet ghulakh_egress" "ip ghulakh_nat4" "ip6 ghulakh_nat6"; do
    read -r family name <<<"$table"
    if table_is_present "$family" "$name"; then
      if ! table_is_owned "$family" "$name"; then
        echo "Refusing to remove table without Ghulakh ownership marker: $family $name" >&2
        exit 2
      fi
      remove_commands+=("delete table $family $name")
    fi
  done
  if (( ${#remove_commands[@]} > 0 )); then
    printf '%s\n' "${remove_commands[@]}" | nft -f -
  fi
  echo "Removed Ghulakh-owned egress/NAT tables."
  exit 0
fi

[[ $# -ge 2 && $# -le 3 ]] || usage
TUN_IF=$1
WAN_IF=$2
IPV6_MODE=${3:-nat66}
[[ $TUN_IF =~ ^[a-zA-Z0-9_.-]{1,15}$ ]] || usage
[[ $WAN_IF =~ ^[a-zA-Z0-9_.-]{1,15}$ ]] || usage
[[ $TUN_IF != "$WAN_IF" ]] || { echo "TUN and WAN interfaces must differ." >&2; exit 2; }
[[ $IPV6_MODE == "nat66" || $IPV6_MODE == "routed" ]] || usage
# The TUN may be created by the server after this script is installed.
# nftables matches the interface name and activates the rules when it appears.
ip link show "$WAN_IF" >/dev/null 2>&1 || { echo "WAN interface not found: $WAN_IF" >&2; exit 2; }

for table in "inet ghulakh_egress" "ip ghulakh_nat4"; do
  read -r family name <<<"$table"
  if table_is_present "$family" "$name"; then
    echo "Refusing to overwrite existing table: $family $name (use --remove first)." >&2
    exit 2
  fi
done
if table_is_present ip6 ghulakh_nat6; then
  echo "Refusing to overwrite existing table: ip6 ghulakh_nat6 (use --remove first)." >&2
  exit 2
fi

# This dedicated base chain constrains only traffic entering/leaving the TUN.
# Its accept policy does not replace or override other host firewall chains.
{
cat <<NFT
table inet ghulakh_egress {
  comment "ghulakh-egress-v1";
  chain input {
    type filter hook input priority -10; policy accept;
    # IPv6 Neighbor Discovery is required for clients to resolve the TUN
    # gateway. Accept only valid link-local control messages (hop limit 255);
    # all other traffic addressed to server-local services remains blocked.
    iifname "$TUN_IF" ip6 hoplimit 255 icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert } counter accept
    iifname "$TUN_IF" counter drop
  }
  chain forward {
    type filter hook forward priority -10; policy accept;

    ct state invalid counter drop
    iifname "$TUN_IF" ip saddr != 10.77.0.0/16 counter drop
    iifname "$TUN_IF" ip6 saddr != fd77:77::/64 counter drop

    iifname "$TUN_IF" oifname "$WAN_IF" ip daddr {
      0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8,
      169.254.0.0/16, 172.16.0.0/12, 192.0.0.0/24, 192.0.2.0/24,
      192.88.99.0/24, 192.168.0.0/16, 198.18.0.0/15,
      198.51.100.0/24, 203.0.113.0/24, 224.0.0.0/4,
      240.0.0.0/4, 255.255.255.255/32
    } counter drop
    iifname "$TUN_IF" oifname "$WAN_IF" ip6 daddr {
      ::/128, ::1/128, ::ffff:0:0/96, 2001::/23, fc00::/7, fe80::/10, ff00::/8, 2001:db8::/32
    } counter drop

    iifname "$TUN_IF" oifname "$WAN_IF" ip saddr 10.77.0.0/16 accept
    iifname "$TUN_IF" oifname "$WAN_IF" ip6 saddr fd77:77::/64 accept
    iifname "$TUN_IF" counter drop

    iifname "$WAN_IF" oifname "$TUN_IF" ip daddr 10.77.0.0/16 ct state established,related accept
    iifname "$WAN_IF" oifname "$TUN_IF" ip6 daddr fd77:77::/64 ct state established,related accept
    iifname "$WAN_IF" oifname "$TUN_IF" ip daddr 10.77.0.0/16 counter drop
    iifname "$WAN_IF" oifname "$TUN_IF" ip6 daddr fd77:77::/64 counter drop
    oifname "$TUN_IF" counter drop
  }
}
table ip ghulakh_nat4 {
  comment "ghulakh-egress-v1";
  chain postrouting {
    type nat hook postrouting priority srcnat; policy accept;
    ip saddr 10.77.0.0/16 oifname "$WAN_IF" counter masquerade
  }
}
NFT
if [[ $IPV6_MODE == "nat66" ]]; then
  cat <<NFT
table ip6 ghulakh_nat6 {
  comment "ghulakh-egress-v1";
  chain postrouting {
    type nat hook postrouting priority srcnat; policy accept;
    ip6 saddr fd77:77::/64 oifname "$WAN_IF" counter masquerade
  }
}
NFT
fi
} | nft -f -

echo "Installed Ghulakh egress policy: TUN=$TUN_IF WAN=$WAN_IF IPv6=$IPV6_MODE"
