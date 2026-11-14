#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SCRIPT="$ROOT/tools/configure-egress-nftables.sh"
TMP="$(mktemp -d)"
trap 'rm -rf -- "$TMP"' EXIT
mkdir -p "$TMP/bin"
cat >"$TMP/bin/nft" <<'NFT'
#!/usr/bin/env bash
set -euo pipefail
case "$*" in
  "-j list tables") cat "$NFT_FIXTURE" ;;
  "-f -") cat >"$NFT_APPLIED" ;;
  *) echo "unexpected nft invocation: $*" >&2; exit 90 ;;
esac
NFT
cat >"$TMP/bin/ip" <<'IP'
#!/usr/bin/env bash
exit 0
IP
chmod 0755 "$TMP/bin/nft" "$TMP/bin/ip"
export PATH="$TMP/bin:$PATH" NFT_APPLIED="$TMP/applied"

run_check() {
  NFT_FIXTURE="$1" bash "$SCRIPT" --check-owned
}
run_remove() {
  NFT_FIXTURE="$1" bash "$SCRIPT" --remove
}

cat >"$TMP/valid.json" <<'JSON'
{"nftables":[{"table":{"family":"inet","name":"ghulakh_egress","comment":"ghulakh-egress-v1"}},{"table":{"family":"ip","name":"ghulakh_nat4","comment":"ghulakh-egress-v1"}}]}
JSON
run_check "$TMP/valid.json"

cat >"$TMP/decoy.json" <<'JSON'
{"nftables":[{"table":{"family":"inet","name":"ghulakh_egress"}},{"chain":{"family":"inet","table":"ghulakh_egress","comment":"ghulakh-egress-v1"}}]}
JSON
if run_check "$TMP/decoy.json"; then
  echo "A chain-level comment was incorrectly accepted as table ownership." >&2
  exit 1
fi

cat >"$TMP/foreign.json" <<'JSON'
{"nftables":[{"table":{"family":"inet","name":"ghulakh_egress","comment":"administrator-owned"}}]}
JSON
if run_check "$TMP/foreign.json"; then
  echo "A foreign table comment was incorrectly accepted." >&2
  exit 1
fi

printf '%s' '{"unexpected":[]}' >"$TMP/wrong-shape.json"
if run_check "$TMP/wrong-shape.json"; then
  echo "An unexpected nftables JSON shape was incorrectly accepted." >&2
  exit 1
fi

printf '%s' '{invalid json' >"$TMP/malformed.json"
if run_check "$TMP/malformed.json"; then
  echo "Malformed nftables JSON was incorrectly accepted." >&2
  exit 1
fi

: >"$NFT_APPLIED"
run_remove "$TMP/valid.json"
grep -Fqx 'delete table inet ghulakh_egress' "$NFT_APPLIED"
grep -Fqx 'delete table ip ghulakh_nat4' "$NFT_APPLIED"
[[ "$(wc -l <"$NFT_APPLIED")" -eq 2 ]]

printf '%s' '{"nftables":[]}' >"$TMP/empty.json"
: >"$NFT_APPLIED"
run_remove "$TMP/empty.json"
[[ ! -s "$NFT_APPLIED" ]]

echo "nftables ownership regression tests passed."
