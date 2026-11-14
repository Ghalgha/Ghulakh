#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DEPLOY="$ROOT/tools/deploy-server.sh"
TMP="$(mktemp -d)"
trap 'rm -rf -- "$TMP"' EXIT

sed -n '/^stage_release() ($/,/^)/p' "$DEPLOY" >"$TMP/stage-release.sh"
source "$TMP/stage-release.sh"
safe_file() { [[ -f "$1" && ! -L "$1" ]]; }
EGRESS_SCRIPT_NAME=configure-egress-nftables.sh
CREDENTIAL_TOOL_NAME=create_credential.py

mkdir -p "$TMP/bin" "$TMP/releases" "$TMP/old-release"
printf 'server binary\n' >"$TMP/server"
printf 'egress helper\n' >"$TMP/egress"
printf 'credential helper\n' >"$TMP/credential"
printf 'old release\n' >"$TMP/old-release/keep"
ln -s "$TMP/old-release" "$TMP/current"
printf 'persistent configuration\n' >"$TMP/persistent"
EXPECTED_ID="$(sha256sum "$TMP/server" "$TMP/egress" "$TMP/credential" | cut -c1-64 | sha256sum | cut -c1-64)"

cat >"$TMP/bin/install" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
destination="${@: -1}"
if [[ -n "${FAIL_INSTALL_BASENAME:-}" && "${destination##*/}" == "$FAIL_INSTALL_BASENAME" ]]; then
  exit 73
fi
exec /usr/bin/install "$@"
SH
chmod 0755 "$TMP/bin/install"

# Fail each individual payload write. No partial release may be published or block retry.
for failed_file in ghulakh-server configure-egress-nftables.sh create_credential.py; do
  if PATH="$TMP/bin:$PATH" FAIL_INSTALL_BASENAME="$failed_file" \
      stage_release "$TMP/server" "$TMP/egress" "$TMP/credential" "$TMP/releases" "$EXPECTED_ID" >/dev/null 2>&1; then
    echo "Release staging unexpectedly succeeded after $failed_file write failure." >&2
    exit 1
  fi
  [[ -z "$(find "$TMP/releases" -mindepth 1 -maxdepth 1 -print -quit)" ]] || {
    echo "Failed release staging left a partial release or staging directory." >&2
    exit 1
  }
  [[ "$(readlink "$TMP/current")" == "$TMP/old-release" ]]
  [[ -f "$TMP/persistent" && -f "$TMP/old-release/keep" ]]
done

# A retry after each partial-write failure must publish one complete release.
published="$(stage_release "$TMP/server" "$TMP/egress" "$TMP/credential" "$TMP/releases" "$EXPECTED_ID")"
[[ "$published" == "$TMP/releases/$EXPECTED_ID" ]]
[[ -d "$published" && ! -L "$published" ]]
[[ "$(stat -c '%U:%G:%a' "$published")" == root:root:755 ]]
[[ "$(stat -c '%U:%G:%a' "$published/ghulakh-server")" == root:root:755 ]]
[[ "$(stat -c '%U:%G:%a' "$published/configure-egress-nftables.sh")" == root:root:755 ]]
[[ "$(stat -c '%U:%G:%a' "$published/create_credential.py")" == root:root:644 ]]
cmp -s "$TMP/server" "$published/ghulakh-server"
cmp -s "$TMP/egress" "$published/configure-egress-nftables.sh"
cmp -s "$TMP/credential" "$published/create_credential.py"

# Repeated staging is idempotent and rejects altered content.
[[ "$(stage_release "$TMP/server" "$TMP/egress" "$TMP/credential" "$TMP/releases" "$EXPECTED_ID")" == "$published" ]]
printf 'tampered\n' >>"$published/ghulakh-server"
if stage_release "$TMP/server" "$TMP/egress" "$TMP/credential" "$TMP/releases" "$EXPECTED_ID" >/dev/null 2>&1; then
  echo "Existing release with mismatched content was accepted." >&2
  exit 1
fi
[[ "$(readlink "$TMP/current")" == "$TMP/old-release" ]]
[[ -f "$TMP/persistent" ]]

echo "Release staging behavioral tests passed."
