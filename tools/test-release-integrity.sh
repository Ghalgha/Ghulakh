#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
EGRESS_SCRIPT_NAME="configure-egress-nftables.sh"
CREDENTIAL_TOOL_NAME="create_credential.py"
DEPLOY="$ROOT/tools/deploy-server.sh"
TMP="$(mktemp -d)"
trap 'rm -rf -- "$TMP"' EXIT
sed -n '/^verify_release_tree() {/,/^}/p' "$DEPLOY" >"$TMP/ownership-functions.sh"
sed -n '/^verify_release_integrity() {/,/^}/p' "$DEPLOY" >>"$TMP/ownership-functions.sh"
source "$TMP/ownership-functions.sh"

RELEASES="$TMP/releases"
mkdir -p "$RELEASES"
chmod 0755 "$RELEASES"
chown root:root "$RELEASES"
: >"$TMP/mountinfo"
verify_release_tree "$RELEASES" "$TMP/mountinfo"

RELEASE="$RELEASES/placeholder"
mkdir "$RELEASE"
printf 'server executable fixture\n' >"$RELEASE/ghulakh-server"
printf 'egress script fixture\n' >"$RELEASE/configure-egress-nftables.sh"
printf 'credential helper fixture\n' >"$RELEASE/create_credential.py"
chmod 0755 "$RELEASE" "$RELEASE/ghulakh-server" "$RELEASE/configure-egress-nftables.sh"
chmod 0644 "$RELEASE/create_credential.py"
chown -R root:root "$RELEASE"
ID="$(sha256sum "$RELEASE/ghulakh-server" "$RELEASE/configure-egress-nftables.sh" "$RELEASE/create_credential.py" | cut -c1-64 | sha256sum | cut -c1-64)"
mv "$RELEASE" "$RELEASES/$ID"
verify_release_integrity "$RELEASES" "$TMP/mountinfo"

printf 'tamper\n' >>"$RELEASES/$ID/ghulakh-server"
if verify_release_integrity "$RELEASES" "$TMP/mountinfo"; then
  echo "Modified release binary passed integrity validation." >&2
  exit 1
fi
printf 'server executable fixture\n' >"$RELEASES/$ID/ghulakh-server"
if verify_release_integrity "$RELEASES" "$TMP/mountinfo"; then
  echo "A release with a non-matching directory identifier passed validation." >&2
  exit 1
fi
mv "$RELEASES/$ID" "$RELEASES/placeholder"
if verify_release_integrity "$RELEASES" "$TMP/mountinfo"; then
  echo "A release with a malformed identifier passed validation." >&2
  exit 1
fi
echo "Release integrity regression tests passed."
