#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DEPLOY="$ROOT/tools/deploy-server.sh"
TMP="$(mktemp -d)"
trap 'rm -rf -- "$TMP"' EXIT

sed -n '/^verify_release_tree() {/,/^}/p' "$DEPLOY" >"$TMP/functions.sh"
sed -n '/^uninstall() {/,/^}/p' "$DEPLOY" >>"$TMP/functions.sh"

BASE="$TMP/base"
RELEASES="$BASE/releases"
CURRENT="$BASE/current"
MARKER="$BASE/.managed-by-ghulakh"
UNINSTALL_JOURNAL="$BASE/.uninstall-in-progress"
SERVER_UNIT="$TMP/systemd/ghulakh-server.service"
EGRESS_UNIT="$TMP/systemd/ghulakh-egress.service"
mkdir -p "$RELEASES/partial" "$TMP/systemd"
chmod 0755 "$BASE" "$RELEASES" "$RELEASES/partial"
chown root:root "$BASE" "$RELEASES" "$RELEASES/partial"
printf 'runtime-removed\n' >"$UNINSTALL_JOURNAL"
chmod 0600 "$UNINSTALL_JOURNAL"
chown root:root "$UNINSTALL_JOURNAL"
printf 'partial release\n' >"$RELEASES/partial/remnant"
printf 'persistent secret\n' >"$TMP/persistent-config"
: >"$TMP/systemctl-calls"

require_root() { :; }
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
systemctl() { printf '%s\n' "$*" >>"$TMP/systemctl-calls"; [[ "$*" == daemon-reload ]]; }
source "$TMP/functions.sh"

printf 'REMOVE GHULAKH\n' | uninstall
[[ ! -e "$RELEASES" && ! -e "$MARKER" && ! -e "$UNINSTALL_JOURNAL" ]]
[[ -f "$TMP/persistent-config" ]]
grep -Fxq daemon-reload "$TMP/systemctl-calls"

# Invalid journals must fail closed without deleting release content.
mkdir -p "$RELEASES/partial"
chmod 0755 "$BASE" "$RELEASES" "$RELEASES/partial"
chown root:root "$BASE" "$RELEASES" "$RELEASES/partial"
printf 'unexpected\n' >"$UNINSTALL_JOURNAL"
chmod 0600 "$UNINSTALL_JOURNAL"
chown root:root "$UNINSTALL_JOURNAL"
if ( uninstall </dev/null ); then
  echo "Invalid uninstall journal was accepted." >&2
  exit 1
fi
[[ -d "$RELEASES/partial" && -f "$RELEASES/partial/remnant" ]]

# A failed daemon-reload must retain both the journal and remaining files.
printf 'runtime-removed\n' >"$UNINSTALL_JOURNAL"
chmod 0600 "$UNINSTALL_JOURNAL"
chown root:root "$UNINSTALL_JOURNAL"
systemctl() { return 1; }
if ( printf 'REMOVE GHULAKH\n' | uninstall ); then
  echo "Recovery continued after systemd daemon-reload failure." >&2
  exit 1
fi
[[ -f "$UNINSTALL_JOURNAL" && -f "$RELEASES/partial/remnant" ]]
echo "Uninstall recovery behavioral tests passed."
