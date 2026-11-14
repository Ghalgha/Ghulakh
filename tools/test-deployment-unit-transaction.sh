#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DEPLOY="$ROOT/tools/deploy-server.sh"
TMP="$(mktemp -d)"
trap 'rm -rf -- "$TMP"' EXIT

sed -n '/^write_units() {/,/^}/p' "$DEPLOY" >"$TMP/write-units.sh"
source "$TMP/write-units.sh"

BASE=""
CURRENT=""
MARKER=""
SERVER_UNIT=""
EGRESS_UNIT=""
NAME=ghulakh
ENV_FILE=/etc/ghulakh/server.env
EGRESS_SCRIPT_NAME=configure-egress-nftables.sh
CREDENTIAL_TOOL_NAME=create_credential.py
unit_stage_dir=""

# Keep the production function intact while redirecting its temporary unit
# directory into this isolated fixture.
mktemp() {
  if [[ "${@: -1}" == /etc/systemd/system/.ghulakh-units.XXXXXX ]]; then
    command mktemp -d "$TMP/systemd-units.XXXXXX"
  else
    command mktemp "$@"
  fi
}

systemd-analyze() {
  [[ "${FAIL_VERIFY:-0}" != 1 ]]
}

cp() {
  if [[ "${FAIL_MARKER_BACKUP:-0}" == 1 && "${3:-}" == "$MARKER" && "${4:-}" == "$marker_backup" ]]; then
    printf 'partial marker snapshot\n' >"$marker_backup"
    return 1
  fi
  command cp "$@"
}

mv() {
  if [[ -n "${FAIL_MV_DEST:-}" && "${3:-}" == "$FAIL_MV_DEST" ]]; then
    FAIL_MV_DEST=""
    return 1
  fi
  command mv "$@"
}

sha256sum() {
  if [[ "${FAIL_SHA256_ONCE:-0}" == 1 ]]; then
    FAIL_SHA256_ONCE=0
    return 1
  fi
  command sha256sum "$@"
}

prepare_fixture() {
  local name="$1"
  local root="$TMP/$name"
  mkdir -p "$root/systemd" "$root/base/releases"
  BASE="$root/base"
  CURRENT="$BASE/current"
  MARKER="$BASE/.managed-by-ghulakh"
  SERVER_UNIT="$root/systemd/ghulakh-server.service"
  EGRESS_UNIT="$root/systemd/ghulakh-egress.service"
  printf 'previous server unit\n' >"$SERVER_UNIT"
  printf 'previous egress unit\n' >"$EGRESS_UNIT"
  printf 'previous ownership marker\n' >"$MARKER"
  chmod 0600 "$MARKER"
  unset FAIL_VERIFY FAIL_MARKER_BACKUP FAIL_MV_DEST FAIL_SHA256_ONCE
  unit_stage_dir=""
}

assert_previous_state() {
  [[ "$(cat "$SERVER_UNIT")" == 'previous server unit' ]]
  [[ "$(cat "$EGRESS_UNIT")" == 'previous egress unit' ]]
  [[ "$(cat "$MARKER")" == 'previous ownership marker' ]]
  [[ -z "$unit_stage_dir" || ! -e "$unit_stage_dir" ]]
}

# A failure while taking the marker snapshot must not leave a partial backup.
prepare_fixture marker-snapshot
FAIL_MARKER_BACKUP=1
if write_units eth0 nat66; then
  echo "write_units accepted a failed ownership-marker snapshot." >&2
  exit 1
fi
assert_previous_state
if compgen -G "$BASE/.managed-by-ghulakh.backup.*" >/dev/null; then
  echo "write_units left a partial ownership-marker backup." >&2
  exit 1
fi

# Failure after the first unit rename must restore both units and the marker.
prepare_fixture second-unit-rename
FAIL_MV_DEST="$SERVER_UNIT"
if write_units eth0 nat66; then
  echo "write_units accepted a failed second unit rename." >&2
  exit 1
fi
assert_previous_state

# Failure while creating the ownership marker must restore all replaced files.
prepare_fixture marker-write
FAIL_SHA256_ONCE=1
if write_units eth0 nat66; then
  echo "write_units accepted a failed ownership-marker write." >&2
  exit 1
fi
assert_previous_state

# Successful installation must publish both units and a matching marker.
prepare_fixture success
write_units eth0 routed
[[ -z "$unit_stage_dir" ]]
grep -Fq 'ExecStart=/bin/bash '"$CURRENT"'/configure-egress-nftables.sh ghulakh0 eth0 routed' "$EGRESS_UNIT"
grep -Fq 'ExecStart='"$CURRENT"'/ghulakh-server' "$SERVER_UNIT"
sha256sum -c "$MARKER" >/dev/null

# First-install failure must remove both newly created unit files and preserve the empty reservation marker.
prepare_fixture first-install
rm -f "$SERVER_UNIT" "$EGRESS_UNIT"
: >"$MARKER"
FAIL_MV_DEST="$SERVER_UNIT"
if write_units eth0 nat66; then
  echo "write_units accepted a failed first-install unit rename." >&2
  exit 1
fi
[[ ! -e "$SERVER_UNIT" && ! -e "$EGRESS_UNIT" && -f "$MARKER" && ! -s "$MARKER" ]]
[[ -z "$unit_stage_dir" ]]

echo "Deployment unit transaction tests passed."
