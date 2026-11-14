#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DEPLOY="$ROOT/tools/deploy-server.sh"
TMP="$(mktemp -d)"
trap 'rm -rf -- "$TMP"' EXIT

sed -n '/^verify_release_tree() {/,/^}/p' "$DEPLOY" >"$TMP/functions.sh"
sed -n '/^uninstall() {/,/^}/p' "$DEPLOY" >>"$TMP/functions.sh"

require_root() { :; }
die() { printf 'ERROR: %s\\n' "$*" >&2; return 1; }
safe_file() { [[ -f "$1" && ! -L "$1" ]]; }
verify_release_integrity() { [[ -d "$1" && ! -L "$1" ]]; }
verify_managed_unit_runtime() { return 0; }
mktemp() {
  if [[ "${1:-}" == -d && "${2:-}" == /run/ghulakh-uninstall.* ]]; then
    command mktemp -d "$TMP/run/ghulakh-uninstall.XXXXXX"
  else
    command mktemp "$@"
  fi
}
mkdir -p "$TMP/run"

new_case() {
  CASE="$TMP/$1"
  BASE="$CASE/base"
  RELEASES="$BASE/releases"
  CURRENT="$BASE/current"
  MARKER="$BASE/.managed-by-ghulakh"
  UNINSTALL_JOURNAL="$BASE/.uninstall-in-progress"
  SERVER_UNIT="$CASE/systemd/ghulakh-server.service"
  EGRESS_UNIT="$CASE/systemd/ghulakh-egress.service"
  EGRESS_SCRIPT_NAME="configure-egress-nftables.sh"
  mkdir -p "$RELEASES/$(printf 'a%.0s' {1..64})" "$CASE/systemd" "$CASE/persistent"
  chmod 0755 "$BASE" "$RELEASES" "$RELEASES/"* "$CASE/systemd"
  chown root:root "$BASE" "$RELEASES" "$RELEASES/"*
  local release="$RELEASES/$(printf 'a%.0s' {1..64})"
  printf 'binary fixture\\n' >"$release/ghulakh-server"
  printf 'credential tool fixture\\n' >"$release/create_credential.py"
  cat >"$release/$EGRESS_SCRIPT_NAME" <<'SH'
#!/usr/bin/env bash
case "${1:-}" in
  --check-owned) exit 0 ;;
  --remove) printf 'removed\\n' >>"$EGRESS_REMOVAL_LOG"; exit 0 ;;
  *) exit 2 ;;
esac
SH
  chmod 0755 "$release/ghulakh-server" "$release/$EGRESS_SCRIPT_NAME"
  chmod 0644 "$release/create_credential.py"
  chown root:root "$release/"*
  ln -s "$release" "$CURRENT"
  printf 'Managed by Ghulakh deployment tool\\n' >"$SERVER_UNIT"
  printf 'Managed by Ghulakh deployment tool\\n' >"$EGRESS_UNIT"
  chmod 0644 "$SERVER_UNIT" "$EGRESS_UNIT"
  chown root:root "$SERVER_UNIT" "$EGRESS_UNIT"
  sha256sum "$SERVER_UNIT" "$EGRESS_UNIT" >"$MARKER"
  chmod 0600 "$MARKER"
  chown root:root "$MARKER"
  printf 'persistent data\\n' >"$CASE/persistent/credentials"
  EGRESS_REMOVAL_LOG="$CASE/egress-removal.log"
  SYSTEMCTL_LOG="$CASE/systemctl.log"
  : >"$SYSTEMCTL_LOG"
  FAIL_SERVER_STOP=0
  FAIL_EGRESS_STOP=0
  FAIL_DAEMON_RELOAD_ONCE=0
  RELOAD_COUNT=0
  FAIL_RELEASE_REMOVE=0
  source "$TMP/functions.sh"
}

systemctl() {
  printf '%s\\n' "$*" >>"$SYSTEMCTL_LOG"
  case "$*" in
    "disable --now ghulakh-server.service")
      [[ "$FAIL_SERVER_STOP" == 0 ]] || return 1
      SERVER_STOPPED=1
      ;;
    "disable --now ghulakh-egress.service")
      [[ "$FAIL_EGRESS_STOP" == 0 ]] || return 1
      EGRESS_STOPPED=1
      "$CURRENT/$EGRESS_SCRIPT_NAME" --remove
      ;;
    daemon-reload)
      RELOAD_COUNT=$((RELOAD_COUNT + 1))
      if [[ "$FAIL_DAEMON_RELOAD_ONCE" == 1 && "$RELOAD_COUNT" == 1 ]]; then return 1; fi
      ;;
    *) return 2 ;;
  esac
}
rm() {
  if [[ "$FAIL_RELEASE_REMOVE" == 1 && "${1:-}" == -rf && "${2:-}" == --one-file-system && "${3:-}" == "$RELEASES" ]]; then
    return 1
  fi
  command rm "$@"
}

# Server stop failure: no managed files or release data may be removed.
new_case server-stop-failure
FAIL_SERVER_STOP=1
if uninstall </dev/null >/dev/null 2>&1; then
  echo "Uninstall continued after server stop failure." >&2
  exit 1
fi
[[ -f "$SERVER_UNIT" && -f "$EGRESS_UNIT" && -L "$CURRENT" && -f "$MARKER" && -d "$RELEASES" ]]
[[ ! -e "$UNINSTALL_JOURNAL" && ! -e "$EGRESS_REMOVAL_LOG" ]]

# Egress stop failure: files remain; server may already be stopped.
new_case egress-stop-failure
FAIL_EGRESS_STOP=1
if uninstall </dev/null >/dev/null 2>&1; then
  echo "Uninstall continued after egress stop failure." >&2
  exit 1
fi
[[ -f "$SERVER_UNIT" && -f "$EGRESS_UNIT" && -L "$CURRENT" && -f "$MARKER" && -d "$RELEASES" ]]
[[ ! -e "$UNINSTALL_JOURNAL" && ! -e "$EGRESS_REMOVAL_LOG" ]]
grep -Fxq 'disable --now ghulakh-server.service' "$SYSTEMCTL_LOG"
! grep -Fxq 'daemon-reload' "$SYSTEMCTL_LOG"

# daemon-reload failure restores both unit files and the active release link.
new_case daemon-reload-failure
FAIL_DAEMON_RELOAD_ONCE=1
if uninstall <<<"REMOVE GHULAKH" >/dev/null 2>&1; then
  echo "Uninstall ignored daemon-reload failure." >&2
  exit 1
fi
[[ -f "$SERVER_UNIT" && -f "$EGRESS_UNIT" && -L "$CURRENT" && -f "$MARKER" && -d "$RELEASES" ]]
[[ ! -e "$UNINSTALL_JOURNAL" ]]
[[ "$(readlink -f "$CURRENT")" == "$RELEASES/$(printf 'a%.0s' {1..64})" ]]
[[ "$RELOAD_COUNT" == 2 ]]

# Release cleanup failure retains journal and data; retry completes safely.
new_case release-cleanup-failure
FAIL_RELEASE_REMOVE=1
if uninstall <<<"REMOVE GHULAKH" >/dev/null 2>&1; then
  echo "Uninstall ignored release cleanup failure." >&2
  exit 1
fi
[[ -f "$UNINSTALL_JOURNAL" && -f "$MARKER" && -d "$RELEASES" ]]
[[ ! -e "$SERVER_UNIT" && ! -e "$EGRESS_UNIT" && ! -e "$CURRENT" ]]
FAIL_RELEASE_REMOVE=0
printf 'REMOVE GHULAKH\\n' | uninstall >/dev/null
[[ ! -e "$BASE" ]]
[[ -f "$CASE/persistent/credentials" ]]

# Successful uninstall removes only runtime and preserves persistent data.
new_case successful-uninstall
printf 'REMOVE GHULAKH\\n' | uninstall >/dev/null
[[ ! -e "$BASE" && ! -e "$SERVER_UNIT" && ! -e "$EGRESS_UNIT" ]]
[[ -f "$CASE/persistent/credentials" ]]
grep -Fxq -- '--remove' "$EGRESS_REMOVAL_LOG"
echo "Uninstall transaction behavioral tests passed."
