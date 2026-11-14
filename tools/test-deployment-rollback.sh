#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DEPLOY="$ROOT/tools/deploy-server.sh"
TMP="$(mktemp -d)"
trap 'rm -rf -- "$TMP"' EXIT

sed -n '/^  stop_uncommitted_unit() {/,/^  }/p' "$DEPLOY" >"$TMP/rollback-functions.sh"
sed -n '/^  verify_rollback_unit_state() {/,/^  }/p' "$DEPLOY" >>"$TMP/rollback-functions.sh"
sed -n '/^  rollback_activation() {/,/^  }/p' "$DEPLOY" >>"$TMP/rollback-functions.sh"
source "$TMP/rollback-functions.sh"

systemctl() {
  local unit prop
  case "$1" in
    show)
      prop="$2"; unit="$4"
      case "$unit:$prop" in
        ghulakh-server.service:--property=LoadState) printf '%s\n' "$LOAD_SERVER" ;;
        ghulakh-egress.service:--property=LoadState) printf '%s\n' "$LOAD_EGRESS" ;;
        ghulakh-server.service:--property=ActiveState) printf '%s\n' "$ACTIVE_SERVER" ;;
        ghulakh-egress.service:--property=ActiveState) printf '%s\n' "$ACTIVE_EGRESS" ;;
        *) return 2 ;;
      esac
      ;;
    is-enabled)
      case "$2" in
        ghulakh-server.service) printf '%s\n' "$ENABLED_SERVER" ;;
        ghulakh-egress.service) printf '%s\n' "$ENABLED_EGRESS" ;;
        *) return 2 ;;
      esac
      ;;
    disable)
      if [[ "$2" == --now ]]; then unit="$3"; else unit="$2"; fi
      case "$unit" in
        ghulakh-server.service) ENABLED_SERVER=disabled; ACTIVE_SERVER=inactive ;;
        ghulakh-egress.service) ENABLED_EGRESS=disabled; ACTIVE_EGRESS=inactive ;;
        *) return 2 ;;
      esac
      ;;
    enable)
      if [[ "$2" == --runtime ]]; then unit="$3"; ENABLE_STATE=enabled-runtime; else unit="$2"; ENABLE_STATE=enabled; fi
      if [[ "$unit" == ghulakh-server.service ]]; then ENABLED_SERVER="$ENABLE_STATE"; else ENABLED_EGRESS="$ENABLE_STATE"; fi
      ;;
    mask)
      unit="$3"
      if [[ "$unit" == ghulakh-server.service ]]; then ENABLED_SERVER=masked-runtime; else ENABLED_EGRESS=masked-runtime; fi
      ;;
    restart)
      unit="$2"
      if [[ "${FAIL_RESTART_UNIT:-}" == "$unit" ]]; then return 1; fi
      if [[ "$unit" == ghulakh-server.service ]]; then ACTIVE_SERVER=active; else ACTIVE_EGRESS=active; fi
      ;;
    stop)
      unit="$2"
      if [[ "$unit" == ghulakh-server.service ]]; then ACTIVE_SERVER=inactive; else ACTIVE_EGRESS=inactive; fi
      ;;
    daemon-reload)
      if [[ -f "$SERVER_UNIT" ]]; then LOAD_SERVER=loaded; else LOAD_SERVER=not-found; fi
      if [[ -f "$EGRESS_UNIT" ]]; then LOAD_EGRESS=loaded; else LOAD_EGRESS=not-found; fi
      return 0
      ;;
    *) return 2 ;;
  esac
}

prepare_fixture() {
  BASE="$1/base"
  RELEASES="$BASE/releases"
  CURRENT="$BASE/current"
  MARKER="$BASE/.managed-by-ghulakh"
  SERVER_UNIT="$1/systemd/ghulakh-server.service"
  EGRESS_UNIT="$1/systemd/ghulakh-egress.service"
  mkdir -p "$RELEASES/old" "$RELEASES/new" "$(dirname "$SERVER_UNIT")" "$BASE/transaction"
  TRANSACTION_DIR="$BASE/transaction"
  transaction_dir="$TRANSACTION_DIR"
  unit_stage_dir="$1/unit-stage"
  mkdir -p "$unit_stage_dir"
  printf 'old server unit\n' >"$TRANSACTION_DIR/old-server"
  printf 'old egress unit\n' >"$TRANSACTION_DIR/old-egress"
  printf 'old marker\n' >"$TRANSACTION_DIR/old-marker"
  cp "$TRANSACTION_DIR/old-server" "$BASE/expected-server"
  cp "$TRANSACTION_DIR/old-egress" "$BASE/expected-egress"
  cp "$TRANSACTION_DIR/old-marker" "$BASE/expected-marker"
  printf 'new server unit\n' >"$SERVER_UNIT"
  printf 'new egress unit\n' >"$EGRESS_UNIT"
  printf 'new marker\n' >"$MARKER"
  ln -s "$RELEASES/new" "$CURRENT"
  old_target="$RELEASES/old"
}

# Update rollback: restore both units, marker, current and prior runtime states.
prepare_fixture "$TMP/update"
had_old_egress=1 had_old_server=1 had_old_marker=1
old_egress_enabled=enabled-runtime old_server_enabled=disabled
old_egress_active=active old_server_active=inactive
LOAD_SERVER=loaded LOAD_EGRESS=loaded
ACTIVE_SERVER=failed ACTIVE_EGRESS=active
ENABLED_SERVER=enabled ENABLED_EGRESS=enabled
rollback_activation
[[ "$(readlink "$CURRENT")" == "$old_target" ]]
cmp -s "$BASE/expected-server" "$SERVER_UNIT"
cmp -s "$BASE/expected-egress" "$EGRESS_UNIT"
cmp -s "$BASE/expected-marker" "$MARKER"
[[ "$ACTIVE_EGRESS" == active && "$ENABLED_EGRESS" == enabled-runtime ]]
[[ "$ACTIVE_SERVER" == inactive && "$ENABLED_SERVER" == disabled ]]
[[ ! -e "$TRANSACTION_DIR" && -z "$unit_stage_dir" ]]

# First-install rollback: stop newly loaded units before deleting their unit files.
prepare_fixture "$TMP/first-install"
had_old_egress=0 had_old_server=0 had_old_marker=0
old_target=""
LOAD_SERVER=loaded LOAD_EGRESS=loaded
ACTIVE_SERVER=active ACTIVE_EGRESS=active
ENABLED_SERVER=enabled ENABLED_EGRESS=enabled
rollback_activation
[[ ! -e "$CURRENT" && ! -e "$SERVER_UNIT" && ! -e "$EGRESS_UNIT" && ! -e "$MARKER" ]]
[[ "$LOAD_SERVER" == not-found && "$LOAD_EGRESS" == not-found ]]
[[ "$ACTIVE_SERVER" == inactive && "$ACTIVE_EGRESS" == inactive ]]
[[ -d "$RELEASES/old" && -d "$RELEASES/new" && -z "$unit_stage_dir" ]]

# If restoration commands fail and the resulting state is wrong, retain snapshots.
prepare_fixture "$TMP/failed-rollback"
had_old_egress=1 had_old_server=1 had_old_marker=1
old_egress_enabled=enabled old_server_enabled=enabled
old_egress_active=active old_server_active=active
LOAD_SERVER=loaded LOAD_EGRESS=loaded
ACTIVE_SERVER=inactive ACTIVE_EGRESS=inactive
ENABLED_SERVER=enabled ENABLED_EGRESS=enabled
FAIL_RESTART_UNIT=ghulakh-egress.service
if rollback_activation; then
  echo "Rollback reported success after the previous egress service failed to restart." >&2
  exit 1
fi
[[ -d "$TRANSACTION_DIR" && "$(readlink "$CURRENT")" == "$old_target" ]]
cmp -s "$TRANSACTION_DIR/old-server" "$SERVER_UNIT"
cmp -s "$TRANSACTION_DIR/old-egress" "$EGRESS_UNIT"
cmp -s "$TRANSACTION_DIR/old-marker" "$MARKER"

echo "Deployment rollback behavioral tests passed."
