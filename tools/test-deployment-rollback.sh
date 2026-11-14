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
      if [[ "$2" == --runtime ]]; then
        unit="$3"; ENABLE_STATE=enabled-runtime
        if [[ "${FAIL_ENABLE_UNIT_ONCE:-}" == "$unit" ]]; then FAIL_ENABLE_UNIT_ONCE=""; return 1; fi
        if [[ "$unit" == ghulakh-server.service ]]; then ENABLED_SERVER="$ENABLE_STATE"; else ENABLED_EGRESS="$ENABLE_STATE"; fi
      else
        for unit in "${@:2}"; do
          if [[ "${FAIL_ENABLE_UNIT_ONCE:-}" == "$unit" ]]; then FAIL_ENABLE_UNIT_ONCE=""; return 1; fi
          if [[ "$unit" == ghulakh-server.service ]]; then ENABLED_SERVER=enabled; else ENABLED_EGRESS=enabled; fi
        done
      fi
      ;;
    mask)
      unit="$3"
      if [[ "$unit" == ghulakh-server.service ]]; then ENABLED_SERVER=masked-runtime; else ENABLED_EGRESS=masked-runtime; fi
      ;;
    restart)
      unit="$2"
      if [[ "${FAIL_RESTART_UNIT_ONCE:-}" == "$unit" ]]; then FAIL_RESTART_UNIT_ONCE=""; return 1; fi
      if [[ "${FAIL_RESTART_UNIT:-}" == "$unit" ]]; then return 1; fi
      if [[ "$unit" == ghulakh-server.service ]]; then ACTIVE_SERVER=active; else ACTIVE_EGRESS=active; fi
      ;;
    stop)
      unit="$2"
      if [[ "$unit" == ghulakh-server.service ]]; then ACTIVE_SERVER=inactive; else ACTIVE_EGRESS=inactive; fi
      ;;
    daemon-reload)
      if [[ "${FAIL_DAEMON_RELOAD_ONCE:-0}" == 1 ]]; then FAIL_DAEMON_RELOAD_ONCE=0; return 1; fi
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


# Every activation boundary must restore the complete previous deployment.
run_activation_failure_case() {
  local case_name="$1" failure_kind="$2" failure_unit="${3:-}"
  prepare_fixture "$TMP/activation-$case_name"
  had_old_egress=1 had_old_server=1 had_old_marker=1
  old_egress_enabled=enabled-runtime old_server_enabled=disabled
  old_egress_active=active old_server_active=inactive
  LOAD_SERVER=loaded LOAD_EGRESS=loaded
  ACTIVE_SERVER=active ACTIVE_EGRESS=active
  ENABLED_SERVER=enabled ENABLED_EGRESS=enabled
  FAIL_DAEMON_RELOAD_ONCE=0 FAIL_ENABLE_UNIT_ONCE="" FAIL_RESTART_UNIT_ONCE=""
  case "$failure_kind" in
    daemon-reload) FAIL_DAEMON_RELOAD_ONCE=1 ;;
    enable) FAIL_ENABLE_UNIT_ONCE="$failure_unit" ;;
    restart) FAIL_RESTART_UNIT_ONCE="$failure_unit" ;;
    *) echo "Unknown activation failure fixture: $failure_kind" >&2; return 1 ;;
  esac

  local activation_failed=0
  if ! systemctl daemon-reload; then
    activation_failed=1
  elif ! systemctl enable ghulakh-egress.service ghulakh-server.service; then
    activation_failed=1
  elif ! systemctl restart ghulakh-egress.service; then
    activation_failed=1
  elif ! systemctl restart ghulakh-server.service; then
    activation_failed=1
  fi
  [[ "$activation_failed" == 1 ]] || {
    echo "Activation unexpectedly succeeded in $case_name." >&2
    return 1
  }

  rollback_activation
  [[ "$(readlink "$CURRENT")" == "$old_target" ]]
  cmp -s "$BASE/expected-server" "$SERVER_UNIT"
  cmp -s "$BASE/expected-egress" "$EGRESS_UNIT"
  cmp -s "$BASE/expected-marker" "$MARKER"
  [[ "$ACTIVE_EGRESS" == active && "$ENABLED_EGRESS" == enabled-runtime ]]
  [[ "$ACTIVE_SERVER" == inactive && "$ENABLED_SERVER" == disabled ]]
  [[ ! -e "$TRANSACTION_DIR" && -z "$unit_stage_dir" ]]
}

run_activation_failure_case daemon-reload daemon-reload
run_activation_failure_case enable-egress enable ghulakh-egress.service
run_activation_failure_case enable-server enable ghulakh-server.service
run_activation_failure_case restart-egress restart ghulakh-egress.service
run_activation_failure_case restart-server restart ghulakh-server.service

echo "Deployment rollback behavioral tests passed."
