#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DEPLOY="$ROOT/tools/deploy-server.sh"
EGRESS="$ROOT/tools/configure-egress-nftables.sh"
CREDENTIAL="$ROOT/tools/create_credential.py"

bash -n "$DEPLOY"
bash -n "$EGRESS"
python3 -c 'import ast, pathlib, sys; ast.parse(pathlib.Path(sys.argv[1]).read_text())' "$CREDENTIAL"
python3 "$ROOT/tools/test_credential_file_safety.py"

# Exercise rollback verification against controlled systemd state responses.
ROLLBACK_HELPER="$(mktemp)"
trap 'rm -f -- "$ROLLBACK_HELPER"' EXIT
sed -n '/^  verify_rollback_unit_state() {/,/^  }/p' "$DEPLOY" >"$ROLLBACK_HELPER"
source "$ROLLBACK_HELPER"
SYSTEMD_LOAD=loaded SYSTEMD_ACTIVE=active SYSTEMD_ENABLED=enabled SYSTEMD_QUERY_FAILED=0
systemctl() {
  case "$1 $2 $3" in
    "show --property=LoadState --value") [[ "$SYSTEMD_QUERY_FAILED" == 0 ]] || return 1; printf '%s\\n' "$SYSTEMD_LOAD" ;;
    "show --property=ActiveState --value") [[ "$SYSTEMD_QUERY_FAILED" == 0 ]] || return 1; printf '%s\\n' "$SYSTEMD_ACTIVE" ;;
    "is-enabled "*) printf '%s\\n' "$SYSTEMD_ENABLED" ;;
    *) return 2 ;;
  esac
}
verify_rollback_unit_state ghulakh-server.service loaded active enabled
SYSTEMD_ACTIVE=inactive SYSTEMD_ENABLED=disabled
verify_rollback_unit_state ghulakh-server.service loaded inactive disabled
SYSTEMD_LOAD=not-found
verify_rollback_unit_state ghulakh-server.service not-found "" ""
SYSTEMD_LOAD=loaded SYSTEMD_ACTIVE=failed
if verify_rollback_unit_state ghulakh-server.service loaded active enabled 2>/dev/null; then
  echo "Rollback accepted an incorrect service activity state." >&2
  exit 1
fi
SYSTEMD_ACTIVE=active SYSTEMD_ENABLED=masked
if verify_rollback_unit_state ghulakh-server.service loaded active enabled 2>/dev/null; then
  echo "Rollback accepted an incorrect service enablement state." >&2
  exit 1
fi
SYSTEMD_LOAD=not-found SYSTEMD_QUERY_FAILED=1
if verify_rollback_unit_state ghulakh-server.service not-found "" "" 2>/dev/null; then
  echo "Rollback accepted an unreadable systemd state." >&2
  exit 1
fi
grep -Fq 'mv -Tf "$link" "$CURRENT"' "$DEPLOY"
grep -Fq 'Previous deployment state was restored; persistent configuration was preserved.' "$DEPLOY"
grep -Fq 'Managed by Ghulakh deployment tool' "$DEPLOY"
grep -Fq 'sha256sum -c "$MARKER"' "$DEPLOY"
grep -Fq 'Existing release content does not match its release identifier.' "$DEPLOY"
grep -Fq 'cut -c1-64 | sha256sum' "$DEPLOY"
grep -Fq 'getent passwd' "$DEPLOY"
grep -Fq 'account_home account_shell' "$DEPLOY"
grep -Fq 'ExecStartPre=/usr/bin/test -c /dev/net/tun' "$DEPLOY"
grep -Fq 'systemd-analyze verify' "$DEPLOY"
grep -Fq 'ghulakh-egress.service' "$DEPLOY"
grep -Fq 'Unverified partial systemd installation found' "$DEPLOY"
grep -Fq '.current.$BASHPID.$RANDOM' "$DEPLOY"
grep -Fq 'Required server.env setting is missing or changed' "$DEPLOY"
grep -Fq 'root:$NAME:750' "$DEPLOY"
grep -Fq 'root:$NAME:640' "$DEPLOY"
grep -Fq 'O_NOFOLLOW' "$CREDENTIAL"
grep -Fq '[[ ! -e "$ENV_FILE" && ! -L "$ENV_FILE" ]]' "$DEPLOY"
grep -Fq 'os.fstat(fd)' "$CREDENTIAL"
grep -Fq 'rollback_units' "$DEPLOY"
grep -Fq 'verify_rollback_unit_state ghulakh-server.service' "$DEPLOY"
grep -Fq 'cmp -s "$transaction_dir/old-marker" "$MARKER"' "$DEPLOY"
grep -Fq 'trap - EXIT HUP INT TERM' "$DEPLOY"
grep -Fq 'old-egress' "$DEPLOY"
grep -Fq 'old-server' "$DEPLOY"
grep -Fq 'marker_backup' "$DEPLOY"
grep -Fq 'mv -f "$tmpdir/new-egress" "$EGRESS_UNIT"' "$DEPLOY"
grep -Fq 'mv -f "$tmpdir/new-server" "$SERVER_UNIT"' "$DEPLOY"
grep -Fq 'sha256sum "$SERVER_UNIT" "$EGRESS_UNIT" >"$marker_tmp"' "$DEPLOY"
grep -Fq 'Reserve the new managed root before staging' "$DEPLOY"
grep -Fq 'if [[ ! -e "$MARKER" ]]; then install -o root -g root -m 0600 /dev/null "$MARKER"; fi' "$DEPLOY"
grep -Fq 'expected-gid' "$DEPLOY"
grep -Fq -- '--mode 0640' "$DEPLOY"
grep -Fq 'choices=("0600", "0640")' "$CREDENTIAL"
grep -Fq 'noise-private.generated' "$DEPLOY"
grep -Fq 'Unverified partial systemd installation found' "$DEPLOY"
grep -Fq 'Managed marker permissions are invalid' "$DEPLOY"
grep -Fq 'if [[ -e "$unit" || -L "$unit" ]]' "$DEPLOY"
grep -Fq 'systemctl enable --runtime ghulakh-egress.service' "$DEPLOY"
grep -Fq 'systemctl mask --runtime ghulakh-egress.service' "$DEPLOY"
grep -Fq 'Unsupported previous enablement state' "$DEPLOY"
grep -Fq 'Unsupported previous activity state' "$DEPLOY"
grep -Fq 'for unit_name in ghulakh-egress.service ghulakh-server.service; do' "$DEPLOY"
grep -Fq 'unit_load_state="$(systemctl show --property=LoadState --value "$unit_name" 2>/dev/null || true)"' "$DEPLOY"
grep -Fq 'Refusing unmanaged systemd unit outside' "$DEPLOY"
grep -Fq 'WAN interface and IPv6 mode are immutable for an installed deployment' "$DEPLOY"
grep -Fq 'Active release exists without a populated ownership marker' "$DEPLOY"
grep -Fq 'Managed marker or systemd units exist without an active release' "$DEPLOY"
grep -Fq 'Active release exists without both regular managed systemd units' "$DEPLOY"
grep -Fq 'Current release symlink is dangling or does not resolve to a real directory' "$DEPLOY"
grep -Fq 'ExecStart=/bin/bash $CURRENT/$EGRESS_SCRIPT_NAME ghulakh0 $WAN $IPV6_MODE' "$DEPLOY"
grep -Fq 'partial snapshot removed' "$DEPLOY"
grep -Fq 'disable --now ghulakh-egress.service >/dev/null 2>&1 || failed=1' "$DEPLOY"
grep -Fq 'disable --now ghulakh-server.service >/dev/null 2>&1 || failed=1' "$DEPLOY"
grep -Fq 'ExecStop=/bin/bash' "$DEPLOY"
grep -Fq 'AmbientCapabilities=CAP_NET_ADMIN' "$DEPLOY"
grep -Fq 'ProtectSystem=strict' "$DEPLOY"
grep -Fq 'systemctl disable --now ghulakh-server.service' "$DEPLOY"
grep -Fq 'verify_release_tree "$RELEASES"' "$DEPLOY"
grep -Fq 'Empty ownership marker is not an unambiguous incomplete-install reservation' "$DEPLOY"
grep -Fq 'rm -rf --one-file-system "$RELEASES"' "$DEPLOY"
grep -Fq 'UNINSTALL_JOURNAL="/usr/local/lib/ghulakh/.uninstall-in-progress"' "$DEPLOY"
grep -Fq 'An interrupted uninstall is pending; resume uninstall before installing or updating.' "$DEPLOY"
grep -Fq '$(cat "$UNINSTALL_JOURNAL") == runtime-removed' "$DEPLOY"
grep -Fq 'recovery journal retained for retry' "$DEPLOY"
grep -Fq 'index($5, root "/") == 1' "$DEPLOY"
grep -Fq 'backup_dir="$(mktemp -d /run/ghulakh-uninstall.XXXXXX)"' "$DEPLOY"
grep -Fq 'uninstall rollback incomplete' "$DEPLOY"
grep -Fq 'Active release directory is not a root-owned directory' "$DEPLOY"
grep -Fq 'rm -rf --one-file-system "$RELEASES"' "$DEPLOY"
grep -Fq 'Persistent configuration and service account remain' "$DEPLOY"
grep -Fq 'ghulakh_preflight_udp_port 4434' "$DEPLOY"
grep -Fq 'ghulakh_preflight_tun_interface' "$DEPLOY"
grep -Fq 'systemctl --no-pager --full status ghulakh-server.service || failed=1' "$DEPLOY"
grep -Fq 'systemctl --no-pager --full status ghulakh-egress.service || failed=1' "$DEPLOY"
grep -Fq 'find "$release_root" -xdev' "$DEPLOY"
grep -Fq 'existing_tables="$(owned_tables)"' "$EGRESS"
grep -Fq 'command -v python3' "$EGRESS"
grep -Fq '"$active_release/$EGRESS_SCRIPT_NAME" --check-active "$ipv6_mode"' "$DEPLOY"
grep -Fq 'ipv6_mode="$(awk' "$DEPLOY"
grep -Fq -- '--check-active' "$EGRESS"
grep -Fq 'verify_release_integrity "$RELEASES"' "$DEPLOY"
grep -Fq 'expected_id="$(sha256sum "$release_dir/ghulakh-server"' "$DEPLOY"
grep -Fq 'nft -j list tables' "$EGRESS"
grep -Fq 'table.get("comment") != "ghulakh-egress-v1"' "$EGRESS"

# Deployment must not edit host-global network state or broad firewall chains.
if grep -Eq 'sysctl[[:space:]]+-w|iptables|ip[[:space:]]+route[[:space:]]+(add|del)|nft[[:space:]]+(add|delete)[[:space:]]+table' "$DEPLOY"; then
  echo "Deployment script contains a forbidden host-global network mutation." >&2
  exit 1
fi
if grep -Eq 'rm[[:space:]]+-rf[[:space:]]+/(etc|usr|var)([[:space:]]|$)' "$DEPLOY"; then
  echo "Deployment script contains an unsafe absolute recursive removal." >&2
  exit 1
fi
bash "$ROOT/tools/test-deployment-preflight.sh"
sudo bash "$ROOT/tools/test-egress-ownership.sh"
sudo bash "$ROOT/tools/test-release-ownership.sh"
sudo bash "$ROOT/tools/test-release-integrity.sh"
sudo bash "$ROOT/tools/test-uninstall-recovery.sh"
echo "Deployment lifecycle static checks passed."
