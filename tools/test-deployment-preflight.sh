#!/usr/bin/env bash
set -euo pipefail
set -x
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
mkdir -p "$TMP/bin" "$TMP/proc/4242/fd" "$TMP/current" "$TMP/sys/class/net"
printf 'binary\n' > "$TMP/current/ghulakh-server"
ln -s "$TMP/current/ghulakh-server" "$TMP/proc/4242/exe"
printf '0::/system.slice/ghulakh-server.service\n' > "$TMP/proc/4242/cgroup"
ln -s /dev/net/tun "$TMP/proc/4242/fd/3"
export GHULAKH_PROC_ROOT="$TMP/proc" GHULAKH_SYS_CLASS_NET="$TMP/sys/class/net" CURRENT="$TMP/current"
source "$ROOT/tools/deployment-preflight.sh"
cat > "$TMP/bin/systemctl" <<'SH'
#!/usr/bin/env bash
case "$*" in
  *MainPID*) printf '%s\n' "${TEST_MAIN_PID:-0}" ;;
  *LoadState*) printf '%s\n' "${TEST_LOAD_STATE:-not-found}" ;;
  *FragmentPath*) printf '%s\n' "${TEST_FRAGMENT_PATH:-/usr/lib/systemd/system/ghulakh-server.service}" ;;
  *) exit 1 ;;
esac
SH
cat > "$TMP/bin/ss" <<'SH'
#!/usr/bin/env bash
printf '%s\n' "${TEST_SS_OUTPUT:-}"
SH
cat > "$TMP/bin/ip" <<'SH'
#!/usr/bin/env bash
if [[ "$*" == *"ghulakh0"* ]]; then
  [[ "${TEST_TUN_PRESENT:-0}" == 1 ]] || exit 1
  printf '7: ghulakh0: <POINTOPOINT,NOARP,UP> mtu 1100 type tun\n'
  exit 0
fi
exit 1
SH
chmod +x "$TMP/bin/"*
export PATH="$TMP/bin:$PATH"
export TEST_MAIN_PID=0 TEST_SS_OUTPUT="" TEST_TUN_PRESENT=0
ghulakh_preflight_udp_port 4434
ghulakh_preflight_tun_interface ghulakh0
mkdir "$TMP/sys/class/net/ghulakh0"
export TEST_MAIN_PID=4242
export TEST_SS_OUTPUT='UNCONN 0 0 0.0.0.0:4434 0.0.0.0:* users:(("ghulakh-server",pid=4242,fd=8))'
export TEST_TUN_PRESENT=1
ghulakh_preflight_udp_port 4434
ghulakh_preflight_tun_interface ghulakh0
export TEST_SS_OUTPUT='UNCONN 0 0 0.0.0.0:4434 0.0.0.0:* users:(("other",pid=9001,fd=8))'
if ghulakh_preflight_udp_port 4434 2>/dev/null; then echo "foreign UDP listener was accepted" >&2; exit 1; fi
export TEST_SS_OUTPUT='UNCONN 0 0 0.0.0.0:4434 0.0.0.0:*'
if ghulakh_preflight_udp_port 4434 2>/dev/null; then echo "unidentified UDP listener was accepted" >&2; exit 1; fi
export TEST_MAIN_PID=0 TEST_TUN_PRESENT=1
if ghulakh_preflight_tun_interface ghulakh0 2>/dev/null; then echo "unowned TUN interface was accepted" >&2; exit 1; fi
cat > "$TMP/bin/ip" <<'SH'
#!/usr/bin/env bash
printf '7: ghulakh0: <UP> mtu 1500 type dummy\n'
SH
chmod +x "$TMP/bin/ip"
if ghulakh_preflight_tun_interface ghulakh0 2>/dev/null; then echo "non-TUN interface was accepted" >&2; exit 1; fi

# Managed-layout preflight refuses foreign files and externally loaded units.
sed -n '/^assert_managed_layout() {/,/^}/p' "$ROOT/tools/deploy-server.sh" >"$TMP/assert-managed-layout.sh"
source "$TMP/assert-managed-layout.sh"
BASE="$TMP/managed-root"
RELEASES="$BASE/releases"
MARKER="$BASE/.managed-by-ghulakh"
SERVER_UNIT="$TMP/systemd/ghulakh-server.service"
EGRESS_UNIT="$TMP/systemd/ghulakh-egress.service"
safe_file() { [[ -f "$1" && ! -L "$1" ]]; }
die() { printf 'ERROR: %s\\n' "$*" >&2; exit 1; }
mkdir -p "$TMP/systemd"
TEST_LOAD_STATE=not-found
TEST_FRAGMENT_PATH=/usr/lib/systemd/system/ghulakh-server.service
assert_managed_layout

printf 'administrator-owned unit\n' >"$SERVER_UNIT"
if (assert_managed_layout) 2>/dev/null; then
  echo "Managed-layout preflight accepted a foreign server unit file." >&2
  exit 1
fi
rm -f "$SERVER_UNIT"
ln -s "$TMP/foreign-unit" "$SERVER_UNIT"
if (assert_managed_layout) 2>/dev/null; then
  echo "Managed-layout preflight accepted a symlink at the server unit path." >&2
  exit 1
fi
rm -f "$SERVER_UNIT"
export TEST_LOAD_STATE=loaded
TEST_FRAGMENT_PATH=/usr/lib/systemd/system/ghulakh-server.service
if (assert_managed_layout) 2>/dev/null; then
  echo "Managed-layout preflight accepted a systemd unit loaded outside the managed path." >&2
  exit 1
fi
echo "Deployment preflight behavioral tests passed."
