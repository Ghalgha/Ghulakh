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
case "$*" in *MainPID*) printf '%s\n' "${TEST_MAIN_PID:-0}" ;; *) exit 1 ;; esac
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
echo "Deployment preflight behavioral tests passed."
