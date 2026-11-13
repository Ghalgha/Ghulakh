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
grep -Fq 'mv -Tf "$link" "$CURRENT"' "$DEPLOY"
grep -Fq 'Previous release restored when available' "$DEPLOY"
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
grep -Fq 'os.fstat(fd)' "$CREDENTIAL"
grep -Fq 'rollback_units' "$DEPLOY"
grep -Fq 'trap - EXIT HUP INT TERM' "$DEPLOY"
grep -Fq 'trap - EXIT HUP INT TERM' "$DEPLOY"
grep -Fq 'old-egress' "$DEPLOY"
grep -Fq 'old-server' "$DEPLOY"
grep -Fq 'marker_backup' "$DEPLOY"
grep -Fq 'mv -f "$tmpdir/new-egress" "$EGRESS_UNIT"' "$DEPLOY"
grep -Fq 'mv -f "$tmpdir/new-server" "$SERVER_UNIT"' "$DEPLOY"
grep -Fq 'sha256sum "$SERVER_UNIT" "$EGRESS_UNIT" >"$marker_tmp"' "$DEPLOY"
grep -Fq 'expected-gid' "$DEPLOY"
grep -Fq -- '--mode 0640' "$DEPLOY"
grep -Fq 'choices=("0600", "0640")' "$CREDENTIAL"
grep -Fq 'noise-private.generated' "$DEPLOY"
grep -Fq 'Unverified partial systemd installation found' "$DEPLOY"
grep -Fq 'Managed marker permissions are invalid' "$DEPLOY"
grep -Fq 'Refusing to replace unmanaged systemd unit' "$DEPLOY"
grep -Fq 'ExecStop=/bin/bash' "$DEPLOY"
grep -Fq 'AmbientCapabilities=CAP_NET_ADMIN' "$DEPLOY"
grep -Fq 'ProtectSystem=strict' "$DEPLOY"
grep -Fq 'systemctl disable --now ghulakh-server.service' "$DEPLOY"
grep -Fq 'rm -rf -- "$RELEASES"' "$DEPLOY"
grep -Fq 'Persistent configuration and service account remain' "$DEPLOY"

# Deployment must not edit host-global network state or broad firewall chains.
if grep -Eq 'sysctl[[:space:]]+-w|iptables|ip[[:space:]]+route[[:space:]]+(add|del)|nft[[:space:]]+(add|delete)[[:space:]]+table' "$DEPLOY"; then
  echo "Deployment script contains a forbidden host-global network mutation." >&2
  exit 1
fi
if grep -Eq 'rm[[:space:]]+-rf[[:space:]]+/(etc|usr|var)([[:space:]]|$)' "$DEPLOY"; then
  echo "Deployment script contains an unsafe absolute recursive removal." >&2
  exit 1
fi
echo "Deployment lifecycle static checks passed."
