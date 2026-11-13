#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DEPLOY="$ROOT/tools/deploy-server.sh"
EGRESS="$ROOT/tools/configure-egress-nftables.sh"
CREDENTIAL="$ROOT/tools/create_credential.py"

bash -n "$DEPLOY"
bash -n "$EGRESS"
python3 -c 'import ast, pathlib, sys; ast.parse(pathlib.Path(sys.argv[1]).read_text())' "$CREDENTIAL"
grep -Fq 'mv -Tf "$link" "$CURRENT"' "$DEPLOY"
grep -Fq 'Previous release restored when available' "$DEPLOY"
grep -Fq 'Managed by Ghulakh deployment tool' "$DEPLOY"
grep -Fq 'sha256sum -c "$MARKER"' "$DEPLOY"
grep -Fq 'Existing release content does not match its release identifier.' "$DEPLOY"
grep -Fq 'cut -c1-64 | sha256sum' "$DEPLOY"
grep -Fq 'ghulakh-egress.service' "$DEPLOY"
grep -Fq 'Required server.env setting is missing or changed' "$DEPLOY"
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
