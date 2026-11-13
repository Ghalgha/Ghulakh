#!/usr/bin/env bash
# Managed server deployment. Only Ghulakh-owned paths, units and nftables tables are changed.
set -Eeuo pipefail
umask 077
readonly NAME="ghulakh" BASE="/usr/local/lib/ghulakh" RELEASES="/usr/local/lib/ghulakh/releases"
readonly CURRENT="/usr/local/lib/ghulakh/current" MARKER="/usr/local/lib/ghulakh/.managed-by-ghulakh"
readonly CONFIG="/etc/ghulakh" ENV_FILE="/etc/ghulakh/server.env"
readonly CREDENTIALS="/etc/ghulakh/device-credentials.sha256"
readonly NOISE_PRIVATE="/etc/ghulakh/noise_private.hex" NOISE_PUBLIC="/etc/ghulakh/noise_public.hex"
readonly SERVER_UNIT="/etc/systemd/system/ghulakh-server.service"
readonly EGRESS_UNIT="/etc/systemd/system/ghulakh-egress.service"
readonly EGRESS_SCRIPT_NAME="configure-egress-nftables.sh"
readonly CREDENTIAL_TOOL_NAME="create_credential.py"

die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
usage() {
  cat <<'USAGE'
Usage:
  sudo bash tools/deploy-server.sh install|update --binary FILE --wan-interface IFACE [--ipv6-mode nat66|routed]
  sudo bash tools/deploy-server.sh credential
  sudo bash tools/deploy-server.sh status
  sudo bash tools/deploy-server.sh uninstall

Install/update stage a binary and atomically switch the current release.
WAN interface and IPv6 mode must remain unchanged during updates.
Sysctls, routes, INPUT firewall rules and unrelated services are never changed.
Uninstall preserves /etc/ghulakh, /var/lib/ghulakh and the service account.
USAGE
  exit 2
}
require_root() { [[ $EUID -eq 0 ]] || die "Run as root."; }
require_command() { command -v "$1" >/dev/null 2>&1 || die "Missing command: $1"; }
safe_file() { [[ -f "$1" && ! -L "$1" ]]; }

check_platform() {
  [[ -d /run/systemd/system ]] || die "A running systemd system is required."
  [[ -c /dev/net/tun ]] || die "/dev/net/tun is unavailable."
  [[ -r /proc/sys/net/ipv4/ip_forward && $(< /proc/sys/net/ipv4/ip_forward) == 1 ]] || die "Enable net.ipv4.ip_forward=1 administratively."
  [[ -r /proc/sys/net/ipv6/conf/all/forwarding && $(< /proc/sys/net/ipv6/conf/all/forwarding) == 1 ]] || die "Enable net.ipv6.conf.all.forwarding=1 administratively."
  for cmd in systemctl systemd-analyze install ip nft runuser useradd getent python3 sha256sum readlink stat; do require_command "$cmd"; done
}
parse_args() {
  ACTION="$1"; shift
  BINARY=""; WAN=""; IPV6_MODE="nat66"
  while (($#)); do
    case "$1" in
      --binary) (($# >= 2)) || usage; BINARY="$2"; shift 2 ;;
      --wan-interface) (($# >= 2)) || usage; WAN="$2"; shift 2 ;;
      --ipv6-mode) (($# >= 2)) || usage; IPV6_MODE="$2"; shift 2 ;;
      *) usage ;;
    esac
  done
  [[ -n "$BINARY" && -n "$WAN" ]] || usage
  [[ "$WAN" =~ ^[a-zA-Z0-9_.-]{1,15}$ ]] || die "Invalid WAN interface name."
  [[ "$IPV6_MODE" == nat66 || "$IPV6_MODE" == routed ]] || die "IPv6 mode must be nat66 or routed."
  safe_file "$BINARY" && [[ -x "$BINARY" ]] || die "Binary must be an executable regular file, not a symlink."
  ip link show "$WAN" >/dev/null 2>&1 || die "WAN interface does not exist: $WAN"
}
assert_managed_layout() {
  if [[ -e "$BASE" || -L "$BASE" ]]; then
    [[ -d "$BASE" && ! -L "$BASE" && -f "$MARKER" && ! -L "$MARKER" ]] || die "$BASE is not a verified managed installation; refusing to adopt or overwrite it."
    [[ $(stat -c "%U:%G" "$BASE") == root:root ]] || die "Managed release root must be owned by root:root."
  fi
  if [[ -e "$RELEASES" || -L "$RELEASES" ]]; then
    [[ -d "$RELEASES" && ! -L "$RELEASES" && $(stat -c "%U:%G" "$RELEASES") == root:root ]] || die "Managed releases path is not a root-owned directory."
  fi
  for unit in "$SERVER_UNIT" "$EGRESS_UNIT"; do
    if [[ -e "$unit" ]]; then
      safe_file "$unit" || die "Refusing non-regular unit path: $unit"
      grep -Fq 'Managed by Ghulakh deployment tool' "$unit" || die "Refusing to replace unmanaged systemd unit: $unit"
    fi
  done
  if [[ -e "$MARKER" ]]; then
    [[ $(stat -c "%U:%G:%a" "$MARKER") == root:root:600 ]] || die "Managed marker permissions are invalid."
  fi
  if [[ -s "$MARKER" ]]; then sha256sum -c "$MARKER" >/dev/null || die "Managed systemd unit checksum mismatch; refusing to overwrite or remove modified units."; fi
}
ensure_account() {
  if ! id "$NAME" >/dev/null 2>&1; then
    [[ ! -e "$MARKER" && ! -e "$BASE" ]] || die "Managed marker exists but service account is missing."
    useradd --system --home-dir /var/lib/ghulakh --no-create-home --shell /usr/sbin/nologin "$NAME"
  else
    local account_entry account_name account_password account_uid account_gid account_gecos account_home account_shell
    account_entry="$(getent passwd "$NAME")"
    IFS=: read -r account_name account_password account_uid account_gid account_gecos account_home account_shell <<<"$account_entry"
    [[ "$account_home" == /var/lib/ghulakh && "$account_shell" == /usr/sbin/nologin ]] || die "Existing ghulakh account has an unexpected home or shell; refusing to adopt it."
  fi
  for directory in /var/lib/ghulakh "$CONFIG"; do
    if [[ -e "$directory" ]]; then
      [[ -d "$directory" && ! -L "$directory" ]] || die "Refusing non-directory or symlink path: $directory"
      [[ $(stat -c '%U:%G' "$directory") == "$NAME:$NAME" ]] || die "Existing directory $directory must be owned by $NAME:$NAME; it was left unchanged."
    else
      install -d -o "$NAME" -g "$NAME" -m 0700 "$directory"
    fi
  done
}
ensure_config() {
  if [[ ! -e "$CREDENTIALS" ]]; then
    install -o "$NAME" -g "$NAME" -m 0600 /dev/null "$CREDENTIALS"
  else
    safe_file "$CREDENTIALS" || die "Credential digest path must be a regular file."
    [[ $(stat -c '%U:%G:%a' "$CREDENTIALS") == "$NAME:$NAME:600" ]] || die "Credential digest file must be owned by $NAME:$NAME mode 0600; left unchanged."
  fi
  if [[ -e "$NOISE_PRIVATE" || -e "$NOISE_PUBLIC" ]]; then
    safe_file "$NOISE_PRIVATE" && safe_file "$NOISE_PUBLIC" || die "Both Noise key files must be regular files."
    [[ $(stat -c '%U:%G:%a' "$NOISE_PRIVATE") == "$NAME:$NAME:600" ]] || die "Noise private key must be owned by $NAME:$NAME mode 0600."
    [[ $(stat -c '%U:%G:%a' "$NOISE_PUBLIC") == "$NAME:$NAME:644" ]] || die "Noise public key must be owned by $NAME:$NAME mode 0644."
  else
    runuser -u "$NAME" -- "$STAGED_BINARY" --generate-noise-keypair "$NOISE_PRIVATE" "$NOISE_PUBLIC" >/dev/null
  fi
  if [[ ! -e "$ENV_FILE" ]]; then
    local tmp
    tmp="$(mktemp "$CONFIG/server.env.XXXXXX")"
    cat >"$tmp" <<EOF
GHULAKH_CREDENTIAL_HASHES=$CREDENTIALS
GHULAKH_TUN_ENABLED=true
GHULAKH_FORWARDING_ENABLED=true
GHULAKH_TUN_NAME=ghulakh0
GHULAKH_TURN_GATEWAY_BIND=0.0.0.0:4434
GHULAKH_NOISE_PRIVATE_KEY=$NOISE_PRIVATE
GHULAKH_NOISE_PUBLIC_KEY=$NOISE_PUBLIC
EOF
    install -o root -g "$NAME" -m 0640 "$tmp" "$ENV_FILE"
    rm -f "$tmp"
  else
    safe_file "$ENV_FILE" || die "Server environment file must be a regular file."
    [[ $(stat -c '%U:%G:%a' "$ENV_FILE") == "root:$NAME:640" ]] || die "server.env must be root:$NAME mode 0640; left unchanged."
  fi
}
write_units() {
  local wan="$1" mode="$2" tmpdir a b
  tmpdir="$(mktemp -d)"
  a="$tmpdir/ghulakh-egress.service"; b="$tmpdir/ghulakh-server.service"
  cat >"$a" <<EOF
# Managed by Ghulakh deployment tool
[Unit]
Description=Ghulakh owned VPN egress policy
Wants=network-online.target
After=network-online.target nftables.service
Before=ghulakh-server.service
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/bash $CURRENT/$EGRESS_SCRIPT_NAME ghulakh0 $wan $mode
ExecStop=/bin/bash $CURRENT/$EGRESS_SCRIPT_NAME --remove
[Install]
WantedBy=multi-user.target
EOF
  cat >"$b" <<EOF
# Managed by Ghulakh deployment tool
[Unit]
Description=Ghulakh protected TURN VPN gateway
Requires=ghulakh-egress.service
After=network-online.target ghulakh-egress.service
Wants=network-online.target
[Service]
Type=simple
User=$NAME
Group=$NAME
EnvironmentFile=$ENV_FILE
ExecStartPre=/usr/bin/test -c /dev/net/tun
ExecStart=$CURRENT/ghulakh-server
Restart=on-failure
RestartSec=3
UMask=0077
LimitNOFILE=65536
AmbientCapabilities=CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_ADMIN
DeviceAllow=/dev/net/tun rw
PrivateDevices=no
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
PrivateTmp=yes
RestrictSUIDSGID=yes
LockPersonality=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK
RuntimeDirectory=ghulakh
RuntimeDirectoryMode=0700
StateDirectory=ghulakh
StateDirectoryMode=0700
[Install]
WantedBy=multi-user.target
EOF
  systemd-analyze verify "$a" "$b" || { rm -f "$a" "$b"; rmdir "$tmpdir"; return 1; }
  if [[ -e "$EGRESS_UNIT" ]] && ! cmp -s "$a" "$EGRESS_UNIT"; then
    rm -f "$a" "$b"; rmdir "$tmpdir"
    return 1
  fi
  if [[ -e "$SERVER_UNIT" ]] && ! cmp -s "$b" "$SERVER_UNIT"; then
    rm -f "$a" "$b"; rmdir "$tmpdir"
    return 1
  fi
  install -o root -g root -m 0644 "$a" "$EGRESS_UNIT"
  install -o root -g root -m 0644 "$b" "$SERVER_UNIT"
  rm -f "$a" "$b"; rmdir "$tmpdir"
}
deploy() {
  require_root
  check_platform
  parse_args "$@"
  assert_managed_layout
  local egress_tool credential_tool release_id release_dir old_target link
  egress_tool="$(cd "$(dirname "$0")" && pwd)/$EGRESS_SCRIPT_NAME"
  credential_tool="$(cd "$(dirname "$0")" && pwd)/$CREDENTIAL_TOOL_NAME"
  safe_file "$egress_tool" && safe_file "$credential_tool" || die "Deployment helper files are missing."
  bash -n "$egress_tool"
  ensure_account
  install -d -o root -g root -m 0755 "$BASE" "$RELEASES"
  if [[ ! -e "$MARKER" ]]; then install -o root -g root -m 0600 /dev/null "$MARKER"; fi
  release_id="$(sha256sum "$BINARY" "$egress_tool" "$credential_tool" | cut -c1-64 | sha256sum | cut -c1-64)"
  release_dir="$RELEASES/$release_id"
  if [[ -e "$release_dir" || -L "$release_dir" ]]; then
    [[ -d "$release_dir" && ! -L "$release_dir" && $(stat -c "%U:%G" "$release_dir") == root:root ]] || die "Release directory is not a root-owned real directory."
    safe_file "$release_dir/ghulakh-server" && safe_file "$release_dir/$EGRESS_SCRIPT_NAME" && safe_file "$release_dir/$CREDENTIAL_TOOL_NAME" || die "Release contains a missing file or symlink."
    local existing_id
    existing_id="$(sha256sum "$release_dir/ghulakh-server" "$release_dir/$EGRESS_SCRIPT_NAME" "$release_dir/$CREDENTIAL_TOOL_NAME" | cut -c1-64 | sha256sum | cut -c1-64)"
    [[ "$existing_id" == "$release_id" ]] || die "Existing release content does not match its release identifier."
  else
    install -d -o root -g root -m 0755 "$release_dir"
    install -o root -g root -m 0755 "$BINARY" "$release_dir/ghulakh-server"
    install -o root -g root -m 0755 "$egress_tool" "$release_dir/$EGRESS_SCRIPT_NAME"
    install -o root -g root -m 0644 "$credential_tool" "$release_dir/$CREDENTIAL_TOOL_NAME"
  fi
  STAGED_BINARY="$release_dir/ghulakh-server"
  [[ -x "$STAGED_BINARY" ]] || die "Staged binary is missing."
  ensure_config
  for required in \
    "GHULAKH_CREDENTIAL_HASHES=$CREDENTIALS" \
    "GHULAKH_TUN_ENABLED=true" \
    "GHULAKH_FORWARDING_ENABLED=true" \
    "GHULAKH_TUN_NAME=ghulakh0" \
    "GHULAKH_TURN_GATEWAY_BIND=0.0.0.0:4434" \
    "GHULAKH_NOISE_PRIVATE_KEY=$NOISE_PRIVATE" \
    "GHULAKH_NOISE_PUBLIC_KEY=$NOISE_PUBLIC"; do
    grep -Fqx "$required" "$ENV_FILE" || die "Required server.env setting is missing or changed: $required"
  done
  [[ ! -e "$CURRENT" || -L "$CURRENT" ]] || die "Current release path is not a symlink; refusing to replace it."
  old_target=""
  if [[ -L "$CURRENT" ]]; then
    old_target="$(readlink "$CURRENT")"
    case "$(readlink -f "$CURRENT")" in "$RELEASES"/*) ;; *) die "Current release points outside managed releases."; esac
  fi
  if ! grep -Eq "^[[:space:]]*[0-9a-f]{64}[[:space:]]*$" "$CREDENTIALS"; then
    [[ -z "$old_target" ]] || die "No valid device credential digests exist; update refused."
    printf "Initial device credential (copy it now; it is shown only once):\n"
    runuser -u "$NAME" -- python3 "$release_dir/$CREDENTIAL_TOOL_NAME" --digest-file "$CREDENTIALS"
  fi
  printf "Pinned Noise server public key (hex):\n"
  cat "$NOISE_PUBLIC"
  link="$BASE/.current.$BASHPID.$RANDOM"
  ln -s "$release_dir" "$link"
  mv -Tf "$link" "$CURRENT"
  if ! write_units "$WAN" "$IPV6_MODE"; then
    if [[ -n "$old_target" ]]; then ln -sfn "$old_target" "$link"; mv -Tf "$link" "$CURRENT"; else rm -f "$CURRENT"; fi
    die "Unit validation failed; active release pointer was restored."
  fi
  sha256sum "$SERVER_UNIT" "$EGRESS_UNIT" >"$MARKER.tmp"
  chmod 0600 "$MARKER.tmp"
  mv -f "$MARKER.tmp" "$MARKER"
  systemctl daemon-reload
  if systemctl enable ghulakh-egress.service ghulakh-server.service &&
     systemctl restart ghulakh-egress.service &&
     systemctl restart ghulakh-server.service; then
    printf 'Deployment active. Release: %s\n' "$release_id"
    printf 'Create a device credential: sudo bash tools/deploy-server.sh credential\n'
    printf 'Allow the gateway UDP port in the existing INPUT firewall after reviewing host policy.\n'
    return 0
  fi
  printf 'Activation failed; attempting release rollback.\n' >&2
  if [[ -n "$old_target" ]]; then
    ln -sfn "$old_target" "$link"; mv -Tf "$link" "$CURRENT"
    systemctl daemon-reload
    systemctl restart ghulakh-egress.service || true
    systemctl restart ghulakh-server.service || true
  else
    systemctl disable --now ghulakh-server.service ghulakh-egress.service || true
    rm -f "$CURRENT"
    systemctl daemon-reload
  fi
  die "Deployment activation failed. Previous release restored when available; persistent configuration was preserved."
}
credential() {
  require_root
  [[ -f "$MARKER" && -L "$CURRENT" ]] || die "Managed deployment is not installed."
  [[ -s "$CURRENT/$CREDENTIAL_TOOL_NAME" ]] || die "Credential tool is missing."
  runuser -u "$NAME" -- python3 "$CURRENT/$CREDENTIAL_TOOL_NAME" --digest-file "$CREDENTIALS"
}
status() {
  require_root
  systemctl --no-pager --full status ghulakh-server.service || true
  systemctl --no-pager --full status ghulakh-egress.service || true
}
uninstall() {
  require_root
  [[ -f "$MARKER" && -d "$BASE" && ! -L "$BASE" ]] || die "No verified managed installation found."
  if [[ -s "$MARKER" ]]; then
    sha256sum -c "$MARKER" >/dev/null || die "Managed unit checksum verification failed; refusing uninstall."
  else
    [[ ! -e "$SERVER_UNIT" && ! -e "$EGRESS_UNIT" ]] || die "Unverified partial systemd installation found; refusing uninstall."
  fi
  for unit in "$SERVER_UNIT" "$EGRESS_UNIT"; do
    safe_file "$unit" && grep -Fq 'Managed by Ghulakh deployment tool' "$unit" || die "Refusing to remove unmanaged or modified unit: $unit"
  done
  printf 'This stops the VPN and removes its units, releases and owned egress tables.\n'
  printf 'Configuration, keys, credentials, service account, sysctls and routes are preserved.\n'
  printf 'Type REMOVE GHULAKH to continue: '
  local answer
  IFS= read -r answer
  [[ "$answer" == "REMOVE GHULAKH" ]] || die "Uninstall cancelled."
  systemctl disable --now ghulakh-server.service
  systemctl disable --now ghulakh-egress.service
  rm -f "$SERVER_UNIT" "$EGRESS_UNIT" "$CURRENT"
  systemctl daemon-reload
  rm -rf -- "$RELEASES"
  rm -f "$MARKER"
  rmdir "$BASE" 2>/dev/null || true
  printf 'Runtime removed. Persistent configuration and service account remain in place.\n'
}
(($#)) || usage
case "$1" in
  install|update) [[ $# -ge 2 ]] || usage; require_root; deploy "$@" ;;
  credential) [[ $# -eq 1 ]] || usage; credential ;;
  status) [[ $# -eq 1 ]] || usage; status ;;
  uninstall) [[ $# -eq 1 ]] || usage; uninstall ;;
  *) usage ;;
esac
