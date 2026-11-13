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
  if [[ -e /var/lib/ghulakh ]]; then
    [[ -d /var/lib/ghulakh && ! -L /var/lib/ghulakh ]] || die "Refusing non-directory or symlink path: /var/lib/ghulakh"
    [[ $(stat -c '%U:%G:%a' /var/lib/ghulakh) == "$NAME:$NAME:700" ]] || die "Existing /var/lib/ghulakh must be owned by $NAME:$NAME mode 0700."
  else
    install -d -o "$NAME" -g "$NAME" -m 0700 /var/lib/ghulakh
  fi
  if [[ -e "$CONFIG" ]]; then
    [[ -d "$CONFIG" && ! -L "$CONFIG" ]] || die "Refusing non-directory or symlink path: $CONFIG"
    [[ $(stat -c '%U:%G:%a' "$CONFIG") == "root:$NAME:750" ]] || die "Existing $CONFIG must be owned by root:$NAME mode 0750."
  else
    install -d -o root -g "$NAME" -m 0750 "$CONFIG"
  fi
}
ensure_config() {
  if [[ ! -e "$CREDENTIALS" && ! -L "$CREDENTIALS" ]]; then
    install -o root -g "$NAME" -m 0640 /dev/null "$CREDENTIALS"
  else
    safe_file "$CREDENTIALS" || die "Credential digest path must be a regular file."
    [[ $(stat -c '%U:%G:%a' "$CREDENTIALS") == "root:$NAME:640" ]] || die "Credential digest file must be owned by root:$NAME mode 0640; left unchanged."
  fi
  if [[ -e "$NOISE_PRIVATE" || -e "$NOISE_PUBLIC" ]]; then
    safe_file "$NOISE_PRIVATE" && safe_file "$NOISE_PUBLIC" || die "Both Noise key files must be regular files."
    [[ $(stat -c '%U:%G:%a' "$NOISE_PRIVATE") == "$NAME:$NAME:600" ]] || die "Noise private key must be owned by $NAME:$NAME mode 0600."
    [[ $(stat -c '%U:%G:%a' "$NOISE_PUBLIC") == "$NAME:$NAME:644" ]] || die "Noise public key must be owned by $NAME:$NAME mode 0644."
  else
    local generated_private="/var/lib/ghulakh/noise-private.generated"
    local generated_public="/var/lib/ghulakh/noise-public.generated"
    [[ ! -e "$generated_private" && ! -e "$generated_public" ]] || die "Stale temporary Noise key files exist; inspect them before retrying."
    runuser -u "$NAME" -- "$STAGED_BINARY" --generate-noise-keypair "$generated_private" "$generated_public" >/dev/null
    safe_file "$generated_private" && safe_file "$generated_public" || die "Noise key generation did not produce regular files."
    install -o "$NAME" -g "$NAME" -m 0600 "$generated_private" "$NOISE_PRIVATE"
    if ! install -o "$NAME" -g "$NAME" -m 0644 "$generated_public" "$NOISE_PUBLIC"; then
      rm -f "$NOISE_PRIVATE"
      rm -f "$generated_private" "$generated_public"
      die "Could not install the public Noise key; partial keypair was removed."
    fi
    rm -f "$generated_private" "$generated_public"
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
  local wan="$1" mode="$2" tmpdir marker_tmp marker_backup
  local had_egress=0 had_server=0 had_marker=0
  tmpdir="$(mktemp -d /etc/systemd/system/.ghulakh-units.XXXXXX)"
  marker_tmp="$BASE/.managed-by-ghulakh.tmp.$BASHPID"
  marker_backup="$BASE/.managed-by-ghulakh.backup.$BASHPID"

  local transaction_active=0
  rollback_units() {
    local rollback_failed=0
    trap - EXIT HUP INT TERM
    if (( had_egress )); then
      mv -f "$tmpdir/old-egress" "$EGRESS_UNIT" || rollback_failed=1
    else
      rm -f "$EGRESS_UNIT" || rollback_failed=1
    fi
    if (( had_server )); then
      mv -f "$tmpdir/old-server" "$SERVER_UNIT" || rollback_failed=1
    else
      rm -f "$SERVER_UNIT" || rollback_failed=1
    fi
    if (( had_marker )); then
      mv -f "$marker_backup" "$MARKER" || rollback_failed=1
    else
      rm -f "$MARKER" || rollback_failed=1
    fi
    if (( rollback_failed )); then
      trap - EXIT HUP INT TERM
      printf 'CRITICAL: unit rollback was incomplete; unit backups: %s; marker backup: %s\\n' "$tmpdir" "$marker_backup" >&2
      return 1
    fi
    transaction_active=0
    trap - EXIT HUP INT TERM
    rm -f "$marker_tmp" "$marker_backup"
    rm -rf -- "$tmpdir"
    return 0
  }

  cat >"$tmpdir/ghulakh-egress.service" <<EOF
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
  cat >"$tmpdir/ghulakh-server.service" <<EOF
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

  systemd-analyze verify "$tmpdir/ghulakh-egress.service" "$tmpdir/ghulakh-server.service" || {
    rm -rf -- "$tmpdir"
    return 1
  }
  if [[ -e "$EGRESS_UNIT" ]]; then
    cp -a -- "$EGRESS_UNIT" "$tmpdir/old-egress" || { rm -rf -- "$tmpdir"; return 1; }
    had_egress=1
  fi
  if [[ -e "$SERVER_UNIT" ]]; then
    cp -a -- "$SERVER_UNIT" "$tmpdir/old-server" || { rm -rf -- "$tmpdir"; return 1; }
    had_server=1
  fi
  if [[ -e "$MARKER" ]]; then
    cp -a -- "$MARKER" "$marker_backup" || { rm -rf -- "$tmpdir"; return 1; }
    had_marker=1
  fi

  install -o root -g root -m 0644 "$tmpdir/ghulakh-egress.service" "$tmpdir/new-egress" &&
    install -o root -g root -m 0644 "$tmpdir/ghulakh-server.service" "$tmpdir/new-server" || {
      rm -rf -- "$tmpdir"
      return 1
    }
  transaction_active=1
  trap 'if (( transaction_active )); then rollback_units || true; fi' EXIT
  trap 'if (( transaction_active )); then rollback_units || true; fi; exit 1' HUP INT TERM
  if ! mv -f "$tmpdir/new-egress" "$EGRESS_UNIT"; then
    rollback_units || true
    return 1
  fi
  if ! mv -f "$tmpdir/new-server" "$SERVER_UNIT"; then
    rollback_units || true
    return 1
  fi

  if ! sha256sum "$SERVER_UNIT" "$EGRESS_UNIT" >"$marker_tmp" ||
     ! chmod 0600 "$marker_tmp" ||
     ! mv -f "$marker_tmp" "$MARKER"; then
    rollback_units || true
    return 1
  fi

  transaction_active=0
  trap - EXIT HUP INT TERM
  rm -f "$marker_backup"
  rm -rf -- "$tmpdir"
  return 0
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
    python3 "$release_dir/$CREDENTIAL_TOOL_NAME" --digest-file "$CREDENTIALS" --mode 0640
    chown root:"$NAME" "$CREDENTIALS"
    chmod 0640 "$CREDENTIALS"
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
  [[ -f "$MARKER" && ! -L "$MARKER" && -L "$CURRENT" ]] || die "Managed deployment is not installed."
  [[ -d "$RELEASES" && ! -L "$RELEASES" && $(stat -c '%U:%G' "$RELEASES") == root:root ]] || die "Managed releases directory is invalid."
  sha256sum -c "$MARKER" >/dev/null || die "Managed systemd unit checksum mismatch; refusing credential changes."
  [[ -d "$CONFIG" && ! -L "$CONFIG" && $(stat -c '%U:%G:%a' "$CONFIG") == "root:$NAME:750" ]] || die "Credential directory ownership or mode is invalid."
  [[ "$(readlink -f "$CURRENT")" == "$RELEASES/"* ]] || die "Active release points outside the managed release directory."
  [[ -d "$(readlink -f "$CURRENT")" && ! -L "$(readlink -f "$CURRENT")" && $(stat -c '%U:%G' "$(readlink -f "$CURRENT")") == root:root ]] || die "Active release directory is invalid."
  safe_file "$CURRENT/$CREDENTIAL_TOOL_NAME" || die "Credential tool is missing or is not a regular file."
  safe_file "$CREDENTIALS" || die "Credential digest file is missing, a symlink, or not a regular file."
  [[ $(stat -c '%U:%G:%a:%h' "$CREDENTIALS") == "root:$NAME:640:1" ]] || die "Credential digest file ownership, mode or link count is invalid; left unchanged."
  python3 "$CURRENT/$CREDENTIAL_TOOL_NAME" --digest-file "$CREDENTIALS" --mode 0640 --expected-uid 0 --expected-gid "$(id -g "$NAME")"
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
    for unit in "$SERVER_UNIT" "$EGRESS_UNIT"; do
      safe_file "$unit" && grep -Fq 'Managed by Ghulakh deployment tool' "$unit" || die "Refusing to remove unmanaged or modified unit: $unit"
    done
  else
    [[ ! -e "$SERVER_UNIT" && ! -e "$EGRESS_UNIT" ]] || die "Unverified partial systemd installation found; refusing uninstall."
  fi
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
