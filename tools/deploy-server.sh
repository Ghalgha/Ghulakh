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
readonly TUN_INTERFACE="ghulakh0"
readonly PREFLIGHT_TOOL_NAME="deployment-preflight.sh"

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
verify_release_tree() {
  local release_root="$1" mountinfo_file="${2:-/proc/self/mountinfo}" unsafe_entry mounted_path
  [[ -d "$release_root" && ! -L "$release_root" && -r "$mountinfo_file" ]] || return 1
  mounted_path="$(awk -v root="$release_root" '$5 == root || index($5, root "/") == 1 { print $5; exit }' "$mountinfo_file")" || return 1
  [[ -z "$mounted_path" ]] || return 1
  unsafe_entry="$(find "$release_root" -xdev \\( -type l -o \\( -type f -links +1 \\) -o ! -user root -o ! -group root \\) -print -quit)" || return 1
  [[ -z "$unsafe_entry" ]]
}
verify_release_integrity() (
  local release_root="$1" release_dir release_name expected_id extra_entry
  verify_release_tree "$release_root" "${2:-/proc/self/mountinfo}" || return 1
  shopt -s nullglob dotglob
  for release_dir in "$release_root"/*; do
    [[ -d "$release_dir" && ! -L "$release_dir" ]] || return 1
    release_name="${release_dir##*/}"
    [[ "$release_name" =~ ^[0-9a-f]{64}$ ]] || return 1
    [[ $(stat -c '%U:%G:%a' "$release_dir") == root:root:755 ]] || return 1
    [[ $(stat -c '%U:%G:%a:%h' "$release_dir/ghulakh-server") == root:root:755:1 ]] || return 1
    [[ $(stat -c '%U:%G:%a:%h' "$release_dir/$EGRESS_SCRIPT_NAME") == root:root:755:1 ]] || return 1
    [[ $(stat -c '%U:%G:%a:%h' "$release_dir/$CREDENTIAL_TOOL_NAME") == root:root:644:1 ]] || return 1
    extra_entry="$(find "$release_dir" -mindepth 1 -maxdepth 1 ! -type f -print -quit)" || return 1
    [[ -z "$extra_entry" ]] || return 1
    expected_id="$(sha256sum "$release_dir/ghulakh-server" "$release_dir/$EGRESS_SCRIPT_NAME" "$release_dir/$CREDENTIAL_TOOL_NAME" | cut -c1-64 | sha256sum | cut -c1-64)" || return 1
    [[ "$expected_id" == "$release_name" ]] || return 1
  done
)
PREFLIGHT_TOOL="$(cd "$(dirname "$0")" && pwd)/$PREFLIGHT_TOOL_NAME"
safe_file "$PREFLIGHT_TOOL" || die "Deployment preflight helper is missing or is not a regular file."
source "$PREFLIGHT_TOOL"

check_platform() {
  [[ -d /run/systemd/system ]] || die "A running systemd system is required."
  [[ -c /dev/net/tun ]] || die "/dev/net/tun is unavailable."
  [[ -r /proc/sys/net/ipv4/ip_forward && $(< /proc/sys/net/ipv4/ip_forward) == 1 ]] || die "Enable net.ipv4.ip_forward=1 administratively."
  [[ -r /proc/sys/net/ipv6/conf/all/forwarding && $(< /proc/sys/net/ipv6/conf/all/forwarding) == 1 ]] || die "Enable net.ipv6.conf.all.forwarding=1 administratively."
  for cmd in systemctl systemd-analyze install ip nft ss runuser useradd getent python3 sha256sum readlink stat; do require_command "$cmd"; done
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
    if [[ -e "$unit" || -L "$unit" ]]; then
      safe_file "$unit" || die "Refusing non-regular unit path: $unit"
      grep -Fq 'Managed by Ghulakh deployment tool' "$unit" || die "Refusing to replace unmanaged systemd unit: $unit"
    fi
  done
  if [[ -e "$MARKER" ]]; then
    [[ $(stat -c "%U:%G:%a" "$MARKER") == root:root:600 ]] || die "Managed marker permissions are invalid."
  fi
  if [[ -s "$MARKER" ]]; then sha256sum -c "$MARKER" >/dev/null || die "Managed systemd unit checksum mismatch; refusing to overwrite or remove modified units."; fi
  local unit_load_state unit_name unit_path
  for unit_name in ghulakh-egress.service ghulakh-server.service; do
    if [[ "$unit_name" == ghulakh-egress.service ]]; then unit_path="$EGRESS_UNIT"; else unit_path="$SERVER_UNIT"; fi
    if [[ ! -e "$unit_path" && ! -L "$unit_path" ]]; then
      unit_load_state="$(systemctl show --property=LoadState --value "$unit_name" 2>/dev/null || true)"
      [[ "$unit_load_state" == not-found ]] || die "Refusing unmanaged systemd unit outside $unit_path (LoadState=${unit_load_state:-unknown})."
    fi
  done
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
  if [[ -e "$NOISE_PRIVATE" || -L "$NOISE_PRIVATE" || -e "$NOISE_PUBLIC" || -L "$NOISE_PUBLIC" ]]; then
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
  if [[ ! -e "$ENV_FILE" && ! -L "$ENV_FILE" ]]; then
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
  # Refuse incomplete managed layouts before creating accounts, directories, releases or credentials.
  if [[ -e "$CURRENT" && ! -L "$CURRENT" ]]; then
    die "Current release path is not a symlink; refusing an incomplete managed installation."
  fi
  if [[ -L "$CURRENT" ]]; then
    [[ -s "$MARKER" ]] || die "Active release exists without a populated ownership marker; refusing an ambiguous update."
    safe_file "$EGRESS_UNIT" && safe_file "$SERVER_UNIT" || die "Active release exists without both regular managed systemd units; refusing an incomplete installation."
    local verified_current
    verified_current="$(readlink -f "$CURRENT")"
    [[ -n "$verified_current" && -d "$verified_current" && ! -L "$verified_current" ]] ||
      die "Current release symlink is dangling or does not resolve to a real directory."
    case "$verified_current" in "$RELEASES"/*) ;; *) die "Current release points outside managed releases." ;; esac
    # The managed egress unit is the persisted source of the original network parameters.
    grep -Fqx "ExecStart=/bin/bash $CURRENT/$EGRESS_SCRIPT_NAME ghulakh0 $WAN $IPV6_MODE" "$EGRESS_UNIT" ||
      die "WAN interface and IPv6 mode are immutable for an installed deployment; requested values differ from the recorded deployment."
  else
    # An empty marker alone is the intentional first-install retry reservation.
    [[ ! -s "$MARKER" && ! -e "$SERVER_UNIT" && ! -L "$SERVER_UNIT" && ! -e "$EGRESS_UNIT" && ! -L "$EGRESS_UNIT" ]] ||
      die "Managed marker or systemd units exist without an active release; refusing an incomplete installation."
  fi
  ghulakh_preflight_udp_port 4434 || die "UDP/4434 preflight failed; no existing process was changed."
  ghulakh_preflight_tun_interface "$TUN_INTERFACE" || die "TUN interface preflight failed; no existing interface or process was changed."
  local egress_tool credential_tool release_id release_dir old_target link
  egress_tool="$(cd "$(dirname "$0")" && pwd)/$EGRESS_SCRIPT_NAME"
  credential_tool="$(cd "$(dirname "$0")" && pwd)/$CREDENTIAL_TOOL_NAME"
  safe_file "$egress_tool" && safe_file "$credential_tool" || die "Deployment helper files are missing."
  bash -n "$egress_tool"
  ensure_account
  install -d -o root -g root -m 0755 "$BASE" "$RELEASES"
  # Reserve the new managed root before staging; rollback keeps this empty marker so retries remain verifiable.
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
  # Snapshot every mutable deployment component until systemd activation succeeds.
  local transaction_dir had_old_egress=0 had_old_server=0 had_old_marker=0
  local old_egress_enabled old_server_enabled old_egress_active old_server_active
  local rollback_failed=0
  transaction_dir="$(mktemp -d "$BASE/.deploy-transaction.XXXXXX")" || die "Could not create deployment transaction snapshot."
  if [[ -e "$EGRESS_UNIT" || -L "$EGRESS_UNIT" ]]; then
    cp -a -- "$EGRESS_UNIT" "$transaction_dir/old-egress" || { rm -rf -- "$transaction_dir"; die "Could not snapshot egress unit; partial snapshot removed."; }
    had_old_egress=1
  fi
  if [[ -e "$SERVER_UNIT" || -L "$SERVER_UNIT" ]]; then
    cp -a -- "$SERVER_UNIT" "$transaction_dir/old-server" || { rm -rf -- "$transaction_dir"; die "Could not snapshot server unit; partial snapshot removed."; }
    had_old_server=1
  fi
  if [[ -e "$MARKER" || -L "$MARKER" ]]; then
    cp -a -- "$MARKER" "$transaction_dir/old-marker" || { rm -rf -- "$transaction_dir"; die "Could not snapshot ownership marker; partial snapshot removed."; }
    had_old_marker=1
  fi
  old_egress_enabled="$(systemctl is-enabled ghulakh-egress.service 2>/dev/null || true)"
  old_server_enabled="$(systemctl is-enabled ghulakh-server.service 2>/dev/null || true)"
  old_egress_active="$(systemctl is-active ghulakh-egress.service 2>/dev/null || true)"
  old_server_active="$(systemctl is-active ghulakh-server.service 2>/dev/null || true)"

  validate_previous_unit_state() {
    local unit="$1" enabled_state="$2" active_state="$3"
    case "$enabled_state" in
      enabled|enabled-runtime|disabled|masked-runtime) ;;
      *) die "Unsupported previous enablement state for $unit: ${enabled_state:-unknown}; refusing activation because rollback cannot preserve it." ;;
    esac
    case "$active_state" in
      active|inactive) ;;
      *) die "Unsupported previous activity state for $unit: ${active_state:-unknown}; refusing activation because rollback cannot preserve it." ;;
    esac
  }
  if (( had_old_egress )); then
    validate_previous_unit_state ghulakh-egress.service "$old_egress_enabled" "$old_egress_active"
  fi
  if (( had_old_server )); then
    validate_previous_unit_state ghulakh-server.service "$old_server_enabled" "$old_server_active"
  fi

  rollback_activation() {
    local failed=0 restore_link
    restore_link="$BASE/.rollback-current.$BASHPID.$RANDOM"
    if [[ -n "$old_target" ]]; then
      if ln -s "$old_target" "$restore_link" && mv -Tf "$restore_link" "$CURRENT"; then :; else failed=1; fi
    else
      rm -f "$CURRENT" || failed=1
    fi

    if (( had_old_egress )); then
      cp -a -- "$transaction_dir/old-egress" "$EGRESS_UNIT.rollback" &&
        mv -f "$EGRESS_UNIT.rollback" "$EGRESS_UNIT" || failed=1
    else
      rm -f "$EGRESS_UNIT" || failed=1
    fi
    if (( had_old_server )); then
      cp -a -- "$transaction_dir/old-server" "$SERVER_UNIT.rollback" &&
        mv -f "$SERVER_UNIT.rollback" "$SERVER_UNIT" || failed=1
    else
      rm -f "$SERVER_UNIT" || failed=1
    fi
    if (( had_old_marker )); then
      cp -a -- "$transaction_dir/old-marker" "$MARKER.rollback" &&
        mv -f "$MARKER.rollback" "$MARKER" || failed=1
    else
      rm -f "$MARKER" || failed=1
    fi

    systemctl daemon-reload || failed=1
    if (( had_old_egress )); then
      case "$old_egress_enabled" in
        enabled) systemctl enable ghulakh-egress.service || failed=1 ;;
        enabled-runtime) systemctl enable --runtime ghulakh-egress.service || failed=1 ;;
        disabled) systemctl disable ghulakh-egress.service || failed=1 ;;
        masked-runtime) systemctl mask --runtime ghulakh-egress.service || failed=1 ;;
      esac
      if [[ "$old_egress_active" == active ]]; then
        systemctl restart ghulakh-egress.service || failed=1
      else
        systemctl stop ghulakh-egress.service || failed=1
      fi
    else
      systemctl disable --now ghulakh-egress.service >/dev/null 2>&1 || failed=1
    fi
    if (( had_old_server )); then
      case "$old_server_enabled" in
        enabled) systemctl enable ghulakh-server.service || failed=1 ;;
        enabled-runtime) systemctl enable --runtime ghulakh-server.service || failed=1 ;;
        disabled) systemctl disable ghulakh-server.service || failed=1 ;;
        masked-runtime) systemctl mask --runtime ghulakh-server.service || failed=1 ;;
      esac
      if [[ "$old_server_active" == active ]]; then
        systemctl restart ghulakh-server.service || failed=1
      else
        systemctl stop ghulakh-server.service || failed=1
      fi
    else
      systemctl disable --now ghulakh-server.service >/dev/null 2>&1 || failed=1
    fi

    if (( failed )); then
      printf 'CRITICAL: deployment rollback was incomplete; snapshots retained at %s\n' "$transaction_dir" >&2
      return 1
    fi
    rm -rf -- "$transaction_dir"
    return 0
  }

  trap 'if ! rollback_activation; then printf "CRITICAL: rollback requires manual recovery.\\n" >&2; fi; exit 1' HUP INT TERM

  link="$BASE/.current.$BASHPID.$RANDOM"
  if ! ln -s "$release_dir" "$link" || ! mv -Tf "$link" "$CURRENT"; then
    rm -f "$link"
    rollback_activation || rollback_failed=1
    trap - HUP INT TERM
    if (( rollback_failed )); then die "Release switch failed and rollback was incomplete; inspect $transaction_dir."; fi
    die "Could not switch active release; previous deployment state restored."
  fi
  if ! write_units "$WAN" "$IPV6_MODE"; then
    rollback_activation || rollback_failed=1
    trap - HUP INT TERM
    if (( rollback_failed )); then die "Unit installation failed and rollback was incomplete; inspect $transaction_dir."; fi
    die "Unit validation or installation failed; previous release, units and marker restored."
  fi
  # write_units manages and clears its own traps; re-arm the outer transaction guard.
  trap 'if ! rollback_activation; then printf "CRITICAL: rollback requires manual recovery.\\n" >&2; fi; exit 1' HUP INT TERM
  if ! systemctl daemon-reload; then
    rollback_activation || rollback_failed=1
    trap - HUP INT TERM
    if (( rollback_failed )); then die "daemon-reload failed and rollback was incomplete; inspect $transaction_dir."; fi
    die "systemd daemon-reload failed; previous deployment state restored."
  fi
  if systemctl enable ghulakh-egress.service ghulakh-server.service &&
     systemctl restart ghulakh-egress.service &&
     systemctl restart ghulakh-server.service; then
    rm -rf -- "$transaction_dir"
    trap - HUP INT TERM
    printf 'Deployment active. Release: %s\n' "$release_id"
    printf 'Create a device credential: sudo bash tools/deploy-server.sh credential\n'
    printf 'Allow the gateway UDP port in the existing INPUT firewall after reviewing host policy.\n'
    return 0
  fi

  printf 'Activation failed; restoring the previous release, units, marker and service state.\n' >&2
  rollback_activation || rollback_failed=1
  trap - HUP INT TERM
  if (( rollback_failed )); then die "Deployment activation failed and rollback was incomplete; inspect $transaction_dir."; fi
  die "Deployment activation failed. Previous deployment state was restored; persistent configuration was preserved."
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
  [[ -f "$MARKER" && ! -L "$MARKER" && $(stat -c '%U:%G:%a:%h' "$MARKER") == root:root:600:1 ]] || die "Managed marker ownership, mode or link count is invalid."
  [[ -d "$BASE" && ! -L "$BASE" && $(stat -c '%U:%G:%a' "$BASE") == root:root:755 ]] || die "Managed release root ownership or mode is invalid."
  [[ -d "$RELEASES" && ! -L "$RELEASES" && $(stat -c '%U:%G:%a' "$RELEASES") == root:root:755 && -L "$CURRENT" ]] || die "Managed release layout ownership or mode is invalid."
  safe_file "$SERVER_UNIT" && safe_file "$EGRESS_UNIT" || die "Managed systemd unit files are missing or unsafe."
  sha256sum -c "$MARKER" >/dev/null || die "Managed systemd unit checksum verification failed."
  local active_release failed=0
  active_release="$(readlink -f "$CURRENT")"
  case "$active_release" in "$RELEASES"/*) ;; *) die "Active release points outside managed releases." ;; esac
  [[ -d "$active_release" && ! -L "$active_release" && $(stat -c '%U:%G' "$active_release") == root:root ]] || die "Active release directory is not a root-owned directory."
  verify_release_integrity "$RELEASES" || die "Managed release integrity verification failed."
  safe_file "$active_release/$EGRESS_SCRIPT_NAME" || die "Managed egress helper is missing or unsafe."
  local ipv6_mode
  ipv6_mode="$(awk '/^ExecStart=\\/bin\\/bash .* ghulakh0 / { print $NF }' "$EGRESS_UNIT")"
  [[ "$ipv6_mode" == nat66 || "$ipv6_mode" == routed ]] || die "Could not determine the managed IPv6 mode from the verified egress unit."
  "$active_release/$EGRESS_SCRIPT_NAME" --check-active "$ipv6_mode" || die "The active egress tables are missing or do not match the managed IPv6 mode."
  systemctl --no-pager --full status ghulakh-server.service || failed=1
  systemctl --no-pager --full status ghulakh-egress.service || failed=1
  return "$failed"
}
uninstall() {
  require_root
  [[ -f "$MARKER" && ! -L "$MARKER" && -d "$BASE" && ! -L "$BASE" ]] || die "No verified managed installation found."
  [[ $(stat -c '%U:%G:%a' "$BASE") == root:root:755 ]] || die "Managed release root ownership or mode is invalid."
  [[ $(stat -c '%U:%G:%a:%h' "$MARKER") == root:root:600:1 ]] || die "Managed marker ownership, mode or link count is invalid."
  [[ -d "$RELEASES" && ! -L "$RELEASES" && $(stat -c '%U:%G:%a' "$RELEASES") == root:root:755 ]] || die "Managed releases directory ownership or mode is invalid."
  if [[ ! -s "$MARKER" ]]; then
    [[ ! -e "$CURRENT" && ! -L "$CURRENT" && ! -e "$SERVER_UNIT" && ! -L "$SERVER_UNIT" && ! -e "$EGRESS_UNIT" && ! -L "$EGRESS_UNIT" ]] ||
      die "Empty ownership marker is not an unambiguous incomplete-install reservation."
    verify_release_tree "$RELEASES" || die "Incomplete release tree contains unsafe entries or mount points; refusing cleanup."
    printf 'This removes only the incomplete deployment staging reservation. Persistent configuration, keys, credentials and service account remain.\\n'
    printf 'Type REMOVE GHULAKH: '
    local partial_answer
    IFS= read -r partial_answer
    [[ "$partial_answer" == "REMOVE GHULAKH" ]] || die "Uninstall cancelled."
    rm -rf --one-file-system "$RELEASES" || die "Could not remove incomplete releases; ownership marker retained for retry."
    rm -f -- "$MARKER" || die "Could not remove incomplete ownership marker; inspect $BASE."
    rmdir "$BASE" 2>/dev/null || true
    printf 'Incomplete runtime staging removed; persistent configuration and service account remain.\\n'
    return 0
  fi
  [[ -L "$CURRENT" ]] || die "Active release link is missing or is not a symlink."
  local active_release
  active_release="$(readlink -f "$CURRENT")"
  case "$active_release" in "$RELEASES"/*) ;; *) die "Active release points outside managed releases; refusing uninstall." ;; esac
  [[ -d "$active_release" && ! -L "$active_release" && $(stat -c '%U:%G' "$active_release") == root:root ]] || die "Active release is not a root-owned directory."
  verify_release_integrity "$RELEASES" || die "Release tree integrity verification failed; refusing uninstall."
  if [[ -s "$MARKER" ]]; then
    sha256sum -c "$MARKER" >/dev/null || die "Managed unit checksum verification failed; refusing uninstall."
    for unit in "$SERVER_UNIT" "$EGRESS_UNIT"; do
      safe_file "$unit" && grep -Fq 'Managed by Ghulakh deployment tool' "$unit" || die "Refusing to remove unmanaged or modified unit: $unit"
    done
    safe_file "$CURRENT/$EGRESS_SCRIPT_NAME" || die "Managed egress helper is missing or unsafe."
    "$CURRENT/$EGRESS_SCRIPT_NAME" --check-owned || die "An egress table is not verifiably owned; refusing uninstall."
  else
    [[ ! -e "$SERVER_UNIT" && ! -e "$EGRESS_UNIT" && ! -L "$CURRENT" ]] || die "Unverified partial systemd installation found; refusing uninstall."
  fi
  printf 'This stops the VPN and removes its units, releases and owned egress tables.\n'
  printf 'Configuration, keys, credentials, service account, sysctls and routes are preserved.\n'
  printf 'Type REMOVE GHULAKH to continue: '
  local answer
  IFS= read -r answer
  [[ "$answer" == "REMOVE GHULAKH" ]] || die "Uninstall cancelled."
  if ! systemctl disable --now ghulakh-server.service; then
    die "Could not stop/disable ghulakh-server.service. No managed files were removed; inspect systemctl status and retry."
  fi
  if ! systemctl disable --now ghulakh-egress.service; then
    printf 'ERROR: egress service could not be stopped/disabled. Release files and units remain; the server service may now be stopped.\n' >&2
    printf 'Recovery: inspect both units, then run systemctl enable --now ghulakh-server.service and retry uninstall.\n' >&2
    return 1
  fi
  local backup_dir
  backup_dir="$(mktemp -d /run/ghulakh-uninstall.XXXXXX)" || die "Could not create uninstall rollback snapshot."
  cp -a -- "$SERVER_UNIT" "$backup_dir/ghulakh-server.service" &&
    cp -a -- "$EGRESS_UNIT" "$backup_dir/ghulakh-egress.service" || {
      rm -rf -- "$backup_dir"
      die "Could not snapshot systemd units; no managed files were removed."
    }
  if ! rm -f -- "$SERVER_UNIT" "$EGRESS_UNIT" "$CURRENT" || ! systemctl daemon-reload; then
    local restore_failed=0
    install -o root -g root -m 0644 "$backup_dir/ghulakh-server.service" "$SERVER_UNIT" || restore_failed=1
    install -o root -g root -m 0644 "$backup_dir/ghulakh-egress.service" "$EGRESS_UNIT" || restore_failed=1
    ln -s "$active_release" "$CURRENT" || restore_failed=1
    systemctl daemon-reload || restore_failed=1
    if (( restore_failed )); then
      printf 'CRITICAL: uninstall rollback incomplete; unit backups retained at %s. Restore current -> %s and run systemctl daemon-reload.\n' "$backup_dir" "$active_release" >&2
      return 1
    fi
    rm -rf -- "$backup_dir"
    printf 'Uninstall aborted; managed units and active release link were restored. Services remain stopped; inspect and restart them if required.\n' >&2
    return 1
  fi
  if ! rm -rf --one-file-system "$RELEASES"; then
    printf 'ERROR: systemd units were removed, but release cleanup failed. Remaining data is under %s; persistent configuration is untouched.\n' "$RELEASES" >&2
    return 1
  fi
  rm -f -- "$MARKER" || die "Runtime was stopped and removed, but the ownership marker remains; inspect $BASE before retrying."
  rmdir "$BASE" 2>/dev/null || true
  rm -rf -- "$backup_dir"
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
