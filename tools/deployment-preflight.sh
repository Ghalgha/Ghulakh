#!/usr/bin/env bash
ghulakh_server_main_pid() {
  local pid
  pid="$(systemctl show --property=MainPID --value ghulakh-server.service 2>/dev/null)" || return 1
  [[ "$pid" =~ ^[0-9]+$ && "$pid" -gt 1 ]] || return 1
  printf '%s\n' "$pid"
}
ghulakh_server_process_is_current() {
  local pid="$1" proc_root="${GHULAKH_PROC_ROOT:-/proc}" expected actual cgroup
  [[ "$pid" =~ ^[0-9]+$ && "$pid" -gt 1 ]] || return 1
  [[ -r "$proc_root/$pid/cgroup" && -e "$proc_root/$pid/exe" ]] || return 1
  cgroup="$(cat "$proc_root/$pid/cgroup" 2>/dev/null)" || return 1
  [[ "$cgroup" == *"/ghulakh-server.service"* ]] || return 1
  expected="$(readlink -f "$CURRENT/ghulakh-server" 2>/dev/null)" || return 1
  actual="$(readlink "$proc_root/$pid/exe" 2>/dev/null)" || return 1
  [[ "$actual" == "$expected" || "$actual" == "$expected (deleted)" ]]
}
ghulakh_server_has_tun_fd() {
  local pid="$1" proc_root="${GHULAKH_PROC_ROOT:-/proc}" fd target
  [[ -d "$proc_root/$pid/fd" ]] || return 1
  for fd in "$proc_root/$pid"/fd/*; do
    [[ -e "$fd" || -L "$fd" ]] || continue
    target="$(readlink "$fd" 2>/dev/null)" || continue
    [[ "$target" == "/dev/net/tun" ]] && return 0
  done
  return 1
}
ghulakh_preflight_udp_port() {
  local port="$1" listeners pids pid main_pid listener
  listeners="$(ss -H -lunp "sport = :$port")" || { printf 'Cannot inspect UDP/%s listeners with ss.\n' "$port" >&2; return 1; }
  [[ -n "$listeners" ]] || return 0
  while IFS= read -r listener; do
    [[ "$listener" == *pid=* ]] || { printf 'UDP/%s has a listener without a visible PID; refusing to continue.\n' "$port" >&2; printf '%s\n' "$listeners" >&2; return 1; }
  done <<<"$listeners"
  pids="$(printf '%s\n' "$listeners" | grep -oE 'pid=[0-9]+' | cut -d= -f2 | sort -un || true)"
  [[ -n "$pids" ]] || { printf 'UDP/%s is occupied, but the owning PID is unavailable.\n' "$port" >&2; return 1; }
  main_pid="$(ghulakh_server_main_pid)" || { printf 'UDP/%s is occupied, but no active managed server owns it.\n' "$port" >&2; printf '%s\n' "$listeners" >&2; return 1; }
  ghulakh_server_process_is_current "$main_pid" || { printf 'UDP/%s listener cannot be verified as the active managed server.\n' "$port" >&2; printf '%s\n' "$listeners" >&2; return 1; }
  while IFS= read -r pid; do
    [[ -n "$pid" ]] || continue
    [[ "$pid" == "$main_pid" ]] || { printf 'UDP/%s is also held by foreign PID %s; refusing to continue.\n' "$port" "$pid" >&2; printf '%s\n' "$listeners" >&2; return 1; }
  done <<<"$pids"
}
ghulakh_preflight_tun_interface() {
  local interface="$1" details main_pid sys_class="${GHULAKH_SYS_CLASS_NET:-/sys/class/net}"
  if [[ ! -e "$sys_class/$interface" && ! -L "$sys_class/$interface" ]]; then return 0; fi
  details="$(ip -d link show dev "$interface" 2>/dev/null)" || {
    printf 'Cannot inspect existing interface %s; refusing to continue.\n' "$interface" >&2
    return 1
  }
  if ! grep -Eq '(^|[[:space:]])type[[:space:]]+tun([[:space:]]|$)' <<<"$details"; then
    printf 'Interface %s already exists but is not a TUN interface; refusing to adopt it.\n' "$interface" >&2
    return 1
  fi
  main_pid="$(ghulakh_server_main_pid)" || { printf 'TUN interface %s already exists without an active managed server; refusing to adopt it.\n' "$interface" >&2; return 1; }
  ghulakh_server_process_is_current "$main_pid" && ghulakh_server_has_tun_fd "$main_pid" || {
    printf 'TUN interface %s cannot be tied to the active managed server process; refusing to continue.\n' "$interface" >&2
    return 1
  }
}
