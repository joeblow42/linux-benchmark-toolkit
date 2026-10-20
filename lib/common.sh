#!/usr/bin/env bash
fail() { printf 'ERROR: %s\n' "$*" >&2; exit 2; }
require_command() { command -v "$1" >/dev/null 2>&1 || fail "Required tool unavailable: $1"; }
check_dependencies() {
 local cmd
 printf '%-16s %-12s %s\n' TOOL STATUS PATH
 for cmd in bash python3 dialog lscpu lsblk lspci smartctl ffmpeg fio iperf3; do
  if command -v "$cmd" >/dev/null 2>&1; then
   printf '%-16s %-12s %s\n' "$cmd" available "$(command -v "$cmd")"
  else
   printf '%-16s %-12s %s\n' "$cmd" missing -
  fi
 done
}
create_session() {
 local base="$1" stamp token root
 mkdir -p -- "$base" || fail "Cannot create results root: $base"
 root=$(cd -- "$base" && pwd -P)
 [[ -w "$root" ]] || fail "Results root not writable: $root"
 stamp=$(date -u +%Y%m%dT%H%M%SZ)
 token=$(python3 -c 'import uuid; print(uuid.uuid4().hex[:10])')
 SESSION_DIR="$root/session_${stamp}_${token}"
 (umask 077; mkdir -- "$SESSION_DIR" && mkdir -- "$SESSION_DIR/logs") || fail 'Cannot create session'
}
