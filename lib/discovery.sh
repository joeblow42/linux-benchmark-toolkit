#!/usr/bin/env bash
run_discovery() {
 require_command python3
 require_command uname
 create_session "$1"
 if ! python3 "$ROOT/reporting/discover.py" "$SESSION_DIR"; then
  printf 'Discovery failed, session preserved: %s\n' "$SESSION_DIR" >&2
  return 1
 fi
 if ! python3 "$ROOT/reporting/generate.py" "$SESSION_DIR"; then
  printf 'Reporting failed, raw session preserved: %s\n' "$SESSION_DIR" >&2
  return 1
 fi
 printf 'Session: %s\nHTML report: %s/report.html\n' "$SESSION_DIR" "$SESSION_DIR"
}
