#!/usr/bin/env bash
choose_mode() {
 local choice rc=0
 choice=$(dialog --stdout --clear --backtitle 'Linux Benchmark Toolkit — Phase 1' --title 'Main Menu' \
  --menu 'Select benchmark mode' 17 68 6 \
  discovery 'Read-only discovery and initial report' \
  standard 'Not yet implemented (Phase 3)' \
  extended 'Not yet implemented (Phases 3-4)') || rc=$?
 [[ $rc -eq 0 && -n "$choice" ]] || return 1
 printf '%s' "$choice"
}
