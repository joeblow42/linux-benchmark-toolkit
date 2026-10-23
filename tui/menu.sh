#!/usr/bin/env bash
choose_mode() {
 local choice rc=0
 choice=$(dialog --stdout --clear --backtitle 'Linux Benchmark Toolkit — Phase 1' --title 'Main Menu' \
  --menu 'Select a toolkit operation' 18 72 7 \
  discovery 'Read-only discovery and initial report' \
  standard 'Not yet implemented (Phase 3)' \
  extended 'Not yet implemented (Phases 3-4)' \
  diagnostics 'Toolkit software diagnostics and validation') || rc=$?
 [[ $rc -eq 0 && -n "$choice" ]] || return 1
 printf '%s' "$choice"
}

choose_validation_profile() {
 local choice rc=0
 choice=$(dialog --stdout --clear --backtitle 'Linux Benchmark Toolkit' \
  --title 'Toolkit Diagnostics' --default-item standard \
  --menu 'Select validation profile (Standard recommended)' 17 72 5 \
  quick 'Readiness checks only' \
  standard 'Readiness, unit and safe integration tests' \
  full 'Standard plus archive, relocation and Dialog tests') || rc=$?
 [[ $rc -eq 0 && -n "$choice" ]] || return 1
 printf '%s' "$choice"
}
