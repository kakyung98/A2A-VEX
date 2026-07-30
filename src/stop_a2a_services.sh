#!/usr/bin/env bash
set -euo pipefail
ROOT="${CVE_GENIE_ROOT:-/workspaces/A2A-VEX/src}"
PID_DIR="$ROOT/.a2a-pids"

for name in environment exploit verification; do
  pid_file="$PID_DIR/$name.pid"
  if [[ -f "$pid_file" ]]; then
    pid="$(cat "$pid_file")"
    if kill -0 "$pid" 2>/dev/null; then
      kill "$pid"
      echo "Stopped $name (PID $pid)"
    fi
    rm -f "$pid_file"
  fi
done
