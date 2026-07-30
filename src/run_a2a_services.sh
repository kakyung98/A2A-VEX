#!/usr/bin/env bash
set -euo pipefail

ROOT="${CVE_GENIE_ROOT:-/workspaces/A2A-VEX/src}"
PYTHON="${CVE_GENIE_PYTHON:-$ROOT/env/bin/python}"
PID_DIR="$ROOT/.a2a-pids"
LOG_DIR="$ROOT/.a2a-logs"

mkdir -p "$PID_DIR" "$LOG_DIR"
cd "$ROOT"

start_agent() {
  local name="$1"
  local app="$2"
  local port="$3"
  local pid_file="$PID_DIR/$name.pid"

  if [[ -f "$pid_file" ]] && kill -0 "$(cat "$pid_file")" 2>/dev/null; then
    echo "$name already running (PID $(cat "$pid_file"))"
    return
  fi

  nohup "$PYTHON" -m uvicorn "$app" \
    --host 127.0.0.1 \
    --port "$port" \
    > "$LOG_DIR/$name.log" 2>&1 &
  echo $! > "$pid_file"
  echo "Started $name on port $port (PID $!)"
}

start_agent environment cve_genie_a2a.services.environment_agent:app 8101
start_agent exploit cve_genie_a2a.services.exploit_agent:app 8102
start_agent verification cve_genie_a2a.services.verification_agent:app 8103

echo "Waiting for agents..."
for port in 8101 8102 8103; do
  for _ in $(seq 1 30); do
    if curl -fsS "http://127.0.0.1:$port/health" >/dev/null; then
      break
    fi
    sleep 1
  done
  curl -fsS "http://127.0.0.1:$port/health"
  echo
done

echo "All CVE-Genie A2A agents are ready."
