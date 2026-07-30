#!/usr/bin/env bash
set -euo pipefail

cd /workspaces/A2A-VEX/src
source env/bin/activate

export CVE_GENIE_ROOT=/workspaces/A2A-VEX/src
export ENV_PATH=/workspaces/A2A-VEX/src/.env
export MODEL="${MODEL:-example_run}"

uvicorn cve_genie_web.app:app \
  --host 0.0.0.0 \
  --port 8000 \
  --reload
