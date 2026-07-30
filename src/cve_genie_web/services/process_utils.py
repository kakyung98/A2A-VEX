from __future__ import annotations

from pathlib import Path
import os
import subprocess
from typing import Sequence

from cve_genie_web.config import settings


SENSITIVE_KEYS = (
    "OPENAI_API_KEY",
    "GITHUB_TOKEN",
)


def build_process_env() -> dict[str, str]:
    env = os.environ.copy()
    env["ENV_PATH"] = str(settings.env_file)
    env["MODEL"] = settings.model_name

    existing_pythonpath = env.get("PYTHONPATH", "")
    agentlib_path = str(settings.project_root / "agentlib")
    env["PYTHONPATH"] = (
        f"{agentlib_path}:{existing_pythonpath}"
        if existing_pythonpath
        else agentlib_path
    )
    return env


def mask_sensitive_text(text: str, env: dict[str, str]) -> str:
    masked = text
    for key in SENSITIVE_KEYS:
        value = env.get(key)
        if value:
            masked = masked.replace(value, f"<{key}:masked>")
    return masked


def run_and_log(
    command: Sequence[str],
    *,
    log_path: Path,
    cwd: Path,
    header: str,
) -> int:
    env = build_process_env()

    with log_path.open("a", encoding="utf-8") as log_file:
        log_file.write(f"\n===== {header} =====\n")
        log_file.write("Command: " + " ".join(command) + "\n")
        log_file.flush()

        process = subprocess.Popen(
            list(command),
            cwd=cwd,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            shell=False,
        )

        assert process.stdout is not None

        try:
            for line in process.stdout:
                log_file.write(mask_sensitive_text(line, env))
                log_file.flush()

            return process.wait(timeout=settings.process_timeout_seconds)
        except subprocess.TimeoutExpired:
            process.kill()
            log_file.write(
                "\nProcess exceeded timeout and was terminated.\n"
            )
            log_file.flush()
            return 124
