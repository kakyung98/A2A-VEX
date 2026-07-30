from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import os
import subprocess
from typing import TextIO

from cve_genie_a2a.config import settings


@dataclass(frozen=True)
class PhaseResult:
    exit_code: int
    run_type: str
    log_path: str


def run_phase(
    *,
    cve_id: str,
    json_path: Path,
    run_type: str,
    log_path: Path,
) -> PhaseResult:
    log_path.parent.mkdir(parents=True, exist_ok=True)

    command = [
        str(settings.python_executable),
        str(settings.main_script),
        "--cve",
        cve_id,
        "--json",
        str(json_path),
        "--run-type",
        run_type,
    ]

    environment = os.environ.copy()
    environment["ENV_PATH"] = str(settings.env_file)
    environment["MODEL"] = settings.model_name

    with log_path.open("a", encoding="utf-8") as handle:
        _write_header(handle, run_type, command)
        process = subprocess.Popen(
            command,
            cwd=settings.project_root,
            env=environment,
            stdout=handle,
            stderr=subprocess.STDOUT,
            shell=False,
            text=True,
        )
        exit_code = process.wait()
        handle.write(
            f"\n[A2A] phase={run_type} exit_code={exit_code}\n"
        )

    return PhaseResult(
        exit_code=exit_code,
        run_type=run_type,
        log_path=str(log_path),
    )


def _write_header(
    handle: TextIO,
    run_type: str,
    command: list[str],
) -> None:
    handle.write("\n" + "=" * 72 + "\n")
    handle.write(f"A2A AGENT PHASE: {run_type}\n")
    handle.write("COMMAND: " + " ".join(command) + "\n")
    handle.write("=" * 72 + "\n")
    handle.flush()
