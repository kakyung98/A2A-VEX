from __future__ import annotations

from pathlib import Path
import os

from cve_genie_web.config import settings
from cve_genie_web.services.process_utils import run_and_log


def run_cve_genie(
    *,
    cve_id: str,
    json_path: Path,
    run_type: str,
    log_path: Path,
) -> int:
    execution_mode = os.getenv(
        "CVE_GENIE_EXECUTION_MODE",
        "a2a",
    ).strip().lower()

    if execution_mode == "a2a":
        command = [
            str(settings.python_executable),
            str(settings.project_root / "a2a_orchestrator.py"),
            "--cve",
            cve_id,
            "--json",
            str(json_path),
            "--run-type",
            run_type,
            "--log",
            str(log_path),
        ]
        header = "CVE-GENIE A2A ORCHESTRATION"
    elif execution_mode == "legacy":
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
        header = "CVE-GENIE LEGACY EXECUTION"
    else:
        raise ValueError(
            "CVE_GENIE_EXECUTION_MODE must be 'a2a' or 'legacy'"
        )

    return run_and_log(
        command,
        log_path=log_path,
        cwd=settings.project_root,
        header=header,
    )
