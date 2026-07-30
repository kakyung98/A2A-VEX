from __future__ import annotations

from pathlib import Path

from cve_genie_web.config import settings
from cve_genie_web.services.process_utils import run_and_log


def extract_cve_data(
    *,
    cve_id: str,
    output_path: Path,
    log_path: Path,
) -> int:
    python_executable = settings.python_executable
    cve_data_script = settings.cve_data_script.resolve()
    project_root = settings.project_root.resolve()
    output_path = output_path.resolve()
    log_path = log_path.resolve()

    if not python_executable.exists():
        raise RuntimeError(
            "CVE-Genie Python executable was not found: "
            f"{python_executable}"
        )

    if not python_executable.is_file():
        raise RuntimeError(
            "Configured Python executable is not a file: "
            f"{python_executable}"
        )

    if not cve_data_script.exists():
        raise RuntimeError(
            "CVE data extraction script was not found: "
            f"{cve_data_script}"
        )

    if not cve_data_script.is_file():
        raise RuntimeError(
            "Configured CVE data script is not a file: "
            f"{cve_data_script}"
        )

    if not project_root.exists():
        raise RuntimeError(
            "CVE-Genie project root was not found: "
            f"{project_root}"
        )

    output_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    log_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    command = [
        str(python_executable),
        str(cve_data_script),
        "--cve_id",
        cve_id,
        "--output_path",
        str(output_path),
    ]

    return run_and_log(
        command,
        log_path=log_path,
        cwd=project_root,
        header=(
            "CVE DATA EXTRACTION\n"
            f"Python: {python_executable}\n"
            f"Script: {cve_data_script}\n"
            f"Output: {output_path}"
        ),
    )