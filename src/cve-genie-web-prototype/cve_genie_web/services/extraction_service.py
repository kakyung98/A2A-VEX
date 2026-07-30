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
    output_path.parent.mkdir(parents=True, exist_ok=True)

    command = [
        str(settings.python_executable),
        str(settings.cve_data_script),
        "--cve_id",
        cve_id,
        "--output_path",
        str(output_path),
    ]

    return run_and_log(
        command,
        log_path=log_path,
        cwd=settings.project_root,
        header="CVE DATA EXTRACTION",
    )
