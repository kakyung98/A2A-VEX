from __future__ import annotations

from pathlib import Path

from cve_genie_web.config import settings


def find_result_directory(cve_id: str) -> Path | None:
    candidates = [
        settings.project_root
        / "results"
        / "reproduced_cves"
        / cve_id,
        settings.project_root / "shared" / cve_id,
        settings.job_root / "results" / cve_id,
    ]

    for candidate in candidates:
        if candidate.exists():
            return candidate.resolve()

    return None


def list_artifacts(result_path: str | None) -> list[str]:
    if not result_path:
        return []

    root = Path(result_path)
    if not root.exists():
        return []

    return [
        str(path.relative_to(root))
        for path in sorted(root.rglob("*"))
        if path.is_file()
    ]
