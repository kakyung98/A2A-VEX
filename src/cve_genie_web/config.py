from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import os


@dataclass(frozen=True)
class Settings:
    project_root: Path
    python_executable: Path
    env_file: Path
    cve_data_script: Path
    main_script: Path
    job_root: Path
    database_path: Path
    model_name: str
    process_timeout_seconds: int

    @classmethod
    def from_env(cls) -> "Settings":
        project_root = Path(
            os.getenv("CVE_GENIE_ROOT", "/workspaces/cve-genie/src")
        ).resolve()

        return cls(
            project_root=project_root,
            python_executable=Path(
                os.getenv(
                    "CVE_GENIE_PYTHON",
                    str(project_root / "env" / "bin" / "python"),
                )
            ),
            env_file=Path(
                os.getenv("CVE_GENIE_ENV_FILE", str(project_root / ".env"))
            ).resolve(),
            cve_data_script=Path(
                os.getenv(
                    "CVE_GENIE_DATA_SCRIPT",
                    str(project_root / "data" / "scripts" / "cve_data.py"),
                )
            ).resolve(),
            main_script=Path(
                os.getenv("CVE_GENIE_MAIN_SCRIPT", str(project_root / "main.py"))
            ).resolve(),
            job_root=Path(
                os.getenv("CVE_GENIE_JOB_ROOT", str(project_root / "web_jobs"))
            ).resolve(),
            database_path=Path(
                os.getenv(
                    "CVE_GENIE_DATABASE",
                    str(project_root / "cve_genie_jobs.db"),
                )
            ).resolve(),
            model_name=os.getenv("MODEL", "example_run"),
            process_timeout_seconds=int(
                os.getenv("CVE_GENIE_PROCESS_TIMEOUT", "7200")
            ),
        )


settings = Settings.from_env()
settings.job_root.mkdir(parents=True, exist_ok=True)
(settings.job_root / "inputs").mkdir(parents=True, exist_ok=True)
(settings.job_root / "logs").mkdir(parents=True, exist_ok=True)
(settings.job_root / "results").mkdir(parents=True, exist_ok=True)
