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
            os.getenv(
                "CVE_GENIE_ROOT",
                "/workspaces/A2A-VEX/src",
            )
        ).expanduser().resolve()

        default_python = (
            project_root
            / "env"
            / "bin"
            / "python"
        )

        python_executable = Path(
            os.getenv(
                "CVE_GENIE_PYTHON",
                str(default_python),
            )
        ).expanduser()

        if not python_executable.is_absolute():
            python_executable = (
                project_root
                / python_executable
            )

        env_file = Path(
            os.getenv(
                "CVE_GENIE_ENV_FILE",
                str(project_root / ".env"),
            )
        ).expanduser().resolve()

        cve_data_script = Path(
            os.getenv(
                "CVE_GENIE_DATA_SCRIPT",
                str(
                    project_root
                    / "data"
                    / "scripts"
                    / "cve_data.py"
                ),
            )
        ).expanduser().resolve()

        main_script = Path(
            os.getenv(
                "CVE_GENIE_MAIN_SCRIPT",
                str(project_root / "main.py"),
            )
        ).expanduser().resolve()

        job_root = Path(
            os.getenv(
                "CVE_GENIE_JOB_ROOT",
                str(project_root / "web_jobs"),
            )
        ).expanduser().resolve()

        database_path = Path(
            os.getenv(
                "CVE_GENIE_DATABASE",
                str(
                    project_root
                    / "cve_genie_jobs.db"
                ),
            )
        ).expanduser().resolve()

        model_name = os.getenv(
            "MODEL",
            "example_run",
        )

        process_timeout_seconds = int(
            os.getenv(
                "CVE_GENIE_PROCESS_TIMEOUT",
                "7200",
            )
        )

        return cls(
            project_root=project_root,
            python_executable=python_executable,
            env_file=env_file,
            cve_data_script=cve_data_script,
            main_script=main_script,
            job_root=job_root,
            database_path=database_path,
            model_name=model_name,
            process_timeout_seconds=(
                process_timeout_seconds
            ),
        )

    def validate(self) -> None:
        """
        서버 시작 시 필수 경로가 올바른지 검사한다.
        """

        if not self.project_root.exists():
            raise RuntimeError(
                "CVE-Genie project root does not exist: "
                f"{self.project_root}"
            )

        if not self.project_root.is_dir():
            raise RuntimeError(
                "CVE-Genie project root is not a directory: "
                f"{self.project_root}"
            )

        if not self.python_executable.exists():
            raise RuntimeError(
                "Python executable does not exist: "
                f"{self.python_executable}"
            )

        if not self.python_executable.is_file():
            raise RuntimeError(
                "Python executable is not a file: "
                f"{self.python_executable}"
            )

        if not os.access(
            self.python_executable,
            os.X_OK,
        ):
            raise RuntimeError(
                "Python executable is not executable: "
                f"{self.python_executable}"
            )

        if not self.cve_data_script.exists():
            raise RuntimeError(
                "CVE data script does not exist: "
                f"{self.cve_data_script}"
            )

        if not self.cve_data_script.is_file():
            raise RuntimeError(
                "CVE data script is not a file: "
                f"{self.cve_data_script}"
            )

        if not self.main_script.exists():
            raise RuntimeError(
                "CVE-Genie main script does not exist: "
                f"{self.main_script}"
            )

        if not self.main_script.is_file():
            raise RuntimeError(
                "CVE-Genie main script is not a file: "
                f"{self.main_script}"
            )

        if not self.env_file.exists():
            raise RuntimeError(
                "Environment file does not exist: "
                f"{self.env_file}"
            )

        if not self.env_file.is_file():
            raise RuntimeError(
                "Environment path is not a file: "
                f"{self.env_file}"
            )


settings = Settings.from_env()

settings.job_root.mkdir(
    parents=True,
    exist_ok=True,
)

(settings.job_root / "inputs").mkdir(
    parents=True,
    exist_ok=True,
)

(settings.job_root / "logs").mkdir(
    parents=True,
    exist_ok=True,
)

(settings.job_root / "results").mkdir(
    parents=True,
    exist_ok=True,
)

settings.validate()