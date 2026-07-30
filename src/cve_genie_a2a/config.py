from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import os


@dataclass(frozen=True)
class A2ASettings:
    project_root: Path
    python_executable: Path
    main_script: Path
    env_file: Path
    model_name: str
    request_timeout_seconds: int
    shared_token: str | None
    environment_agent_url: str
    exploit_agent_url: str
    verification_agent_url: str

    @classmethod
    def from_env(cls) -> "A2ASettings":
        root = Path(
            os.getenv("CVE_GENIE_ROOT", "/workspaces/cve-genie/src")
        ).resolve()
        return cls(
            project_root=root,
            python_executable=Path(
                os.getenv("CVE_GENIE_PYTHON", str(root / "env/bin/python"))
            ).resolve(),
            main_script=Path(
                os.getenv("CVE_GENIE_MAIN_SCRIPT", str(root / "main.py"))
            ).resolve(),
            env_file=Path(
                os.getenv("CVE_GENIE_ENV_FILE", str(root / ".env"))
            ).resolve(),
            model_name=os.getenv("MODEL", "example_run"),
            request_timeout_seconds=int(
                os.getenv("CVE_GENIE_A2A_TIMEOUT", "7200")
            ),
            shared_token=os.getenv("CVE_GENIE_A2A_TOKEN"),
            environment_agent_url=os.getenv(
                "CVE_GENIE_ENVIRONMENT_AGENT_URL",
                "http://127.0.0.1:8101",
            ),
            exploit_agent_url=os.getenv(
                "CVE_GENIE_EXPLOIT_AGENT_URL",
                "http://127.0.0.1:8102",
            ),
            verification_agent_url=os.getenv(
                "CVE_GENIE_VERIFICATION_AGENT_URL",
                "http://127.0.0.1:8103",
            ),
        )


settings = A2ASettings.from_env()
