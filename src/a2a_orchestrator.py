from __future__ import annotations

import argparse
import json
from pathlib import Path
from uuid import uuid4

from cve_genie_a2a.client import A2AClient
from cve_genie_a2a.config import settings
from cve_genie_a2a.models import A2ATaskResponse, TaskState


PHASES = {
    "build": (
        "environment_agent_url",
        "cve.environment.build",
    ),
    "exploit": (
        "exploit_agent_url",
        "cve.exploit.generate",
    ),
    "verify": (
        "verification_agent_url",
        "cve.verification.verify",
    ),
}


def append_event(path: Path, event: dict) -> None:
    event_path = path.with_suffix(path.suffix + ".a2a.jsonl")
    with event_path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(event, ensure_ascii=False) + "\n")


def run_workflow(
    *,
    cve_id: str,
    json_path: Path,
    run_type: str,
    log_path: Path,
) -> int:
    client = A2AClient()
    context_id = str(uuid4())
    selected_phases = [item.strip() for item in run_type.split(",")]

    payload = {
        "cve_id": cve_id,
        "json_path": str(json_path.resolve()),
        "log_path": str(log_path.resolve()),
    }

    for phase in selected_phases:
        url_attr, skill_id = PHASES[phase]
        base_url = getattr(settings, url_attr)
        remote = client.discover(base_url)

        print(
            f"[A2A] discovered agent={remote.card.name} "
            f"url={remote.card.url} skill={skill_id}",
            flush=True,
        )

        task_id = str(uuid4())
        append_event(
            log_path,
            {
                "event": "task_submitted",
                "context_id": context_id,
                "task_id": task_id,
                "phase": phase,
                "agent": remote.card.name,
                "skill_id": skill_id,
            },
        )

        result = client.send_task(
            agent=remote,
            skill_id=skill_id,
            context_id=context_id,
            payload=payload,
            task_id=task_id,
        )

        print(
            f"[A2A] task={result.task_id} agent={result.agent_name} "
            f"state={result.state.value}",
            flush=True,
        )
        append_event(
            log_path,
            {
                "event": "task_completed",
                **result.model_dump(mode="json"),
            },
        )

        if result.state != TaskState.completed:
            return int(result.metadata.get("exit_code", 1) or 1)

    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="CVE-Genie A2A orchestrator"
    )
    parser.add_argument("--cve", required=True)
    parser.add_argument("--json", required=True)
    parser.add_argument(
        "--run-type",
        required=True,
        choices=[
            "build",
            "exploit",
            "verify",
            "build,exploit",
            "exploit,verify",
            "build,exploit,verify",
        ],
    )
    parser.add_argument("--log", required=True)
    args = parser.parse_args()

    return run_workflow(
        cve_id=args.cve.upper(),
        json_path=Path(args.json),
        run_type=args.run_type,
        log_path=Path(args.log),
    )


if __name__ == "__main__":
    raise SystemExit(main())
