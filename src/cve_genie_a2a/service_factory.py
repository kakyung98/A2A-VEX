from __future__ import annotations

from pathlib import Path
from typing import Callable

from fastapi import FastAPI, Header, HTTPException

from cve_genie_a2a.config import settings
from cve_genie_a2a.executor import run_phase
from cve_genie_a2a.models import (
    A2ATaskRequest,
    A2ATaskResponse,
    AgentCard,
    AgentSkill,
    Artifact,
    DataPart,
    Message,
    TaskState,
    TextPart,
)


def create_phase_agent(
    *,
    name: str,
    description: str,
    skill_id: str,
    skill_name: str,
    run_type: str,
    public_url: str,
) -> FastAPI:
    app = FastAPI(title=name, version="0.1.0")

    card = AgentCard(
        name=name,
        description=description,
        url=public_url,
        skills=[
            AgentSkill(
                id=skill_id,
                name=skill_name,
                description=description,
            )
        ],
    )

    @app.get("/.well-known/agent-card.json", response_model=AgentCard)
    def agent_card() -> AgentCard:
        return card

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok", "agent": name}

    @app.post("/a2a/tasks", response_model=A2ATaskResponse)
    def execute_task(
        request: A2ATaskRequest,
        authorization: str | None = Header(default=None),
    ) -> A2ATaskResponse:
        _authorize(authorization)

        if request.skill_id != skill_id:
            raise HTTPException(
                status_code=400,
                detail=f"Unsupported skill: {request.skill_id}",
            )

        payload = _extract_payload(request)
        cve_id = str(payload.get("cve_id", "")).strip().upper()
        json_path = Path(str(payload.get("json_path", ""))).resolve()
        log_path = Path(str(payload.get("log_path", ""))).resolve()

        if not cve_id or not json_path.exists():
            raise HTTPException(
                status_code=422,
                detail="cve_id and an existing json_path are required",
            )

        result = run_phase(
            cve_id=cve_id,
            json_path=json_path,
            run_type=run_type,
            log_path=log_path,
        )

        succeeded = result.exit_code == 0
        state = TaskState.completed if succeeded else TaskState.failed

        return A2ATaskResponse(
            task_id=request.task_id,
            context_id=request.context_id,
            agent_name=name,
            state=state,
            message=Message(
                role="agent",
                parts=[
                    TextPart(
                        text=(
                            f"{name} completed phase {run_type}"
                            if succeeded
                            else f"{name} failed phase {run_type}"
                        )
                    )
                ],
            ),
            artifacts=[
                Artifact(
                    name=f"{run_type}-phase-result",
                    description="CVE-Genie phase execution result",
                    data={
                        "cve_id": cve_id,
                        "run_type": run_type,
                        "exit_code": result.exit_code,
                        "json_path": str(json_path),
                        "log_path": result.log_path,
                    },
                )
            ],
            metadata={"exit_code": result.exit_code},
        )

    return app


def _extract_payload(request: A2ATaskRequest) -> dict:
    for part in request.message.parts:
        if isinstance(part, DataPart):
            return part.data
    raise HTTPException(
        status_code=422,
        detail="A data message part is required",
    )


def _authorize(authorization: str | None) -> None:
    if not settings.shared_token:
        return
    expected = f"Bearer {settings.shared_token}"
    if authorization != expected:
        raise HTTPException(status_code=401, detail="Invalid A2A token")
