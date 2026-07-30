from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import httpx

from cve_genie_a2a.config import settings
from cve_genie_a2a.models import (
    A2ATaskRequest,
    A2ATaskResponse,
    AgentCard,
    DataPart,
    Message,
)


@dataclass(frozen=True)
class RemoteAgent:
    base_url: str
    card: AgentCard


class A2AClient:
    def __init__(self) -> None:
        self.timeout = settings.request_timeout_seconds

    def discover(self, base_url: str) -> RemoteAgent:
        response = httpx.get(
            f"{base_url.rstrip('/')}/.well-known/agent-card.json",
            timeout=30,
        )
        response.raise_for_status()
        return RemoteAgent(
            base_url=base_url.rstrip("/"),
            card=AgentCard.model_validate(response.json()),
        )

    def send_task(
        self,
        *,
        agent: RemoteAgent,
        skill_id: str,
        context_id: str,
        payload: dict[str, Any],
        task_id: str,
    ) -> A2ATaskResponse:
        request = A2ATaskRequest(
            task_id=task_id,
            context_id=context_id,
            skill_id=skill_id,
            message=Message(
                role="user",
                parts=[DataPart(data=payload)],
            ),
        )

        headers: dict[str, str] = {}
        if settings.shared_token:
            headers["Authorization"] = f"Bearer {settings.shared_token}"

        response = httpx.post(
            f"{agent.base_url}/a2a/tasks",
            json=request.model_dump(mode="json"),
            headers=headers,
            timeout=self.timeout,
        )
        response.raise_for_status()
        return A2ATaskResponse.model_validate(response.json())
