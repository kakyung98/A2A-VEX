from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class TaskState(str, Enum):
    submitted = "submitted"
    working = "working"
    completed = "completed"
    failed = "failed"


class TextPart(BaseModel):
    kind: str = "text"
    text: str


class DataPart(BaseModel):
    kind: str = "data"
    data: dict[str, Any]


class Message(BaseModel):
    message_id: str = Field(default_factory=lambda: str(uuid4()))
    role: str
    parts: list[TextPart | DataPart]
    created_at: str = Field(default_factory=utc_now)


class Artifact(BaseModel):
    artifact_id: str = Field(default_factory=lambda: str(uuid4()))
    name: str
    description: str | None = None
    data: dict[str, Any] = Field(default_factory=dict)
    created_at: str = Field(default_factory=utc_now)


class A2ATaskRequest(BaseModel):
    task_id: str = Field(default_factory=lambda: str(uuid4()))
    context_id: str = Field(default_factory=lambda: str(uuid4()))
    skill_id: str
    message: Message
    metadata: dict[str, Any] = Field(default_factory=dict)


class A2ATaskResponse(BaseModel):
    task_id: str
    context_id: str
    agent_name: str
    state: TaskState
    message: Message
    artifacts: list[Artifact] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class AgentSkill(BaseModel):
    id: str
    name: str
    description: str
    input_modes: list[str] = ["application/json"]
    output_modes: list[str] = ["application/json"]


class AgentCard(BaseModel):
    name: str
    description: str
    version: str = "0.1.0"
    protocol_version: str = "CVE-Genie-A2A/0.1"
    url: str
    skills: list[AgentSkill]
    capabilities: dict[str, bool] = Field(
        default_factory=lambda: {
            "task_execution": True,
            "artifacts": True,
            "streaming": False,
        }
    )
