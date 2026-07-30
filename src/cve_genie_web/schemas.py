from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator


JobStatus = Literal[
    "queued",
    "validating",
    "extracting",
    "needs_input",
    "ready",
    "running",
    "succeeded",
    "failed",
    "unsupported",
    "cancelled",
]

ReproductionStatus = Literal[
    "confirmed",
    "not_reproduced",
    "inconclusive",
    "unknown",
]


class JobCreateRequest(BaseModel):
    cve_id: str = Field(
        ...,
        examples=["CVE-2021-44228"],
        description="CVE identifier to reproduce",
    )
    run_type: str = Field(
        default="build,exploit,verify",
        description="CVE-Genie run stages",
    )

    @field_validator("cve_id")
    @classmethod
    def validate_cve_id(cls, value: str) -> str:
        normalized = value.strip().upper()

        import re

        if not re.fullmatch(r"CVE-\d{4}-\d{4,}", normalized):
            raise ValueError("Invalid CVE ID format")
        return normalized

    @field_validator("run_type")
    @classmethod
    def validate_run_type(cls, value: str) -> str:
        allowed = {"build", "exploit", "verify"}
        stages = [item.strip() for item in value.split(",") if item.strip()]

        if not stages or any(stage not in allowed for stage in stages):
            raise ValueError(
                "run_type must contain build, exploit, and/or verify"
            )

        return ",".join(dict.fromkeys(stages))


class JobResponse(BaseModel):
    job_id: str
    cve_id: str
    status: JobStatus
    stage: str
    message: str | None = None
    input_json_path: str | None = None
    log_path: str | None = None
    result_path: str | None = None
    exit_code: int | None = None
    run_type: str
    missing_fields: list[str] = []
    reproduction_status: ReproductionStatus = "unknown"
    exploitable: bool | None = None
    verifier_passed: bool | None = None
    final_reason: str | None = None
    created_at: str
    updated_at: str
    started_at: str | None = None
    finished_at: str | None = None


class JobLogResponse(BaseModel):
    job_id: str
    content: str


class JobInputResponse(BaseModel):
    job_id: str
    cve_id: str
    data: dict[str, Any]
    missing_fields: list[str]


class JobInputUpdateRequest(BaseModel):
    data: dict[str, Any]


class JobResultResponse(BaseModel):
    job_id: str
    status: JobStatus
    reproduction_status: ReproductionStatus
    exploitable: bool | None
    verifier_passed: bool | None
    final_reason: str | None
    result_path: str | None
    artifacts: list[str]
