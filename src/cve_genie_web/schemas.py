from __future__ import annotations

import re
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator


JobStatus = Literal[
    "queued",
    "validating",
    "extracting",
    "needs_input",
    "needs_asset_input",
    "ready",
    "running",
    "assessing_asset",
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
    "not_attempted",
]


AnalysisMode = Literal[
    "source_reproduction",
    "asset_context_assessment",
]


SourceAvailability = Literal[
    "available",
    "unavailable",
    "uncertain",
]


AssetAssessmentStatus = Literal[
    "pending",
    "sufficient",
    "insufficient",
    "assessing",
    "assessed",
]


AssetImpactStatus = Literal[
    "likely_affected",
    "likely_not_affected",
    "mitigated",
    "under_investigation",
    "unknown",
]


PatchStatus = Literal[
    "patched",
    "unpatched",
    "unknown",
]


DeploymentType = Literal[
    "server",
    "workstation",
    "embedded",
    "container",
    "virtual_machine",
    "appliance",
    "network_device",
    "cloud_service",
    "unknown",
]


class JobCreateRequest(BaseModel):
    """
    새로운 CVE 분석 작업 생성 요청.
    """

    cve_id: str = Field(
        ...,
        examples=["CVE-2021-44228"],
        description="CVE identifier to analyze",
    )

    run_type: str = Field(
        default="build,exploit,verify",
        description="CVE-Genie run stages",
    )

    @field_validator("cve_id")
    @classmethod
    def validate_cve_id(
        cls,
        value: str,
    ) -> str:
        normalized = value.strip().upper()

        if not re.fullmatch(
            r"CVE-\d{4}-\d{4,}",
            normalized,
        ):
            raise ValueError(
                "Invalid CVE ID format"
            )

        return normalized

    @field_validator("run_type")
    @classmethod
    def validate_run_type(
        cls,
        value: str,
    ) -> str:
        allowed = {
            "build",
            "exploit",
            "verify",
        }

        stages = [
            item.strip()
            for item in value.split(",")
            if item.strip()
        ]

        if not stages:
            raise ValueError(
                "run_type must contain at least one stage"
            )

        if any(
            stage not in allowed
            for stage in stages
        ):
            raise ValueError(
                "run_type must contain only build, "
                "exploit, and/or verify"
            )

        return ",".join(
            dict.fromkeys(stages)
        )


class JobResponse(BaseModel):
    """
    작업 상태 및 결과 조회 응답.
    """

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

    missing_fields: list[str] = Field(
        default_factory=list
    )

    reproduction_status: ReproductionStatus = "unknown"
    exploitable: bool | None = None
    verifier_passed: bool | None = None
    final_reason: str | None = None

    analysis_mode: AnalysisMode | None = None
    source_availability: SourceAvailability | None = None

    asset_assessment_status: (
        AssetAssessmentStatus | None
    ) = None

    asset_impact_status: (
        AssetImpactStatus | None
    ) = None

    asset_assessment_confidence: (
        float | None
    ) = None

    created_at: str
    updated_at: str
    started_at: str | None = None
    finished_at: str | None = None


class JobLogResponse(BaseModel):
    """
    작업 로그 조회 응답.
    """

    job_id: str
    content: str


class JobInputResponse(BaseModel):
    """
    CVE 재현 입력 JSON 조회 응답.
    """

    job_id: str
    cve_id: str
    data: dict[str, Any]

    missing_fields: list[str] = Field(
        default_factory=list
    )


class JobInputUpdateRequest(BaseModel):
    """
    CVE 재현 입력 JSON 수정 요청.
    """

    data: dict[str, Any]


class JobResultResponse(BaseModel):
    """
    작업 최종 결과 및 아티팩트 조회 응답.
    """

    job_id: str
    status: JobStatus

    reproduction_status: ReproductionStatus = "unknown"

    exploitable: bool | None = None
    verifier_passed: bool | None = None
    final_reason: str | None = None

    analysis_mode: AnalysisMode | None = None
    source_availability: SourceAvailability | None = None

    asset_assessment_status: (
        AssetAssessmentStatus | None
    ) = None

    asset_impact_status: (
        AssetImpactStatus | None
    ) = None

    asset_assessment_confidence: (
        float | None
    ) = None

    result_path: str | None = None

    artifacts: list[str] = Field(
        default_factory=list
    )


class AssetExposure(BaseModel):
    """
    자산의 네트워크 노출 정보.
    """

    internet_exposed: bool = False

    reachable_networks: list[str] = Field(
        default_factory=list
    )

    listening_ports: list[int] = Field(
        default_factory=list
    )

    authentication_required: bool | None = None

    access_restrictions: list[str] = Field(
        default_factory=list
    )

    @field_validator("listening_ports")
    @classmethod
    def validate_listening_ports(
        cls,
        values: list[int],
    ) -> list[int]:
        normalized_ports: list[int] = []

        for port in values:
            if port < 1 or port > 65535:
                raise ValueError(
                    "Listening ports must be between "
                    "1 and 65535"
                )

            if port not in normalized_ports:
                normalized_ports.append(port)

        return normalized_ports


class AssetRuntime(BaseModel):
    """
    자산에서 취약 컴포넌트가 실제 실행 또는
    활성화되어 있는지 나타내는 운영 정보.
    """

    service_running: bool | None = None
    vulnerable_feature_enabled: bool | None = None
    component_loaded: bool | None = None
    component_reachable: bool | None = None

    service_name: str | None = None
    process_name: str | None = None
    execution_context: str | None = None


class AssetSecurityControls(BaseModel):
    """
    적용된 보안 통제 및 보완조치.
    """

    firewall_enabled: bool | None = None
    network_segmentation: bool | None = None
    application_allowlisting: bool | None = None
    ids_ips_enabled: bool | None = None
    endpoint_protection_enabled: bool | None = None

    compensating_controls: list[str] = Field(
        default_factory=list
    )


class AssetEvidence(BaseModel):
    """
    자산 운영 정보의 근거.
    """

    evidence_type: Literal[
        "package_inventory",
        "process_list",
        "service_configuration",
        "network_scan",
        "firewall_rule",
        "patch_inventory",
        "vendor_statement",
        "operator_statement",
        "screenshot",
        "log",
        "other",
    ]

    description: str

    observed_at: str | None = None
    source: str | None = None


class AssetOperationInput(BaseModel):
    """
    공개 소스코드를 확보할 수 없는 경우
    사용자가 입력하는 자산 운영 정보.
    """

    product_name: str = Field(
        ...,
        min_length=1,
        description="Installed product name",
    )

    vendor: str | None = None

    installed_version: str = Field(
        ...,
        min_length=1,
        description="Installed product or component version",
    )

    operating_system: str | None = None
    architecture: str | None = None

    deployment_type: DeploymentType = "unknown"

    exposure: AssetExposure = Field(
        default_factory=AssetExposure
    )

    runtime: AssetRuntime = Field(
        default_factory=AssetRuntime
    )

    security_controls: AssetSecurityControls = Field(
        default_factory=AssetSecurityControls
    )

    patch_status: PatchStatus = "unknown"

    evidence: list[AssetEvidence] = Field(
        default_factory=list
    )

    evidence_notes: str | None = None

    @field_validator(
        "product_name",
        "installed_version",
    )
    @classmethod
    def normalize_required_text(
        cls,
        value: str,
    ) -> str:
        normalized = value.strip()

        if not normalized:
            raise ValueError(
                "Value must not be empty"
            )

        return normalized


class AssetOperationUpdateRequest(BaseModel):
    """
    자산 운영 정보 저장 요청.
    """

    asset: AssetOperationInput


class AssetOperationResponse(BaseModel):
    """
    저장된 자산 운영 정보 조회 응답.
    """

    job_id: str
    cve_id: str
    status: JobStatus

    asset: AssetOperationInput | None = None

    asset_assessment_status: (
        AssetAssessmentStatus | None
    ) = None

    missing_fields: list[str] = Field(
        default_factory=list
    )


class AssetAssessmentResponse(BaseModel):
    """
    자산 운영 정보 기반 취약점 영향 평가 결과.
    """

    job_id: str
    cve_id: str

    status: JobStatus

    analysis_mode: AnalysisMode = (
        "asset_context_assessment"
    )

    reproduction_status: ReproductionStatus = (
        "not_attempted"
    )

    asset_impact_status: AssetImpactStatus

    confidence: float = Field(
        ...,
        ge=0.0,
        le=1.0,
    )

    reasons: list[str] = Field(
        default_factory=list
    )

    missing_evidence: list[str] = Field(
        default_factory=list
    )


class JobActionResponse(BaseModel):
    """
    작업 저장, 재개 또는 평가 시작 응답.
    """

    job_id: str
    status: JobStatus
    message: str | None = None