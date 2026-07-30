from __future__ import annotations

from pathlib import Path
from typing import Any
from uuid import uuid4

from fastapi import (
    APIRouter,
    BackgroundTasks,
    HTTPException,
    Query,
)

from cve_genie_web.config import settings
from cve_genie_web.repository import JobRepository
from cve_genie_web.schemas import (
    JobCreateRequest,
    JobInputResponse,
    JobInputUpdateRequest,
    JobLogResponse,
    JobResponse,
    JobResultResponse,
)
from cve_genie_web.services.input_service import (
    InputFileError,
    read_input_json,
    write_input_json,
)
from cve_genie_web.services.result_service import (
    list_artifacts,
)
from cve_genie_web.services.validation_service import (
    validate_reproduction_input,
)
from cve_genie_web.workers.job_worker import (
    assess_asset_job,
    resume_job,
    run_job,
)


router = APIRouter(
    prefix="/api/jobs",
    tags=["jobs"],
)

repository = JobRepository()


ASSET_REQUIRED_FIELDS = {
    "product_name",
    "installed_version",
}


def get_job_or_404(job_id: str):
    try:
        return repository.get(job_id)

    except KeyError as exc:
        raise HTTPException(
            status_code=404,
            detail="Job not found",
        ) from exc


def _validate_asset_input(
    asset: Any,
) -> dict[str, Any]:
    if not isinstance(asset, dict):
        raise HTTPException(
            status_code=422,
            detail="The asset field must be a JSON object.",
        )

    missing_fields = sorted(
        field_name
        for field_name in ASSET_REQUIRED_FIELDS
        if not str(asset.get(field_name) or "").strip()
    )

    if missing_fields:
        raise HTTPException(
            status_code=422,
            detail={
                "message": (
                    "Required asset fields are missing."
                ),
                "missing_fields": missing_fields,
            },
        )

    for field_name in (
        "runtime",
        "exposure",
        "security_controls",
    ):
        value = asset.get(field_name)

        if value is not None and not isinstance(
            value,
            dict,
        ):
            raise HTTPException(
                status_code=422,
                detail=(
                    f"asset.{field_name} must be "
                    "a JSON object."
                ),
            )

    exposure = asset.get("exposure") or {}
    listening_ports = exposure.get(
        "listening_ports",
        [],
    )

    if not isinstance(listening_ports, list):
        raise HTTPException(
            status_code=422,
            detail=(
                "asset.exposure.listening_ports "
                "must be a list."
            ),
        )

    invalid_ports: list[Any] = []

    for port in listening_ports:
        if (
            not isinstance(port, int)
            or isinstance(port, bool)
            or port < 1
            or port > 65535
        ):
            invalid_ports.append(port)

    if invalid_ports:
        raise HTTPException(
            status_code=422,
            detail={
                "message": "Invalid listening ports.",
                "invalid_ports": invalid_ports,
            },
        )

    return asset


def _asset_response(job) -> dict[str, Any]:
    return {
        "job_id": job.job_id,
        "cve_id": job.cve_id,
        "status": job.status,
        "stage": job.stage,
        "message": job.message,
        "analysis_mode": job.analysis_mode,
        "source_availability": (
            job.source_availability
        ),
        "base_vex_status": job.base_vex_status,
        "asset_assessment_status": (
            job.asset_assessment_status
        ),
        "asset_impact_status": (
            job.asset_impact_status
        ),
        "likelihood_status": job.likelihood_status,
        "confidence": (
            job.asset_assessment_confidence
        ),
        "asset": job.asset_input,
        "semantic_profile": job.semantic_profile,
        "evidence_claims": job.evidence_claims,
        "matched_conditions": (
            job.matched_conditions
        ),
        "unmatched_conditions": (
            job.unmatched_conditions
        ),
        "unknown_conditions": (
            job.unknown_conditions
        ),
        "supporting_claim_ids": (
            job.supporting_claim_ids
        ),
        "contradicting_claim_ids": (
            job.contradicting_claim_ids
        ),
        "reasons": (
            job.asset_assessment_reasons
        ),
    }


@router.post(
    "",
    response_model=JobResponse,
    status_code=202,
)
def create_job(
    request: JobCreateRequest,
    background_tasks: BackgroundTasks,
) -> JobResponse:
    job_id = str(uuid4())
    job_directory = settings.job_root / job_id

    input_path = (
        job_directory
        / "input"
        / f"{request.cve_id}.json"
    )

    log_path = (
        job_directory
        / "logs"
        / "job.log"
    )

    log_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    log_path.touch(
        exist_ok=False,
    )

    job = repository.create(
        job_id=job_id,
        cve_id=request.cve_id,
        input_json_path=str(input_path),
        log_path=str(log_path),
        run_type=request.run_type,
    )

    background_tasks.add_task(
        run_job,
        job_id,
    )

    return JobResponse.model_validate(
        job.to_dict()
    )


@router.get(
    "",
    response_model=list[JobResponse],
)
def list_jobs(
    limit: int = Query(
        default=50,
        ge=1,
        le=200,
    ),
) -> list[JobResponse]:
    return [
        JobResponse.model_validate(
            job.to_dict()
        )
        for job in repository.list(
            limit=limit
        )
    ]


@router.get(
    "/{job_id}",
    response_model=JobResponse,
)
def get_job(
    job_id: str,
) -> JobResponse:
    job = get_job_or_404(job_id)

    return JobResponse.model_validate(
        job.to_dict()
    )


@router.get(
    "/{job_id}/log",
    response_model=JobLogResponse,
)
def get_job_log(
    job_id: str,
) -> JobLogResponse:
    job = get_job_or_404(job_id)

    if not job.log_path:
        return JobLogResponse(
            job_id=job_id,
            content="",
        )

    path = Path(job.log_path)

    content = (
        path.read_text(
            encoding="utf-8",
            errors="replace",
        )
        if path.exists()
        else ""
    )

    return JobLogResponse(
        job_id=job_id,
        content=content,
    )


@router.get(
    "/{job_id}/input",
    response_model=JobInputResponse,
)
def get_job_input(
    job_id: str,
) -> JobInputResponse:
    job = get_job_or_404(job_id)

    try:
        data = read_input_json(
            Path(job.input_json_path or "")
        )

    except InputFileError as exc:
        raise HTTPException(
            status_code=404,
            detail=str(exc),
        ) from exc

    return JobInputResponse(
        job_id=job.job_id,
        cve_id=job.cve_id,
        data=data,
        missing_fields=job.missing_fields,
    )


@router.put(
    "/{job_id}/input",
    response_model=JobInputResponse,
)
def update_job_input(
    job_id: str,
    request: JobInputUpdateRequest,
) -> JobInputResponse:
    job = get_job_or_404(job_id)
    path = Path(
        job.input_json_path or ""
    )

    write_input_json(
        path,
        request.data,
    )

    validation = validate_reproduction_input(
        request.data,
        expected_cve_id=job.cve_id,
    )

    repository.update(
        job_id,
        message="Input JSON updated",
        missing_fields=(
            validation.missing_fields
        ),
    )

    return JobInputResponse(
        job_id=job.job_id,
        cve_id=job.cve_id,
        data=request.data,
        missing_fields=(
            validation.missing_fields
        ),
    )


@router.post(
    "/{job_id}/resume",
    response_model=JobResponse,
    status_code=202,
)
def resume_existing_job(
    job_id: str,
    background_tasks: BackgroundTasks,
) -> JobResponse:
    job = get_job_or_404(job_id)

    if job.status not in {
        "needs_input",
        "failed",
        "unsupported",
    }:
        raise HTTPException(
            status_code=409,
            detail=(
                "Only needs_input, failed, or "
                "unsupported jobs can be resumed."
            ),
        )

    background_tasks.add_task(
        resume_job,
        job_id,
    )

    job = repository.update(
        job_id,
        status="queued",
        stage="queued",
        message="Resume requested",
        finished_at=None,
        exit_code=None,
        reproduction_status="unknown",
        exploitable=None,
        verifier_passed=None,
        final_reason=None,
    )

    return JobResponse.model_validate(
        job.to_dict()
    )


@router.get(
    "/{job_id}/asset-input",
)
def get_asset_input(
    job_id: str,
) -> dict[str, Any]:
    return _asset_response(
        get_job_or_404(job_id)
    )


@router.put(
    "/{job_id}/asset-input",
)
def update_asset_input(
    job_id: str,
    request: dict[str, Any],
) -> dict[str, Any]:
    job = get_job_or_404(job_id)

    allowed_statuses = {
        "needs_asset_input",
        "failed",
        "succeeded",
    }

    if job.status not in allowed_statuses:
        raise HTTPException(
            status_code=409,
            detail=(
                "Asset input can only be saved for "
                "needs_asset_input, failed, or completed "
                "asset-context jobs."
            ),
        )

    if (
        job.status == "succeeded"
        and job.analysis_mode
        != "asset_context_assessment"
    ):
        raise HTTPException(
            status_code=409,
            detail=(
                "A source-reproduction job cannot be "
                "converted into an asset-context job."
            ),
        )

    asset = _validate_asset_input(
        request.get("asset")
    )

    job = repository.update(
        job_id,
        analysis_mode="asset_context_assessment",
        base_vex_status="under_investigation",
        asset_input=asset,
        asset_assessment_status="pending",
        asset_impact_status=None,
        asset_assessment_confidence=None,
        asset_assessment_reasons=[],
        matched_conditions=[],
        unmatched_conditions=[],
        unknown_conditions=[],
        supporting_claim_ids=[],
        contradicting_claim_ids=[],
        likelihood_status=None,
        reproduction_status="not_attempted",
        exploitable=None,
        verifier_passed=None,
        final_reason=(
            "Asset operational context saved. "
            "Likelihood assessment has not completed."
        ),
        message=(
            "Asset operational context saved"
        ),
        finished_at=None,
    )

    return _asset_response(job)


@router.post(
    "/{job_id}/assess-asset",
    status_code=202,
)
def assess_asset(
    job_id: str,
    background_tasks: BackgroundTasks,
) -> dict[str, Any]:
    job = get_job_or_404(job_id)

    allowed_statuses = {
        "needs_asset_input",
        "failed",
        "succeeded",
    }

    if job.status not in allowed_statuses:
        raise HTTPException(
            status_code=409,
            detail=(
                "Asset assessment can only be started for "
                "needs_asset_input, failed, or completed "
                "asset-context jobs."
            ),
        )

    if (
        job.status == "succeeded"
        and job.analysis_mode
        != "asset_context_assessment"
    ):
        raise HTTPException(
            status_code=409,
            detail=(
                "This completed job used source reproduction "
                "and cannot be reassessed as an asset-context job."
            ),
        )

    if not job.asset_input:
        raise HTTPException(
            status_code=409,
            detail=(
                "Asset operational information must be "
                "saved before assessment."
            ),
        )

    job = repository.update(
        job_id,
        status="assessing_asset",
        stage="queued_asset_assessment",
        asset_assessment_status="pending",
        analysis_mode="asset_context_assessment",
        base_vex_status="under_investigation",
        likelihood_status=None,
        message=(
            "Semantic asset assessment queued"
        ),
        reproduction_status="not_attempted",
        exploitable=None,
        verifier_passed=None,
        exit_code=None,
        finished_at=None,
    )

    background_tasks.add_task(
        assess_asset_job,
        job_id,
    )

    return {
        "job_id": job.job_id,
        "status": job.status,
        "stage": job.stage,
        "base_vex_status": (
            job.base_vex_status
        ),
        "asset_assessment_status": (
            job.asset_assessment_status
        ),
        "message": job.message,
    }


@router.get(
    "/{job_id}/result",
    response_model=JobResultResponse,
)
def get_job_result(
    job_id: str,
) -> JobResultResponse:
    job = get_job_or_404(job_id)

    return JobResultResponse(
        job_id=job.job_id,
        status=job.status,
        reproduction_status=(
            job.reproduction_status
        ),
        exploitable=(
            None
            if job.exploitable is None
            else bool(job.exploitable)
        ),
        verifier_passed=(
            None
            if job.verifier_passed is None
            else bool(job.verifier_passed)
        ),
        final_reason=job.final_reason,
        result_path=job.result_path,
        artifacts=list_artifacts(
            job.result_path
        ),
    )
