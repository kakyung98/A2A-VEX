from __future__ import annotations

from pathlib import Path
from uuid import uuid4

from fastapi import APIRouter, BackgroundTasks, HTTPException, Query

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
from cve_genie_web.services.result_service import list_artifacts
from cve_genie_web.services.validation_service import (
    validate_reproduction_input,
)
from cve_genie_web.workers.job_worker import (
    resume_job,
    run_job,
)


router = APIRouter(prefix="/api/jobs", tags=["jobs"])
repository = JobRepository()


def get_job_or_404(job_id: str):
    try:
        return repository.get(job_id)
    except KeyError as exc:
        raise HTTPException(
            status_code=404,
            detail="Job not found",
        ) from exc


@router.post("", response_model=JobResponse, status_code=202)
def create_job(
    request: JobCreateRequest,
    background_tasks: BackgroundTasks,
) -> JobResponse:
    job_id = str(uuid4())
    job_directory = settings.job_root / job_id

    input_path = job_directory / "input" / f"{request.cve_id}.json"
    log_path = job_directory / "logs" / "job.log"

    log_path.parent.mkdir(parents=True, exist_ok=True)
    log_path.touch(exist_ok=False)

    job = repository.create(
        job_id=job_id,
        cve_id=request.cve_id,
        input_json_path=str(input_path),
        log_path=str(log_path),
        run_type=request.run_type,
    )

    background_tasks.add_task(run_job, job_id)

    return JobResponse.model_validate(job.to_dict())


@router.get("", response_model=list[JobResponse])
def list_jobs(
    limit: int = Query(default=50, ge=1, le=200),
) -> list[JobResponse]:
    return [
        JobResponse.model_validate(job.to_dict())
        for job in repository.list(limit=limit)
    ]


@router.get("/{job_id}", response_model=JobResponse)
def get_job(job_id: str) -> JobResponse:
    job = get_job_or_404(job_id)
    return JobResponse.model_validate(job.to_dict())


@router.get("/{job_id}/log", response_model=JobLogResponse)
def get_job_log(job_id: str) -> JobLogResponse:
    job = get_job_or_404(job_id)

    if not job.log_path:
        return JobLogResponse(job_id=job_id, content="")

    path = Path(job.log_path)
    content = (
        path.read_text(encoding="utf-8", errors="replace")
        if path.exists()
        else ""
    )

    return JobLogResponse(job_id=job_id, content=content)


@router.get("/{job_id}/input", response_model=JobInputResponse)
def get_job_input(job_id: str) -> JobInputResponse:
    job = get_job_or_404(job_id)

    try:
        data = read_input_json(Path(job.input_json_path or ""))
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


@router.put("/{job_id}/input", response_model=JobInputResponse)
def update_job_input(
    job_id: str,
    request: JobInputUpdateRequest,
) -> JobInputResponse:
    job = get_job_or_404(job_id)
    path = Path(job.input_json_path or "")

    write_input_json(path, request.data)

    validation = validate_reproduction_input(
        request.data,
        expected_cve_id=job.cve_id,
    )

    repository.update(
        job_id,
        message="Input JSON updated",
        missing_fields=validation.missing_fields,
    )

    return JobInputResponse(
        job_id=job.job_id,
        cve_id=job.cve_id,
        data=request.data,
        missing_fields=validation.missing_fields,
    )


@router.post("/{job_id}/resume", response_model=JobResponse, status_code=202)
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
                "Only needs_input, failed, or unsupported jobs "
                "can be resumed"
            ),
        )

    background_tasks.add_task(resume_job, job_id)

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

    return JobResponse.model_validate(job.to_dict())


@router.get("/{job_id}/result", response_model=JobResultResponse)
def get_job_result(job_id: str) -> JobResultResponse:
    job = get_job_or_404(job_id)

    return JobResultResponse(
        job_id=job.job_id,
        status=job.status,
        reproduction_status=job.reproduction_status,
        exploitable=(
            None if job.exploitable is None else bool(job.exploitable)
        ),
        verifier_passed=(
            None
            if job.verifier_passed is None
            else bool(job.verifier_passed)
        ),
        final_reason=job.final_reason,
        result_path=job.result_path,
        artifacts=list_artifacts(job.result_path),
    )
