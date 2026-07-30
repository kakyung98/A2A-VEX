from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import traceback

from cve_genie_web.repository import JobRepository
from cve_genie_web.services.extraction_service import extract_cve_data
from cve_genie_web.services.input_service import (
    InputFileError,
    read_input_json,
)
from cve_genie_web.services.reproduction_result_service import (
    parse_reproduction_result,
)
from cve_genie_web.services.result_service import find_result_directory
from cve_genie_web.services.runner_service import run_cve_genie
from cve_genie_web.services.validation_service import (
    validate_reproduction_input,
)


repository = JobRepository()


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def append_log(log_path: Path, message: str) -> None:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("a", encoding="utf-8") as handle:
        handle.write(message.rstrip() + "\n")


def validate_and_run(job_id: str) -> None:
    job = repository.get(job_id)
    log_path = Path(job.log_path or "")
    json_path = Path(job.input_json_path or "")

    repository.update(
        job_id,
        status="validating",
        stage="validating",
        message="Validating extracted reproduction context",
        missing_fields=[],
        reproduction_status="unknown",
        exploitable=None,
        verifier_passed=None,
        final_reason=None,
    )

    try:
        document = read_input_json(json_path)
    except InputFileError as exc:
        repository.update(
            job_id,
            status="failed",
            stage="validating",
            message=str(exc),
            finished_at=utc_now_iso(),
        )
        return

    validation = validate_reproduction_input(
        document,
        expected_cve_id=job.cve_id,
    )

    if validation.unsupported_reasons:
        message = "; ".join(validation.unsupported_reasons)
        append_log(log_path, f"[unsupported] {message}")
        repository.update(
            job_id,
            status="unsupported",
            stage="unsupported",
            message=message,
            missing_fields=[],
            reproduction_status="unknown",
            finished_at=utc_now_iso(),
        )
        return

    if not validation.valid:
        message = (
            "Additional reproduction context is required: "
            + ", ".join(validation.missing_fields)
        )
        append_log(log_path, f"[needs_input] {message}")
        repository.update(
            job_id,
            status="needs_input",
            stage="needs_input",
            message=message,
            missing_fields=validation.missing_fields,
            reproduction_status="unknown",
            finished_at=None,
        )
        return

    repository.update(
        job_id,
        status="ready",
        stage="ready",
        message="Input validated; starting CVE-Genie",
        missing_fields=[],
    )

    repository.update(
        job_id,
        status="running",
        stage=job.run_type,
        message="CVE-Genie is running",
    )

    execution_code = run_cve_genie(
        cve_id=job.cve_id,
        json_path=json_path,
        run_type=job.run_type,
        log_path=log_path,
    )

    result_directory = find_result_directory(job.cve_id)
    reproduction = parse_reproduction_result(log_path)

    common_fields = {
        "result_path": (
            str(result_directory)
            if result_directory is not None
            else None
        ),
        "exit_code": execution_code,
        "finished_at": utc_now_iso(),
        "reproduction_status": reproduction.reproduction_status,
        "exploitable": reproduction.exploitable,
        "verifier_passed": reproduction.verifier_passed,
        "final_reason": reproduction.final_reason,
    }

    if execution_code == 0:
        repository.update(
            job_id,
            status="succeeded",
            stage="completed",
            message=(
                "CVE-Genie completed successfully. "
                f"Reproduction result: {reproduction.reproduction_status}"
            ),
            **common_fields,
        )
    else:
        repository.update(
            job_id,
            status="failed",
            stage="execution",
            message=f"CVE-Genie failed: {execution_code}",
            **common_fields,
        )


def run_job(job_id: str) -> None:
    job = repository.get(job_id)
    log_path = Path(job.log_path or "")
    json_path = Path(job.input_json_path or "")

    try:
        repository.update(
            job_id,
            status="extracting",
            stage="extracting",
            message="Extracting CVE data",
            started_at=utc_now_iso(),
            finished_at=None,
            exit_code=None,
            missing_fields=[],
            reproduction_status="unknown",
            exploitable=None,
            verifier_passed=None,
            final_reason=None,
        )

        extraction_code = extract_cve_data(
            cve_id=job.cve_id,
            output_path=json_path,
            log_path=log_path,
        )

        if extraction_code != 0:
            if json_path.exists():
                append_log(
                    log_path,
                    (
                        "[warning] Extraction returned a non-zero exit "
                        "code, but an input file was created. "
                        "The file will be validated."
                    ),
                )
                validate_and_run(job_id)
                return

            repository.update(
                job_id,
                status="failed",
                stage="extracting",
                message=(
                    "CVE data extraction failed and no input JSON "
                    f"was produced: {extraction_code}"
                ),
                exit_code=extraction_code,
                finished_at=utc_now_iso(),
            )
            return

        validate_and_run(job_id)

    except Exception as exc:
        append_log(log_path, traceback.format_exc())
        repository.update(
            job_id,
            status="failed",
            stage="internal_error",
            message=f"Internal worker error: {exc}",
            finished_at=utc_now_iso(),
        )


def resume_job(job_id: str) -> None:
    job = repository.get(job_id)

    if job.status not in {
        "needs_input",
        "failed",
        "unsupported",
    }:
        raise ValueError(
            "Only needs_input, failed, or unsupported jobs can be resumed"
        )

    repository.update(
        job_id,
        status="queued",
        stage="queued",
        message="Job queued after input update",
        exit_code=None,
        finished_at=None,
        reproduction_status="unknown",
        exploitable=None,
        verifier_passed=None,
        final_reason=None,
    )

    validate_and_run(job_id)
