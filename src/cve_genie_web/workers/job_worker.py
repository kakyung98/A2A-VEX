from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import traceback
from typing import Any, Mapping

from cve_genie_web.repository import JobRepository
from cve_genie_web.services.evidence_fusion_service import (
    fuse_evidence,
)
from cve_genie_web.services.extraction_service import (
    extract_cve_data,
)
from cve_genie_web.services.input_service import (
    InputFileError,
    read_input_json,
)
from cve_genie_web.services.likelihood_assessment_service import (
    assess_likelihood,
)
from cve_genie_web.services.reproduction_result_service import (
    parse_reproduction_result,
)
from cve_genie_web.services.result_service import (
    find_result_directory,
)
from cve_genie_web.services.runner_service import (
    run_cve_genie,
)
from cve_genie_web.services.semantic_profile_service import (
    build_semantic_profile,
)
from cve_genie_web.services.validation_service import (
    AnalysisMode,
    SourceAvailability,
    validate_cve_input,
)


repository = JobRepository()


ASSET_INPUT_FIELDS = [
    "asset.product_name",
    "asset.vendor",
    "asset.installed_version",
    "asset.operating_system",
    "asset.architecture",
    "asset.deployment_type",
    "asset.runtime.service_running",
    "asset.runtime.vulnerable_feature_enabled",
    "asset.runtime.component_loaded",
    "asset.runtime.component_reachable",
    "asset.exposure.internet_exposed",
    "asset.exposure.reachable_networks",
    "asset.exposure.listening_ports",
    "asset.exposure.authentication_required",
    "asset.patch_status",
    "asset.security_controls",
    "asset.evidence_notes",
]


def utc_now_iso() -> str:
    return datetime.now(
        timezone.utc
    ).isoformat()


def append_log(
    log_path: Path,
    message: str,
) -> None:
    log_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with log_path.open(
        "a",
        encoding="utf-8",
    ) as handle:
        handle.write(
            message.rstrip() + "\n"
        )


def normalize_string_list(
    values: list[str] | None,
) -> list[str]:
    normalized_values: list[str] = []
    seen: set[str] = set()

    for value in values or []:
        normalized = str(value).strip()

        if not normalized:
            continue

        if normalized in seen:
            continue

        seen.add(normalized)
        normalized_values.append(normalized)

    return normalized_values


def _load_existing_claims(
    job_id: str,
) -> list[dict[str, Any]]:
    """
    Return claims already stored for the job.

    A2A services can save normalized Data Processor or Builder
    claims before asset assessment. The asset worker reuses them.
    """

    job = repository.get(job_id)

    claims = job.evidence_claims

    return [
        dict(claim)
        for claim in claims
        if isinstance(claim, Mapping)
    ]


def pause_for_manual_input(
    *,
    job_id: str,
    log_path: Path,
    missing_fields: list[str],
) -> None:
    normalized_missing_fields = normalize_string_list(
        missing_fields
    )

    if normalized_missing_fields:
        message = (
            "Source code was identified, but additional "
            "reproduction context is required: "
            + ", ".join(normalized_missing_fields)
        )
    else:
        message = (
            "Source code was identified, but additional "
            "reproduction context is required. "
            "Review and complete the generated input JSON."
        )

    append_log(
        log_path,
        f"[needs_input] {message}",
    )

    repository.update(
        job_id,
        status="needs_input",
        stage="reproduction_context_required",
        message=message,
        analysis_mode="source_reproduction",
        source_availability="available",
        missing_fields=normalized_missing_fields,
        reproduction_status="unknown",
        exploitable=None,
        verifier_passed=None,
        final_reason=None,
        exit_code=None,
        finished_at=None,
    )


def pause_for_asset_input(
    *,
    job_id: str,
    log_path: Path,
    source_availability: str,
    source_reasons: list[str],
    repository_urls: list[str],
    source_archive_urls: list[str],
    patch_urls: list[str],
) -> None:
    normalized_reasons = normalize_string_list(
        source_reasons
    )

    reason_text = "; ".join(
        normalized_reasons
    )

    if not reason_text:
        reason_text = (
            "No usable public source repository or "
            "source archive was identified."
        )

    message = (
        "Public source code could not be obtained. "
        "Asset operational information is required "
        "before the vulnerability impact can be assessed. "
        f"Source status: {source_availability}. "
        f"Reason: {reason_text}"
    )

    append_log(
        log_path,
        "[source_availability] "
        f"status={source_availability}",
    )

    for repository_url in repository_urls:
        append_log(
            log_path,
            "[source_repository] "
            f"{repository_url}",
        )

    for source_archive_url in source_archive_urls:
        append_log(
            log_path,
            "[source_archive] "
            f"{source_archive_url}",
        )

    for patch_url in patch_urls:
        append_log(
            log_path,
            "[patch_reference] "
            f"{patch_url}",
        )

    append_log(
        log_path,
        f"[needs_asset_input] {message}",
    )

    repository.update(
        job_id,
        status="needs_asset_input",
        stage="asset_context_required",
        message=message,
        analysis_mode="asset_context_assessment",
        source_availability=source_availability,
        base_vex_status="under_investigation",
        asset_assessment_status="pending",
        asset_impact_status=None,
        likelihood_status=None,
        asset_assessment_confidence=None,
        asset_assessment_reasons=[],
        matched_conditions=[],
        unmatched_conditions=[],
        unknown_conditions=[],
        supporting_claim_ids=[],
        contradicting_claim_ids=[],
        missing_fields=ASSET_INPUT_FIELDS,
        reproduction_status="not_attempted",
        exploitable=None,
        verifier_passed=None,
        final_reason=(
            "Source-based CVE reproduction was not attempted "
            "because usable source code was unavailable."
        ),
        exit_code=None,
        finished_at=None,
    )


def mark_unsupported(
    *,
    job_id: str,
    log_path: Path,
    unsupported_reasons: list[str],
) -> None:
    normalized_reasons = normalize_string_list(
        unsupported_reasons
    )

    if normalized_reasons:
        message = "; ".join(
            normalized_reasons
        )
    else:
        message = (
            "The extracted CVE input is not supported."
        )

    append_log(
        log_path,
        f"[unsupported] {message}",
    )

    repository.update(
        job_id,
        status="unsupported",
        stage="unsupported",
        message=message,
        missing_fields=[],
        reproduction_status="unknown",
        exploitable=None,
        verifier_passed=None,
        final_reason=None,
        exit_code=None,
        finished_at=utc_now_iso(),
    )


def execute_cve_genie(
    *,
    job_id: str,
    json_path: Path,
    log_path: Path,
) -> None:
    job = repository.get(
        job_id
    )

    append_log(
        log_path,
        "[validation] "
        "Source code and reproduction input are ready.",
    )

    repository.update(
        job_id,
        status="ready",
        stage="ready",
        message=(
            "Source code is available and the input "
            "was validated. Starting CVE-Genie."
        ),
        analysis_mode="source_reproduction",
        source_availability="available",
        missing_fields=[],
        reproduction_status="unknown",
        exploitable=None,
        verifier_passed=None,
        final_reason=None,
        exit_code=None,
        finished_at=None,
    )

    repository.update(
        job_id,
        status="running",
        stage=job.run_type,
        message="CVE-Genie is running",
        finished_at=None,
    )

    execution_code = run_cve_genie(
        cve_id=job.cve_id,
        json_path=json_path,
        run_type=job.run_type,
        log_path=log_path,
    )

    result_directory = find_result_directory(
        job.cve_id
    )

    reproduction = parse_reproduction_result(
        log_path
    )

    common_fields = {
        "result_path": (
            str(result_directory)
            if result_directory is not None
            else None
        ),
        "exit_code": execution_code,
        "finished_at": utc_now_iso(),
        "reproduction_status": (
            reproduction.reproduction_status
        ),
        "exploitable": (
            reproduction.exploitable
        ),
        "verifier_passed": (
            reproduction.verifier_passed
        ),
        "final_reason": (
            reproduction.final_reason
        ),
    }

    if execution_code == 0:
        repository.update(
            job_id,
            status="succeeded",
            stage="completed",
            message=(
                "CVE-Genie completed successfully. "
                "Reproduction result: "
                f"{reproduction.reproduction_status}"
            ),
            **common_fields,
        )
        return

    repository.update(
        job_id,
        status="failed",
        stage="execution",
        message=(
            f"CVE-Genie failed with exit code "
            f"{execution_code}"
        ),
        **common_fields,
    )


def validate_and_run(
    job_id: str,
) -> None:
    job = repository.get(
        job_id
    )

    log_path = Path(
        job.log_path or ""
    )

    json_path = Path(
        job.input_json_path or ""
    )

    repository.update(
        job_id,
        status="validating",
        stage="source_discovery",
        message=(
            "Checking source-code availability and "
            "validating the reproduction context."
        ),
        missing_fields=[],
        reproduction_status="unknown",
        exploitable=None,
        verifier_passed=None,
        final_reason=None,
        exit_code=None,
        finished_at=None,
    )

    append_log(
        log_path,
        "[validation] "
        "Checking source-code availability.",
    )

    try:
        document = read_input_json(
            json_path
        )

    except InputFileError as exc:
        append_log(
            log_path,
            f"[validation_error] {exc}",
        )

        repository.update(
            job_id,
            status="failed",
            stage="validating",
            message=str(exc),
            missing_fields=[],
            reproduction_status="unknown",
            exploitable=None,
            verifier_passed=None,
            final_reason=None,
            exit_code=None,
            finished_at=utc_now_iso(),
        )
        return

    validation = validate_cve_input(
        document,
        probe_remote_repositories=True,
        repository_probe_timeout_seconds=20,
    )

    unsupported_reasons = normalize_string_list(
        validation.unsupported_reasons
    )

    missing_fields = normalize_string_list(
        validation.missing_fields
    )

    repository_urls = normalize_string_list(
        validation.repository_urls
    )

    source_archive_urls = normalize_string_list(
        validation.source_archive_urls
    )

    patch_urls = normalize_string_list(
        validation.patch_urls
    )

    source_reasons = normalize_string_list(
        validation.source_reasons
    )

    append_log(
        log_path,
        "[source_availability] "
        f"{validation.source_availability.value}",
    )

    append_log(
        log_path,
        "[analysis_mode] "
        f"{validation.analysis_mode.value}",
    )

    for probe in validation.repository_probes:
        probe_status = (
            "reachable"
            if probe.reachable
            else "unreachable"
        )

        append_log(
            log_path,
            "[repository_probe] "
            f"{probe_status}: "
            f"{probe.repository_url} — "
            f"{probe.reason}",
        )

    if unsupported_reasons:
        mark_unsupported(
            job_id=job_id,
            log_path=log_path,
            unsupported_reasons=unsupported_reasons,
        )
        return

    if (
        validation.analysis_mode
        == AnalysisMode.ASSET_CONTEXT_ASSESSMENT
    ):
        pause_for_asset_input(
            job_id=job_id,
            log_path=log_path,
            source_availability=(
                validation.source_availability.value
            ),
            source_reasons=source_reasons,
            repository_urls=repository_urls,
            source_archive_urls=source_archive_urls,
            patch_urls=patch_urls,
        )
        return

    if (
        validation.source_availability
        != SourceAvailability.AVAILABLE
    ):
        pause_for_asset_input(
            job_id=job_id,
            log_path=log_path,
            source_availability=(
                validation.source_availability.value
            ),
            source_reasons=source_reasons,
            repository_urls=repository_urls,
            source_archive_urls=source_archive_urls,
            patch_urls=patch_urls,
        )
        return

    if (
        not validation.valid
        or bool(missing_fields)
    ):
        pause_for_manual_input(
            job_id=job_id,
            log_path=log_path,
            missing_fields=missing_fields,
        )
        return

    execute_cve_genie(
        job_id=job_id,
        json_path=json_path,
        log_path=log_path,
    )


def assess_asset_job(
    job_id: str,
) -> None:
    """
    Run the source-unavailable asset-context assessment.

    Flow:
    1. Read extracted CVE JSON.
    2. Reuse A2A claims already stored for the job.
    3. Build the CVE semantic prerequisite profile.
    4. Normalize and fuse A2A claims with operator asset input.
    5. Estimate likely_affected, likely_not_affected, or
       under_investigation.
    6. Persist assessment results and provenance references.
    """

    job = repository.get(job_id)
    log_path = Path(job.log_path or "")
    json_path = Path(job.input_json_path or "")

    try:
        if not job.asset_input:
            raise ValueError(
                "Asset operational information is empty."
            )

        repository.update(
            job_id,
            status="assessing_asset",
            stage="semantic_profile",
            message=(
                "Building a semantic CVE prerequisite profile."
            ),
            analysis_mode="asset_context_assessment",
            base_vex_status="under_investigation",
            asset_assessment_status="assessing",
            reproduction_status="not_attempted",
            exploitable=None,
            verifier_passed=None,
            exit_code=None,
            finished_at=None,
        )

        append_log(
            log_path,
            "[asset_assessment] started",
        )

        cve_data = read_input_json(json_path)
        exchanged_claims = _load_existing_claims(job_id)

        append_log(
            log_path,
            "[semantic_profile] "
            f"input_claims={len(exchanged_claims)}",
        )

        semantic_profile = build_semantic_profile(
            cve_data,
            expected_cve_id=job.cve_id,
            exchanged_claims=exchanged_claims,
        )

        repository.save_semantic_profile(
            job_id,
            semantic_profile,
        )

        conditions = semantic_profile.get(
            "conditions",
            [],
        )

        append_log(
            log_path,
            "[semantic_profile] "
            f"conditions={len(conditions)} "
            f"confidence={semantic_profile.get('confidence', 0.0)}",
        )

        repository.update(
            job_id,
            stage="evidence_fusion",
            message=(
                "Fusing A2A semantic evidence with asset context."
            ),
        )

        fused_evidence = fuse_evidence(
            exchanged_claims,
            asset_input=job.asset_input,
        )

        normalized_claims = fused_evidence.get(
            "claims",
            [],
        )

        repository.save_evidence_claims(
            job_id,
            normalized_claims,
        )

        append_log(
            log_path,
            "[evidence_fusion] "
            f"claims={len(normalized_claims)} "
            f"facts={len(fused_evidence.get('facts', []))} "
            f"conflicts={len(fused_evidence.get('conflicted_fact_ids', []))}",
        )

        repository.update(
            job_id,
            stage="likelihood_assessment",
            message=(
                "Comparing exploitation prerequisites "
                "with asset operational evidence."
            ),
        )

        assessment = assess_likelihood(
            semantic_profile,
            fused_evidence,
        )

        likelihood_status = str(
            assessment.get(
                "likelihood_status",
                "under_investigation",
            )
        )

        confidence = float(
            assessment.get(
                "confidence",
                0.0,
            )
        )

        score = float(
            assessment.get(
                "score",
                0.5,
            )
        )

        reasons = [
            str(reason)
            for reason in assessment.get(
                "reasons",
                [],
            )
        ]

        recommendation = assessment.get(
            "recommendation"
        )

        if recommendation:
            reasons.append(
                f"Recommendation: {recommendation}"
            )

        repository.save_asset_assessment(
            job_id,
            likelihood_status=likelihood_status,
            confidence=confidence,
            reasons=reasons,
            matched_conditions=list(
                assessment.get(
                    "matched_conditions",
                    [],
                )
            ),
            unmatched_conditions=list(
                assessment.get(
                    "unmatched_conditions",
                    [],
                )
            ),
            unknown_conditions=list(
                assessment.get(
                    "unknown_conditions",
                    [],
                )
            ),
            supporting_claim_ids=[
                str(item)
                for item in assessment.get(
                    "supporting_claim_ids",
                    [],
                )
            ],
            contradicting_claim_ids=[
                str(item)
                for item in assessment.get(
                    "contradicting_claim_ids",
                    [],
                )
            ],
            base_vex_status="under_investigation",
        )

        final_reason = (
            "Asset-context likelihood assessment completed. "
            f"Likelihood: {likelihood_status}. "
            f"Confidence: {confidence:.2f}. "
            f"Score: {score:.2f}. "
            "The base VEX state remains under_investigation."
        )

        repository.update(
            job_id,
            status="succeeded",
            stage="asset_assessment_completed",
            message=final_reason,
            asset_assessment_status="assessed",
            asset_impact_status=likelihood_status,
            base_vex_status="under_investigation",
            likelihood_status=likelihood_status,
            reproduction_status="not_attempted",
            exploitable=None,
            verifier_passed=None,
            final_reason=final_reason,
            missing_fields=[],
            exit_code=0,
            finished_at=utc_now_iso(),
        )

        append_log(
            log_path,
            "[likelihood_assessment] "
            f"status={likelihood_status} "
            f"confidence={confidence:.2f} "
            f"score={score:.2f}",
        )

        append_log(
            log_path,
            "[asset_assessment] completed",
        )

    except Exception as exc:
        append_log(
            log_path,
            traceback.format_exc(),
        )

        repository.update(
            job_id,
            status="failed",
            stage="asset_assessment_error",
            message=(
                f"Asset assessment failed: {exc}"
            ),
            asset_assessment_status="insufficient",
            base_vex_status="under_investigation",
            reproduction_status="not_attempted",
            exploitable=None,
            verifier_passed=None,
            final_reason=(
                "The asset-context assessment failed. "
                f"Reason: {exc}"
            ),
            exit_code=None,
            finished_at=utc_now_iso(),
        )


def run_job(
    job_id: str,
) -> None:
    job = repository.get(
        job_id
    )

    log_path = Path(
        job.log_path or ""
    )

    json_path = Path(
        job.input_json_path or ""
    )

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

        append_log(
            log_path,
            f"[job] Starting CVE extraction for "
            f"{job.cve_id}",
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
                        "[warning] Extraction returned "
                        "a non-zero exit code, but an "
                        "input JSON file was created. "
                        "The partial input will be validated."
                    ),
                )

                validate_and_run(job_id)
                return

            repository.update(
                job_id,
                status="failed",
                stage="extracting",
                message=(
                    "CVE data extraction failed and "
                    "no input JSON was produced. "
                    f"Exit code: {extraction_code}"
                ),
                missing_fields=[],
                reproduction_status="unknown",
                exploitable=None,
                verifier_passed=None,
                final_reason=None,
                exit_code=extraction_code,
                finished_at=utc_now_iso(),
            )
            return

        validate_and_run(job_id)

    except Exception as exc:
        append_log(
            log_path,
            traceback.format_exc(),
        )

        repository.update(
            job_id,
            status="failed",
            stage="internal_error",
            message=(
                f"Internal worker error: {exc}"
            ),
            reproduction_status="unknown",
            exploitable=None,
            verifier_passed=None,
            final_reason=None,
            finished_at=utc_now_iso(),
        )


def resume_job(
    job_id: str,
) -> None:
    job = repository.get(
        job_id
    )

    if job.status == "needs_asset_input":
        raise ValueError(
            "This job requires asset operational information. "
            "Use the asset-input assessment endpoint instead "
            "of the CVE reproduction resume endpoint."
        )

    resumable_statuses = {
        "needs_input",
        "failed",
        "unsupported",
    }

    if job.status not in resumable_statuses:
        raise ValueError(
            "Only needs_input, failed, or unsupported "
            "jobs can be resumed."
        )

    repository.update(
        job_id,
        status="queued",
        stage="queued",
        message=(
            "Job queued after reproduction input update."
        ),
        exit_code=None,
        finished_at=None,
        missing_fields=[],
        reproduction_status="unknown",
        exploitable=None,
        verifier_passed=None,
        final_reason=None,
    )

    append_log(
        Path(job.log_path or ""),
        "[resume] Revalidating the updated CVE input.",
    )

    validate_and_run(job_id)
