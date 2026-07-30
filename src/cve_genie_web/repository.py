from __future__ import annotations

import json
from typing import Any

from cve_genie_web.database import (
    db_session,
    utc_now_iso,
)
from cve_genie_web.models import Job


_JSON_FIELD_ALIASES = {
    "missing_fields": "missing_fields_json",
    "asset_input": "asset_input_json",
    "asset_assessment_reasons": (
        "asset_assessment_reasons_json"
    ),
    "semantic_profile": "semantic_profile_json",
    "evidence_claims": "evidence_claims_json",
    "matched_conditions": "matched_conditions_json",
    "unmatched_conditions": (
        "unmatched_conditions_json"
    ),
    "unknown_conditions": "unknown_conditions_json",
    "supporting_claim_ids": (
        "supporting_claim_ids_json"
    ),
    "contradicting_claim_ids": (
        "contradicting_claim_ids_json"
    ),
}


_ALLOWED_COLUMNS = {
    "cve_id",
    "status",
    "stage",
    "message",

    "input_json_path",
    "log_path",
    "result_path",
    "exit_code",

    "created_at",
    "updated_at",
    "started_at",
    "finished_at",

    "run_type",
    "missing_fields_json",

    "reproduction_status",
    "exploitable",
    "verifier_passed",
    "final_reason",

    "analysis_mode",
    "source_availability",

    "asset_input_json",
    "asset_assessment_status",
    "asset_impact_status",
    "asset_assessment_confidence",
    "asset_assessment_reasons_json",

    "semantic_profile_json",
    "evidence_claims_json",

    "matched_conditions_json",
    "unmatched_conditions_json",
    "unknown_conditions_json",

    "supporting_claim_ids_json",
    "contradicting_claim_ids_json",

    "base_vex_status",
    "likelihood_status",
}


class JobRepository:
    def create(
        self,
        *,
        job_id: str,
        cve_id: str,
        input_json_path: str,
        log_path: str,
        run_type: str,
    ) -> Job:
        now = utc_now_iso()

        with db_session() as connection:
            connection.execute(
                """
                INSERT INTO jobs (
                    job_id,
                    cve_id,
                    status,
                    stage,
                    message,

                    input_json_path,
                    log_path,
                    result_path,
                    exit_code,

                    created_at,
                    updated_at,
                    started_at,
                    finished_at,

                    run_type,
                    missing_fields_json,

                    reproduction_status,
                    exploitable,
                    verifier_passed,
                    final_reason,

                    analysis_mode,
                    source_availability,

                    asset_input_json,
                    asset_assessment_status,
                    asset_impact_status,
                    asset_assessment_confidence,
                    asset_assessment_reasons_json,

                    semantic_profile_json,
                    evidence_claims_json,

                    matched_conditions_json,
                    unmatched_conditions_json,
                    unknown_conditions_json,

                    supporting_claim_ids_json,
                    contradicting_claim_ids_json,

                    base_vex_status,
                    likelihood_status
                )
                VALUES (
                    ?, ?, ?, ?, ?,
                    ?, ?, ?, ?,
                    ?, ?, ?, ?,
                    ?, ?,
                    ?, ?, ?, ?,
                    ?, ?,
                    ?, ?, ?, ?, ?,
                    ?, ?,
                    ?, ?, ?,
                    ?, ?,
                    ?, ?
                )
                """,
                (
                    job_id,
                    cve_id,
                    "queued",
                    "queued",
                    "Job created",

                    input_json_path,
                    log_path,
                    None,
                    None,

                    now,
                    now,
                    None,
                    None,

                    run_type,
                    "[]",

                    "unknown",
                    None,
                    None,
                    None,

                    None,
                    None,

                    "{}",
                    None,
                    None,
                    None,
                    "[]",

                    "{}",
                    "[]",

                    "[]",
                    "[]",
                    "[]",

                    "[]",
                    "[]",

                    None,
                    None,
                ),
            )

        return self.get(job_id)

    def get(
        self,
        job_id: str,
    ) -> Job:
        with db_session() as connection:
            row = connection.execute(
                """
                SELECT *
                FROM jobs
                WHERE job_id = ?
                """,
                (job_id,),
            ).fetchone()

        if row is None:
            raise KeyError(job_id)

        return Job.from_row(row)

    def list(
        self,
        limit: int = 100,
    ) -> list[Job]:
        with db_session() as connection:
            rows = connection.execute(
                """
                SELECT *
                FROM jobs
                ORDER BY created_at DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()

        return [
            Job.from_row(row)
            for row in rows
        ]

    def update(
        self,
        job_id: str,
        **fields: Any,
    ) -> Job:
        if not fields:
            return self.get(job_id)

        normalized_fields = dict(fields)

        for public_name, storage_name in (
            _JSON_FIELD_ALIASES.items()
        ):
            if public_name not in normalized_fields:
                continue

            value = normalized_fields.pop(
                public_name
            )

            normalized_fields[storage_name] = (
                json.dumps(
                    value,
                    ensure_ascii=False,
                )
            )

        for boolean_field in (
            "exploitable",
            "verifier_passed",
        ):
            if boolean_field not in normalized_fields:
                continue

            value = normalized_fields[boolean_field]

            normalized_fields[boolean_field] = (
                None
                if value is None
                else int(bool(value))
            )

        if (
            "asset_assessment_confidence"
            in normalized_fields
        ):
            confidence = normalized_fields[
                "asset_assessment_confidence"
            ]

            if confidence is not None:
                confidence = float(confidence)

                if confidence < 0.0 or confidence > 1.0:
                    raise ValueError(
                        "asset_assessment_confidence "
                        "must be between 0.0 and 1.0"
                    )

                normalized_fields[
                    "asset_assessment_confidence"
                ] = confidence

        normalized_fields["updated_at"] = utc_now_iso()

        invalid = (
            set(normalized_fields)
            - _ALLOWED_COLUMNS
        )

        if invalid:
            raise ValueError(
                "Unsupported job fields: "
                f"{sorted(invalid)}"
            )

        columns = ", ".join(
            f"{name} = ?"
            for name in normalized_fields
        )

        values = (
            list(normalized_fields.values())
            + [job_id]
        )

        with db_session() as connection:
            cursor = connection.execute(
                f"""
                UPDATE jobs
                SET {columns}
                WHERE job_id = ?
                """,
                values,
            )

            if cursor.rowcount == 0:
                raise KeyError(job_id)

        return self.get(job_id)

    def save_asset_input(
        self,
        job_id: str,
        asset_input: dict[str, Any],
    ) -> Job:
        """
        Persist user-supplied asset operational context.
        """

        return self.update(
            job_id,
            asset_input=asset_input,
            asset_assessment_status="pending",
        )

    def save_semantic_profile(
        self,
        job_id: str,
        semantic_profile: dict[str, Any],
    ) -> Job:
        """
        Persist the normalized CVE semantic prerequisite profile.
        """

        return self.update(
            job_id,
            semantic_profile=semantic_profile,
        )

    def save_evidence_claims(
        self,
        job_id: str,
        evidence_claims: list[dict[str, Any]],
    ) -> Job:
        """
        Persist normalized A2A evidence claims.
        """

        return self.update(
            job_id,
            evidence_claims=evidence_claims,
        )

    def save_asset_assessment(
        self,
        job_id: str,
        *,
        likelihood_status: str,
        confidence: float,
        reasons: list[str],
        matched_conditions: list[Any],
        unmatched_conditions: list[Any],
        unknown_conditions: list[Any],
        supporting_claim_ids: list[str],
        contradicting_claim_ids: list[str],
        asset_impact_status: str | None = None,
        base_vex_status: str = "under_investigation",
    ) -> Job:
        """
        Persist the source-unavailable semantic likelihood result.

        The base VEX state remains under_investigation. The
        likelihood_status is an advisory estimate such as
        likely_affected or likely_not_affected.
        """

        return self.update(
            job_id,
            asset_assessment_status="assessed",
            asset_impact_status=(
                asset_impact_status
                or likelihood_status
            ),
            asset_assessment_confidence=confidence,
            asset_assessment_reasons=reasons,
            matched_conditions=matched_conditions,
            unmatched_conditions=unmatched_conditions,
            unknown_conditions=unknown_conditions,
            supporting_claim_ids=supporting_claim_ids,
            contradicting_claim_ids=(
                contradicting_claim_ids
            ),
            base_vex_status=base_vex_status,
            likelihood_status=likelihood_status,
        )
