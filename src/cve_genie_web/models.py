from __future__ import annotations

from dataclasses import asdict, dataclass
import json
from typing import Any, Mapping


def _load_json_list(
    value: str | None,
) -> list[Any]:
    try:
        decoded = json.loads(value or "[]")
    except (json.JSONDecodeError, TypeError):
        return []

    return decoded if isinstance(decoded, list) else []


def _load_json_dict(
    value: str | None,
) -> dict[str, Any]:
    try:
        decoded = json.loads(value or "{}")
    except (json.JSONDecodeError, TypeError):
        return {}

    return decoded if isinstance(decoded, dict) else {}


@dataclass
class Job:
    job_id: str
    cve_id: str
    status: str
    stage: str
    message: str | None

    input_json_path: str | None
    log_path: str | None
    result_path: str | None
    exit_code: int | None

    created_at: str
    updated_at: str
    started_at: str | None
    finished_at: str | None

    run_type: str
    missing_fields_json: str

    reproduction_status: str
    exploitable: int | None
    verifier_passed: int | None
    final_reason: str | None

    analysis_mode: str | None
    source_availability: str | None

    asset_input_json: str
    asset_assessment_status: str | None
    asset_impact_status: str | None
    asset_assessment_confidence: float | None
    asset_assessment_reasons_json: str

    semantic_profile_json: str
    evidence_claims_json: str

    matched_conditions_json: str
    unmatched_conditions_json: str
    unknown_conditions_json: str

    supporting_claim_ids_json: str
    contradicting_claim_ids_json: str

    base_vex_status: str | None
    likelihood_status: str | None

    @classmethod
    def from_row(
        cls,
        row: Mapping[str, Any],
    ) -> "Job":
        values = dict(row)

        defaults: dict[str, Any] = {
            "run_type": "build,exploit,verify",
            "missing_fields_json": "[]",
            "reproduction_status": "unknown",
            "exploitable": None,
            "verifier_passed": None,
            "final_reason": None,

            "analysis_mode": None,
            "source_availability": None,

            "asset_input_json": "{}",
            "asset_assessment_status": None,
            "asset_impact_status": None,
            "asset_assessment_confidence": None,
            "asset_assessment_reasons_json": "[]",

            "semantic_profile_json": "{}",
            "evidence_claims_json": "[]",

            "matched_conditions_json": "[]",
            "unmatched_conditions_json": "[]",
            "unknown_conditions_json": "[]",

            "supporting_claim_ids_json": "[]",
            "contradicting_claim_ids_json": "[]",

            "base_vex_status": None,
            "likelihood_status": None,
        }

        for key, default_value in defaults.items():
            values.setdefault(key, default_value)

        return cls(**values)

    @property
    def missing_fields(self) -> list[str]:
        return [
            str(item)
            for item in _load_json_list(
                self.missing_fields_json
            )
        ]

    @property
    def asset_input(self) -> dict[str, Any]:
        return _load_json_dict(
            self.asset_input_json
        )

    @property
    def asset_assessment_reasons(self) -> list[str]:
        return [
            str(item)
            for item in _load_json_list(
                self.asset_assessment_reasons_json
            )
        ]

    @property
    def semantic_profile(self) -> dict[str, Any]:
        return _load_json_dict(
            self.semantic_profile_json
        )

    @property
    def evidence_claims(self) -> list[Any]:
        return _load_json_list(
            self.evidence_claims_json
        )

    @property
    def matched_conditions(self) -> list[Any]:
        return _load_json_list(
            self.matched_conditions_json
        )

    @property
    def unmatched_conditions(self) -> list[Any]:
        return _load_json_list(
            self.unmatched_conditions_json
        )

    @property
    def unknown_conditions(self) -> list[Any]:
        return _load_json_list(
            self.unknown_conditions_json
        )

    @property
    def supporting_claim_ids(self) -> list[str]:
        return [
            str(item)
            for item in _load_json_list(
                self.supporting_claim_ids_json
            )
        ]

    @property
    def contradicting_claim_ids(self) -> list[str]:
        return [
            str(item)
            for item in _load_json_list(
                self.contradicting_claim_ids_json
            )
        ]

    @staticmethod
    def _to_bool(
        value: int | None,
    ) -> bool | None:
        if value is None:
            return None

        return bool(value)

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)

        result["missing_fields"] = self.missing_fields
        result["exploitable"] = self._to_bool(
            self.exploitable
        )
        result["verifier_passed"] = self._to_bool(
            self.verifier_passed
        )

        result["asset_input"] = self.asset_input
        result[
            "asset_assessment_reasons"
        ] = self.asset_assessment_reasons

        result["semantic_profile"] = self.semantic_profile
        result["evidence_claims"] = self.evidence_claims

        result[
            "matched_conditions"
        ] = self.matched_conditions

        result[
            "unmatched_conditions"
        ] = self.unmatched_conditions

        result[
            "unknown_conditions"
        ] = self.unknown_conditions

        result[
            "supporting_claim_ids"
        ] = self.supporting_claim_ids

        result[
            "contradicting_claim_ids"
        ] = self.contradicting_claim_ids

        json_storage_fields = {
            "missing_fields_json",
            "asset_input_json",
            "asset_assessment_reasons_json",
            "semantic_profile_json",
            "evidence_claims_json",
            "matched_conditions_json",
            "unmatched_conditions_json",
            "unknown_conditions_json",
            "supporting_claim_ids_json",
            "contradicting_claim_ids_json",
        }

        for field_name in json_storage_fields:
            result.pop(field_name, None)

        return result
