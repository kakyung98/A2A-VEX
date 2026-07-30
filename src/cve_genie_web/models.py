from __future__ import annotations

from dataclasses import asdict, dataclass
import json
from typing import Any, Mapping


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

    @classmethod
    def from_row(cls, row: Mapping[str, Any]) -> "Job":
        values = dict(row)
        values.setdefault("run_type", "build,exploit,verify")
        values.setdefault("missing_fields_json", "[]")
        values.setdefault("reproduction_status", "unknown")
        values.setdefault("exploitable", None)
        values.setdefault("verifier_passed", None)
        values.setdefault("final_reason", None)
        return cls(**values)

    @property
    def missing_fields(self) -> list[str]:
        try:
            value = json.loads(self.missing_fields_json)
        except (json.JSONDecodeError, TypeError):
            return []
        return value if isinstance(value, list) else []

    @staticmethod
    def _to_bool(value: int | None) -> bool | None:
        if value is None:
            return None
        return bool(value)

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["missing_fields"] = self.missing_fields
        result["exploitable"] = self._to_bool(self.exploitable)
        result["verifier_passed"] = self._to_bool(self.verifier_passed)
        result.pop("missing_fields_json", None)
        return result
