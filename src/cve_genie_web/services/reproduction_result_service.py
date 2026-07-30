from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path
import re
from typing import Any


@dataclass(frozen=True)
class ReproductionResult:
    reproduction_status: str
    exploitable: bool | None
    verifier_passed: bool | None
    final_reason: str | None


UNKNOWN_RESULT = ReproductionResult(
    reproduction_status="unknown",
    exploitable=None,
    verifier_passed=None,
    final_reason=None,
)


def _as_bool(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value

    if isinstance(value, int):
        return bool(value)

    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"true", "yes", "1", "passed", "success"}:
            return True
        if normalized in {"false", "no", "0", "failed", "failure"}:
            return False

    return None


def _extract_results_dict(log_text: str) -> dict[str, Any] | None:
    """
    Extract the final Python-style Results dictionary.

    CVE-Genie currently prints output similar to:

        Results: {'success': 'True', 'reason': '...'}
    """
    matches = list(
        re.finditer(
            r"Results\s*:\s*(\{[^\n]*\})",
            log_text,
            flags=re.IGNORECASE,
        )
    )

    for match in reversed(matches):
        candidate = match.group(1)
        try:
            parsed = ast.literal_eval(candidate)
        except (ValueError, SyntaxError):
            continue

        if isinstance(parsed, dict):
            return parsed

    return None


def _infer_from_text(log_text: str) -> ReproductionResult:
    normalized = log_text.lower()

    positive_markers = (
        "cve reproduced",
        "critic accepted the verifier",
        "ctf verifier done",
        "verifier passed",
    )
    negative_markers = (
        "cve not reproduced",
        "failed to reproduce",
        "verifier rejected",
        "verifier failed",
    )

    if any(marker in normalized for marker in positive_markers):
        return ReproductionResult(
            reproduction_status="confirmed",
            exploitable=True,
            verifier_passed=True,
            final_reason="CVE-Genie log indicates successful reproduction",
        )

    if any(marker in normalized for marker in negative_markers):
        return ReproductionResult(
            reproduction_status="not_reproduced",
            exploitable=False,
            verifier_passed=False,
            final_reason="CVE-Genie log indicates reproduction failure",
        )

    return UNKNOWN_RESULT


def parse_reproduction_result(log_path: Path) -> ReproductionResult:
    if not log_path.exists():
        return UNKNOWN_RESULT

    log_text = log_path.read_text(
        encoding="utf-8",
        errors="replace",
    )

    result_dict = _extract_results_dict(log_text)

    if result_dict is None:
        return _infer_from_text(log_text)

    success = _as_bool(result_dict.get("success"))
    reason_value = result_dict.get("reason")
    reason = (
        str(reason_value).strip()
        if reason_value is not None
        else None
    )

    if success is True:
        return ReproductionResult(
            reproduction_status="confirmed",
            exploitable=True,
            verifier_passed=True,
            final_reason=reason or "CVE reproduced",
        )

    if success is False:
        return ReproductionResult(
            reproduction_status="not_reproduced",
            exploitable=False,
            verifier_passed=False,
            final_reason=reason or "CVE was not reproduced",
        )

    return ReproductionResult(
        reproduction_status="inconclusive",
        exploitable=None,
        verifier_passed=None,
        final_reason=reason or "Final result did not contain a valid success flag",
    )
