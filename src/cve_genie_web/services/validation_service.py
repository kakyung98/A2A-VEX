from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable


@dataclass(frozen=True)
class ValidationResult:
    valid: bool
    missing_fields: list[str]
    unsupported_reasons: list[str]


def _walk(value: Any) -> Iterable[tuple[str, Any]]:
    if isinstance(value, dict):
        for key, child in value.items():
            normalized_key = str(key).strip().lower()
            yield normalized_key, child
            yield from _walk(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk(child)


def _has_nonempty_value(
    document: dict[str, Any],
    aliases: set[str],
) -> bool:
    for key, value in _walk(document):
        if key not in aliases:
            continue

        if isinstance(value, str) and value.strip():
            return True

        if isinstance(value, (list, dict)) and value:
            return True

        if value not in (None, "", [], {}):
            return True

    return False


def _contains_text(
    document: dict[str, Any],
    candidates: set[str],
) -> bool:
    for _, value in _walk(document):
        if not isinstance(value, str):
            continue

        normalized = value.lower()
        if any(candidate in normalized for candidate in candidates):
            return True

    return False


def validate_reproduction_input(
    document: dict[str, Any],
    *,
    expected_cve_id: str,
) -> ValidationResult:
    missing: list[str] = []
    unsupported: list[str] = []

    cve_aliases = {
        "cve",
        "cve_id",
        "cveid",
        "id",
        "vulnerability_id",
    }
    repository_aliases = {
        "repo",
        "repo_url",
        "repository",
        "repository_url",
        "source",
        "source_url",
        "source_code",
        "source_code_url",
        "github",
        "git_url",
    }
    version_aliases = {
        "version",
        "vulnerable_version",
        "affected_version",
        "versions",
        "tag",
        "commit",
        "commit_hash",
        "checkout",
        "ref",
    }
    description_aliases = {
        "description",
        "summary",
        "details",
        "problemtype",
        "vulnerability_description",
    }

    if not _has_nonempty_value(document, cve_aliases):
        # Some extracted formats use the CVE ID as a nested value under
        # an unknown key, so also search all string values.
        if not _contains_text(
            document,
            {expected_cve_id.lower()},
        ):
            missing.append("CVE identifier")

    if not _has_nonempty_value(document, repository_aliases):
        missing.append("Source repository URL")

    if not _has_nonempty_value(document, version_aliases):
        missing.append(
            "Vulnerable version, tag, commit, or checkout reference"
        )

    if not _has_nonempty_value(document, description_aliases):
        missing.append("Vulnerability description")

    if _contains_text(
        document,
        {
            "closed source",
            "proprietary software",
            "commercial product",
            "source code unavailable",
        },
    ):
        unsupported.append(
            "The extracted record appears to describe a closed-source "
            "or proprietary target"
        )

    return ValidationResult(
        valid=not missing and not unsupported,
        missing_fields=missing,
        unsupported_reasons=unsupported,
    )
