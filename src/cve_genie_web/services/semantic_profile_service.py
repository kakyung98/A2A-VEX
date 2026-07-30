from __future__ import annotations

from dataclasses import asdict, dataclass, field
import re
from typing import Any, Iterable, Mapping
from uuid import uuid4


_BOOL_TRUE = {
    "true", "yes", "required", "enabled", "needed",
}
_BOOL_FALSE = {
    "false", "no", "not_required", "disabled",
}

_PROTOCOL_PORTS = {
    "http": 80,
    "https": 443,
    "ftp": 21,
    "ssh": 22,
    "smtp": 25,
    "dns": 53,
    "telnet": 23,
    "snmp": 161,
    "modbus": 502,
    "mqtt": 1883,
    "coap": 5683,
}

_NETWORK_TERMS = {
    "remote",
    "network",
    "internet",
    "tcp",
    "udp",
    "http",
    "https",
    "socket",
    "request",
    "endpoint",
    "server",
    "client",
}

_LOCAL_TERMS = {
    "local attacker",
    "local user",
    "local privilege",
    "physical access",
}

_AUTH_REQUIRED_TERMS = {
    "authenticated attacker",
    "authenticated user",
    "after authentication",
    "requires authentication",
    "logged-in user",
    "logged in user",
}

_AUTH_NOT_REQUIRED_TERMS = {
    "unauthenticated attacker",
    "unauthenticated user",
    "without authentication",
    "pre-authentication",
    "pre authentication",
    "no authentication",
}

_USER_INTERACTION_TERMS = {
    "user interaction",
    "victim opens",
    "victim visits",
    "crafted file",
    "malicious file",
    "social engineering",
}

_PRIVILEGED_TERMS = {
    "administrator",
    "administrative privileges",
    "root privileges",
    "privileged user",
    "high privileges",
}

_NO_PRIVILEGE_TERMS = {
    "no privileges",
    "without privileges",
    "unprivileged attacker",
}

_FEATURE_PATTERNS = (
    re.compile(
        r"\bwhen\s+(?P<feature>[a-z0-9 _./-]{3,80}?)\s+is\s+enabled\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\brequires?\s+(?:the\s+)?(?P<feature>[a-z0-9 _./-]{3,80}?)\s+feature\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\bvia\s+(?:the\s+)?(?P<feature>[a-z0-9 _./-]{3,80}?)\s+(?:feature|functionality|interface|endpoint)\b",
        re.IGNORECASE,
    ),
)

_SERVICE_PATTERNS = (
    re.compile(
        r"\b(?P<service>[a-z0-9_.-]+)\s+(?:service|daemon|server)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(?:management|admin(?:istrative)?)\s+"
        r"(?P<service>http|https|web)\s+interface\b",
        re.IGNORECASE,
    ),
)

_PORT_PATTERN = re.compile(
    r"\bport\s+(?P<port>[0-9]{1,5})\b",
    re.IGNORECASE,
)


@dataclass
class SemanticCondition:
    condition_id: str
    predicate: str
    expected_value: Any
    importance: str = "required"
    weight: float = 1.0
    confidence: float = 0.5
    source_claim_ids: list[str] = field(default_factory=list)
    source_references: list[str] = field(default_factory=list)
    explanation: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class SemanticProfile:
    cve_id: str
    attack_vector: str = "unknown"
    required_protocols: list[str] = field(default_factory=list)
    required_ports: list[int] = field(default_factory=list)
    required_services: list[str] = field(default_factory=list)
    required_features: list[str] = field(default_factory=list)
    authentication_required: bool | None = None
    required_privileges: str = "unknown"
    user_interaction_required: bool | None = None
    remote_reachability_required: bool | None = None
    vulnerability_mechanisms: list[str] = field(default_factory=list)
    impacts: list[str] = field(default_factory=list)
    conditions: list[SemanticCondition] = field(default_factory=list)
    source_claim_ids: list[str] = field(default_factory=list)
    source_references: list[str] = field(default_factory=list)
    confidence: float = 0.0
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["conditions"] = [
            condition.to_dict()
            for condition in self.conditions
        ]
        return result


def _walk(value: Any) -> Iterable[tuple[str, Any]]:
    if isinstance(value, Mapping):
        for key, child in value.items():
            normalized_key = str(key).strip().lower()
            yield normalized_key, child
            yield from _walk(child)

    elif isinstance(value, list):
        for child in value:
            yield from _walk(child)


def _iter_strings(value: Any) -> Iterable[str]:
    if isinstance(value, str):
        cleaned = value.strip()
        if cleaned:
            yield cleaned

    elif isinstance(value, Mapping):
        for child in value.values():
            yield from _iter_strings(child)

    elif isinstance(value, list):
        for child in value:
            yield from _iter_strings(child)


def _normalize_token(value: str) -> str:
    return re.sub(
        r"[^a-z0-9_.:/+-]+",
        "_",
        value.strip().lower(),
    ).strip("_")


def _unique_strings(values: Iterable[str]) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()

    for value in values:
        normalized = value.strip()

        if not normalized:
            continue

        marker = normalized.lower()

        if marker in seen:
            continue

        seen.add(marker)
        result.append(normalized)

    return result


def _unique_ints(values: Iterable[int]) -> list[int]:
    result: list[int] = []

    for value in values:
        if value not in result:
            result.append(value)

    return result


def _contains_any(
    text: str,
    terms: set[str],
) -> bool:
    lowered = text.lower()
    return any(term in lowered for term in terms)


def _extract_cve_id(
    data: Mapping[str, Any],
    expected_cve_id: str | None,
) -> str:
    if expected_cve_id:
        return expected_cve_id.upper()

    for key, value in _walk(data):
        if key in {
            "cve_id",
            "cveid",
            "id",
        } and isinstance(value, str):
            match = re.search(
                r"CVE-[0-9]{4}-[0-9]{4,}",
                value,
                re.IGNORECASE,
            )
            if match:
                return match.group(0).upper()

    for key in data:
        match = re.fullmatch(
            r"CVE-[0-9]{4}-[0-9]{4,}",
            str(key),
            re.IGNORECASE,
        )
        if match:
            return match.group(0).upper()

    return "UNKNOWN-CVE"


def _extract_description_text(
    data: Mapping[str, Any],
) -> str:
    preferred_keys = {
        "description",
        "descriptions",
        "summary",
        "details",
        "problemtype",
        "problem_description",
        "vulnerability_description",
    }

    values: list[str] = []

    for key, value in _walk(data):
        if key in preferred_keys:
            values.extend(_iter_strings(value))

    if not values:
        values.extend(_iter_strings(data))

    return "\n".join(_unique_strings(values))


def _claim_value(
    claim: Mapping[str, Any],
) -> Any:
    if "value" in claim:
        return claim["value"]

    if "expected_value" in claim:
        return claim["expected_value"]

    if "result" in claim:
        return claim["result"]

    return None


def _claim_confidence(
    claim: Mapping[str, Any],
) -> float:
    try:
        value = float(claim.get("confidence", 0.5))
    except (TypeError, ValueError):
        return 0.5

    return max(0.0, min(1.0, value))


def _claim_id(
    claim: Mapping[str, Any],
) -> str:
    value = claim.get("claim_id")

    if value:
        return str(value)

    return f"claim-{uuid4()}"


def _claim_reference(
    claim: Mapping[str, Any],
) -> str | None:
    for key in (
        "source_reference",
        "reference",
        "artifact_id",
        "source",
    ):
        value = claim.get(key)
        if value:
            return str(value)

    return None


def _parse_bool(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value

    if isinstance(value, str):
        normalized = _normalize_token(value)

        if normalized in _BOOL_TRUE:
            return True

        if normalized in _BOOL_FALSE:
            return False

    return None


def _condition(
    *,
    predicate: str,
    expected_value: Any,
    importance: str = "required",
    weight: float = 1.0,
    confidence: float = 0.5,
    claim_ids: list[str] | None = None,
    references: list[str] | None = None,
    explanation: str | None = None,
) -> SemanticCondition:
    token = _normalize_token(
        f"{predicate}:{expected_value}"
    )

    return SemanticCondition(
        condition_id=f"condition-{token}",
        predicate=predicate,
        expected_value=expected_value,
        importance=importance,
        weight=weight,
        confidence=max(
            0.0,
            min(1.0, confidence),
        ),
        source_claim_ids=claim_ids or [],
        source_references=references or [],
        explanation=explanation,
    )


def _merge_conditions(
    conditions: Iterable[SemanticCondition],
) -> list[SemanticCondition]:
    merged: dict[
        tuple[str, str],
        SemanticCondition,
    ] = {}

    for condition in conditions:
        key = (
            condition.predicate,
            repr(condition.expected_value),
        )

        existing = merged.get(key)

        if existing is None:
            merged[key] = condition
            continue

        existing.confidence = max(
            existing.confidence,
            condition.confidence,
        )
        existing.weight = max(
            existing.weight,
            condition.weight,
        )
        existing.source_claim_ids = _unique_strings(
            existing.source_claim_ids
            + condition.source_claim_ids
        )
        existing.source_references = _unique_strings(
            existing.source_references
            + condition.source_references
        )

        if (
            existing.importance != "required"
            and condition.importance == "required"
        ):
            existing.importance = "required"

        if not existing.explanation:
            existing.explanation = condition.explanation

    return list(merged.values())


def _profile_from_text(
    cve_id: str,
    text: str,
) -> SemanticProfile:
    lowered = text.lower()

    attack_vector = "unknown"

    if _contains_any(lowered, _LOCAL_TERMS):
        attack_vector = "local"
    elif _contains_any(lowered, _NETWORK_TERMS):
        attack_vector = "network"

    authentication_required: bool | None = None

    if _contains_any(
        lowered,
        _AUTH_NOT_REQUIRED_TERMS,
    ):
        authentication_required = False
    elif _contains_any(
        lowered,
        _AUTH_REQUIRED_TERMS,
    ):
        authentication_required = True

    user_interaction_required: bool | None = None

    if _contains_any(
        lowered,
        _USER_INTERACTION_TERMS,
    ):
        user_interaction_required = True
    elif "no user interaction" in lowered:
        user_interaction_required = False

    required_privileges = "unknown"

    if _contains_any(
        lowered,
        _NO_PRIVILEGE_TERMS,
    ):
        required_privileges = "none"
    elif _contains_any(
        lowered,
        _PRIVILEGED_TERMS,
    ):
        required_privileges = "high"

    remote_reachability_required: bool | None = None

    if attack_vector == "network":
        remote_reachability_required = True
    elif attack_vector == "local":
        remote_reachability_required = False

    protocols = [
        protocol
        for protocol in _PROTOCOL_PORTS
        if re.search(
            rf"\b{re.escape(protocol)}\b",
            lowered,
        )
    ]

    ports: list[int] = []

    for match in _PORT_PATTERN.finditer(text):
        port = int(match.group("port"))

        if 1 <= port <= 65535:
            ports.append(port)

    for protocol in protocols:
        ports.append(_PROTOCOL_PORTS[protocol])

    services: list[str] = []

    for pattern in _SERVICE_PATTERNS:
        for match in pattern.finditer(text):
            services.append(
                _normalize_token(
                    match.group("service")
                )
            )

    features: list[str] = []

    for pattern in _FEATURE_PATTERNS:
        for match in pattern.finditer(text):
            features.append(
                _normalize_token(
                    match.group("feature")
                )
            )

    mechanisms: list[str] = []

    mechanism_terms = {
        "command_injection": (
            "command injection",
            "os command injection",
        ),
        "sql_injection": (
            "sql injection",
        ),
        "path_traversal": (
            "path traversal",
            "directory traversal",
        ),
        "buffer_overflow": (
            "buffer overflow",
            "out-of-bounds write",
            "out of bounds write",
        ),
        "use_after_free": (
            "use-after-free",
            "use after free",
        ),
        "deserialization": (
            "deserialization",
            "unsafe deserialization",
        ),
        "authentication_bypass": (
            "authentication bypass",
            "auth bypass",
        ),
        "code_execution": (
            "remote code execution",
            "arbitrary code execution",
        ),
        "information_disclosure": (
            "information disclosure",
            "information leak",
        ),
    }

    for mechanism, terms in mechanism_terms.items():
        if any(term in lowered for term in terms):
            mechanisms.append(mechanism)

    impacts: list[str] = []

    impact_terms = {
        "code_execution": (
            "code execution",
            "execute arbitrary code",
        ),
        "privilege_escalation": (
            "privilege escalation",
            "elevate privileges",
        ),
        "denial_of_service": (
            "denial of service",
            "crash",
        ),
        "information_disclosure": (
            "information disclosure",
            "sensitive information",
            "data exposure",
        ),
        "authentication_bypass": (
            "authentication bypass",
        ),
        "integrity_loss": (
            "modify data",
            "tamper",
            "arbitrary write",
        ),
    }

    for impact, terms in impact_terms.items():
        if any(term in lowered for term in terms):
            impacts.append(impact)

    conditions: list[SemanticCondition] = []

    if attack_vector == "network":
        conditions.append(
            _condition(
                predicate="remote_reachability",
                expected_value=True,
                weight=1.5,
                confidence=0.70,
                explanation=(
                    "The CVE description indicates "
                    "a network attack path."
                ),
            )
        )

    if authentication_required is not None:
        conditions.append(
            _condition(
                predicate="authentication_required",
                expected_value=authentication_required,
                weight=1.2,
                confidence=0.75,
                explanation=(
                    "Authentication behavior was inferred "
                    "from the vulnerability description."
                ),
            )
        )

    if user_interaction_required is not None:
        conditions.append(
            _condition(
                predicate="user_interaction_possible",
                expected_value=user_interaction_required,
                weight=1.0,
                confidence=0.65,
            )
        )

    for protocol in protocols:
        conditions.append(
            _condition(
                predicate="protocol_enabled",
                expected_value=protocol,
                weight=1.1,
                confidence=0.70,
            )
        )

    for port in _unique_ints(ports):
        conditions.append(
            _condition(
                predicate="listening_port",
                expected_value=port,
                importance="supporting",
                weight=0.6,
                confidence=0.55,
            )
        )

    for service in _unique_strings(services):
        conditions.append(
            _condition(
                predicate="service_running",
                expected_value=service,
                weight=1.3,
                confidence=0.65,
            )
        )

    for feature in _unique_strings(features):
        conditions.append(
            _condition(
                predicate="feature_enabled",
                expected_value=feature,
                weight=1.5,
                confidence=0.70,
            )
        )

    profile = SemanticProfile(
        cve_id=cve_id,
        attack_vector=attack_vector,
        required_protocols=_unique_strings(protocols),
        required_ports=_unique_ints(ports),
        required_services=_unique_strings(services),
        required_features=_unique_strings(features),
        authentication_required=authentication_required,
        required_privileges=required_privileges,
        user_interaction_required=user_interaction_required,
        remote_reachability_required=(
            remote_reachability_required
        ),
        vulnerability_mechanisms=_unique_strings(
            mechanisms
        ),
        impacts=_unique_strings(impacts),
        conditions=_merge_conditions(conditions),
        confidence=0.55 if text else 0.0,
    )

    return profile


def _apply_claims(
    profile: SemanticProfile,
    claims: Iterable[Mapping[str, Any]],
) -> SemanticProfile:
    conditions = list(profile.conditions)
    claim_confidences: list[float] = []

    for raw_claim in claims:
        predicate = _normalize_token(
            str(raw_claim.get("predicate") or "")
        )

        if not predicate:
            continue

        value = _claim_value(raw_claim)
        confidence = _claim_confidence(raw_claim)
        claim_id = _claim_id(raw_claim)
        reference = _claim_reference(raw_claim)
        references = [reference] if reference else []

        profile.source_claim_ids.append(claim_id)
        profile.source_references.extend(references)
        claim_confidences.append(confidence)

        if predicate in {
            "attack_vector",
            "requires_attack_vector",
        } and isinstance(value, str):
            profile.attack_vector = _normalize_token(value)

        elif predicate in {
            "requires_protocol",
            "required_protocol",
        }:
            values = (
                value
                if isinstance(value, list)
                else [value]
            )

            for item in values:
                if item is None:
                    continue

                protocol = _normalize_token(str(item))
                profile.required_protocols.append(protocol)
                conditions.append(
                    _condition(
                        predicate="protocol_enabled",
                        expected_value=protocol,
                        weight=1.2,
                        confidence=confidence,
                        claim_ids=[claim_id],
                        references=references,
                    )
                )

        elif predicate in {
            "requires_port",
            "required_port",
        }:
            values = (
                value
                if isinstance(value, list)
                else [value]
            )

            for item in values:
                try:
                    port = int(item)
                except (TypeError, ValueError):
                    continue

                if 1 <= port <= 65535:
                    profile.required_ports.append(port)
                    conditions.append(
                        _condition(
                            predicate="listening_port",
                            expected_value=port,
                            importance="supporting",
                            weight=0.7,
                            confidence=confidence,
                            claim_ids=[claim_id],
                            references=references,
                        )
                    )

        elif predicate in {
            "requires_service",
            "required_service",
        }:
            values = (
                value
                if isinstance(value, list)
                else [value]
            )

            for item in values:
                if item is None:
                    continue

                service = _normalize_token(str(item))
                profile.required_services.append(service)
                conditions.append(
                    _condition(
                        predicate="service_running",
                        expected_value=service,
                        weight=1.4,
                        confidence=confidence,
                        claim_ids=[claim_id],
                        references=references,
                    )
                )

        elif predicate in {
            "requires_feature",
            "required_feature",
        }:
            values = (
                value
                if isinstance(value, list)
                else [value]
            )

            for item in values:
                if item is None:
                    continue

                feature = _normalize_token(str(item))
                profile.required_features.append(feature)
                conditions.append(
                    _condition(
                        predicate="feature_enabled",
                        expected_value=feature,
                        weight=1.6,
                        confidence=confidence,
                        claim_ids=[claim_id],
                        references=references,
                    )
                )

        elif predicate in {
            "requires_authentication",
            "authentication_required",
        }:
            parsed = _parse_bool(value)

            if parsed is not None:
                profile.authentication_required = parsed
                conditions.append(
                    _condition(
                        predicate="authentication_required",
                        expected_value=parsed,
                        weight=1.2,
                        confidence=confidence,
                        claim_ids=[claim_id],
                        references=references,
                    )
                )

        elif predicate in {
            "requires_remote_reachability",
            "remote_reachability_required",
        }:
            parsed = _parse_bool(value)

            if parsed is not None:
                profile.remote_reachability_required = parsed
                conditions.append(
                    _condition(
                        predicate="remote_reachability",
                        expected_value=parsed,
                        weight=1.6,
                        confidence=confidence,
                        claim_ids=[claim_id],
                        references=references,
                    )
                )

        elif predicate in {
            "requires_user_interaction",
            "user_interaction_required",
        }:
            parsed = _parse_bool(value)

            if parsed is not None:
                profile.user_interaction_required = parsed
                conditions.append(
                    _condition(
                        predicate="user_interaction_possible",
                        expected_value=parsed,
                        weight=1.0,
                        confidence=confidence,
                        claim_ids=[claim_id],
                        references=references,
                    )
                )

        elif predicate in {
            "requires_privilege",
            "required_privilege",
        } and value is not None:
            profile.required_privileges = _normalize_token(
                str(value)
            )

        elif predicate in {
            "vulnerability_mechanism",
            "mechanism",
        }:
            values = (
                value
                if isinstance(value, list)
                else [value]
            )
            profile.vulnerability_mechanisms.extend(
                _normalize_token(str(item))
                for item in values
                if item is not None
            )

        elif predicate in {
            "impact",
            "security_impact",
        }:
            values = (
                value
                if isinstance(value, list)
                else [value]
            )
            profile.impacts.extend(
                _normalize_token(str(item))
                for item in values
                if item is not None
            )

    profile.required_protocols = _unique_strings(
        profile.required_protocols
    )
    profile.required_ports = _unique_ints(
        profile.required_ports
    )
    profile.required_services = _unique_strings(
        profile.required_services
    )
    profile.required_features = _unique_strings(
        profile.required_features
    )
    profile.vulnerability_mechanisms = _unique_strings(
        profile.vulnerability_mechanisms
    )
    profile.impacts = _unique_strings(profile.impacts)
    profile.source_claim_ids = _unique_strings(
        profile.source_claim_ids
    )
    profile.source_references = _unique_strings(
        profile.source_references
    )
    profile.conditions = _merge_conditions(conditions)

    if claim_confidences:
        average_claim_confidence = (
            sum(claim_confidences)
            / len(claim_confidences)
        )
        profile.confidence = max(
            profile.confidence,
            min(
                0.95,
                0.55
                + 0.35 * average_claim_confidence,
            ),
        )

    return profile


def build_semantic_profile(
    cve_data: Mapping[str, Any],
    *,
    expected_cve_id: str | None = None,
    exchanged_claims: Iterable[
        Mapping[str, Any]
    ] = (),
) -> dict[str, Any]:
    """
    Build a normalized exploitation-prerequisite profile.

    The function accepts partial CVE-Genie JSON and optional
    A2A claims produced by Data Processor, KnowledgeBuilder,
    PreReqBuilder, RepoBuilder, or other agents.

    It intentionally returns a dictionary so the result can
    be stored directly through JobRepository.save_semantic_profile().
    """

    cve_id = _extract_cve_id(
        cve_data,
        expected_cve_id,
    )

    text = _extract_description_text(cve_data)

    profile = _profile_from_text(
        cve_id,
        text,
    )

    profile = _apply_claims(
        profile,
        exchanged_claims,
    )

    if not profile.conditions:
        profile.notes.append(
            "No explicit exploitation prerequisites were "
            "extracted. The likelihood result should remain "
            "under_investigation."
        )

    if profile.attack_vector == "unknown":
        profile.notes.append(
            "Attack vector could not be inferred."
        )

    return profile.to_dict()
