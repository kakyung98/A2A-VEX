from __future__ import annotations

from dataclasses import asdict, dataclass, field
import json
from typing import Any, Iterable, Mapping
from uuid import uuid4


EVIDENCE_TYPE_WEIGHTS = {
    "binary_inventory": 1.00,
    "package_inventory": 0.95,
    "sbom": 0.90,
    "patch_inventory": 0.90,
    "service_configuration": 0.90,
    "service_status": 0.85,
    "process_list": 0.85,
    "network_scan": 0.80,
    "firewall_rule": 0.75,
    "route_analysis": 0.75,
    "security_advisory": 0.85,
    "vendor_statement": 0.80,
    "cve_record": 0.80,
    "builder_output": 0.80,
    "agent_inference": 0.65,
    "log": 0.70,
    "screenshot": 0.60,
    "operator_statement": 0.40,
    "other": 0.30,
}


@dataclass
class EvidenceClaim:
    claim_id: str
    context_id: str | None
    task_id: str | None
    agent_name: str
    skill_id: str | None
    subject: str
    predicate: str
    value: Any
    confidence: float
    evidence_type: str
    artifact_id: str | None = None
    source_reference: str | None = None
    supports: list[str] = field(default_factory=list)
    contradicts: list[str] = field(default_factory=list)
    notes: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class FusedFact:
    fact_id: str
    subject: str
    predicate: str
    value: Any
    confidence: float
    supporting_claim_ids: list[str]
    contradicting_claim_ids: list[str]
    evidence_types: list[str]
    agents: list[str]
    conflicted: bool
    alternatives: list[dict[str, Any]]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _normalize_token(value: str) -> str:
    return "_".join(
        token
        for token in value.strip().lower().replace("-", "_").split()
        if token
    )


def _normalize_value(value: Any) -> Any:
    if isinstance(value, str):
        cleaned = value.strip()

        lowered = cleaned.lower()

        if lowered in {"true", "yes", "enabled"}:
            return True

        if lowered in {"false", "no", "disabled"}:
            return False

        return _normalize_token(cleaned)

    if isinstance(value, list):
        return [
            _normalize_value(item)
            for item in value
        ]

    if isinstance(value, Mapping):
        return {
            str(key): _normalize_value(child)
            for key, child in value.items()
        }

    return value


def _canonical_value_key(value: Any) -> str:
    return json.dumps(
        _normalize_value(value),
        ensure_ascii=False,
        sort_keys=True,
    )


def _safe_confidence(value: Any) -> float:
    try:
        confidence = float(value)
    except (TypeError, ValueError):
        confidence = 0.5

    return max(0.0, min(1.0, confidence))


def _effective_confidence(
    claim: EvidenceClaim,
) -> float:
    weight = EVIDENCE_TYPE_WEIGHTS.get(
        claim.evidence_type,
        EVIDENCE_TYPE_WEIGHTS["other"],
    )

    return max(
        0.0,
        min(
            1.0,
            claim.confidence * weight,
        ),
    )


def _combine_support(
    confidences: Iterable[float],
) -> float:
    remaining = 1.0

    for confidence in confidences:
        remaining *= 1.0 - confidence

    return 1.0 - remaining


def normalize_claim(
    raw_claim: Mapping[str, Any],
    *,
    default_agent_name: str = "unknown_agent",
    default_evidence_type: str = "agent_inference",
) -> EvidenceClaim:
    claim_id = str(
        raw_claim.get("claim_id")
        or f"claim-{uuid4()}"
    )

    predicate = _normalize_token(
        str(raw_claim.get("predicate") or "")
    )

    if not predicate:
        raise ValueError(
            "Evidence claim predicate is required."
        )

    subject = str(
        raw_claim.get("subject")
        or "asset"
    ).strip()

    agent_name = str(
        raw_claim.get("agent_name")
        or default_agent_name
    ).strip()

    evidence_type = _normalize_token(
        str(
            raw_claim.get("evidence_type")
            or default_evidence_type
        )
    )

    value = raw_claim.get(
        "value",
        raw_claim.get(
            "expected_value",
            raw_claim.get("result"),
        ),
    )

    return EvidenceClaim(
        claim_id=claim_id,
        context_id=(
            str(raw_claim["context_id"])
            if raw_claim.get("context_id")
            else None
        ),
        task_id=(
            str(raw_claim["task_id"])
            if raw_claim.get("task_id")
            else None
        ),
        agent_name=agent_name,
        skill_id=(
            str(raw_claim["skill_id"])
            if raw_claim.get("skill_id")
            else None
        ),
        subject=subject,
        predicate=predicate,
        value=_normalize_value(value),
        confidence=_safe_confidence(
            raw_claim.get("confidence", 0.5)
        ),
        evidence_type=evidence_type,
        artifact_id=(
            str(raw_claim["artifact_id"])
            if raw_claim.get("artifact_id")
            else None
        ),
        source_reference=(
            str(raw_claim["source_reference"])
            if raw_claim.get("source_reference")
            else None
        ),
        supports=[
            str(item)
            for item in raw_claim.get("supports", [])
        ],
        contradicts=[
            str(item)
            for item in raw_claim.get(
                "contradicts",
                [],
            )
        ],
        notes=(
            str(raw_claim["notes"])
            if raw_claim.get("notes")
            else None
        ),
    )


def _operator_claims(
    asset_input: Mapping[str, Any],
    *,
    context_id: str | None = None,
    task_id: str | None = None,
) -> list[EvidenceClaim]:
    claims: list[EvidenceClaim] = []

    def add(
        predicate: str,
        value: Any,
        *,
        subject: str = "asset",
        confidence: float = 0.70,
    ) -> None:
        if value is None:
            return

        claims.append(
            EvidenceClaim(
                claim_id=f"operator-{uuid4()}",
                context_id=context_id,
                task_id=task_id,
                agent_name="Asset Context Agent",
                skill_id="cve.asset.context",
                subject=subject,
                predicate=predicate,
                value=_normalize_value(value),
                confidence=confidence,
                evidence_type="operator_statement",
            )
        )

    runtime = asset_input.get("runtime") or {}
    exposure = asset_input.get("exposure") or {}
    controls = (
        asset_input.get("security_controls") or {}
    )

    add(
        "service_running",
        runtime.get("service_running"),
    )
    add(
        "feature_enabled",
        runtime.get(
            "vulnerable_feature_enabled"
        ),
    )
    add(
        "component_loaded",
        runtime.get("component_loaded"),
    )
    add(
        "remote_reachability",
        runtime.get("component_reachable"),
    )
    add(
        "internet_exposed",
        exposure.get("internet_exposed"),
    )
    add(
        "authentication_required",
        exposure.get(
            "authentication_required"
        ),
    )
    add(
        "listening_ports",
        exposure.get("listening_ports", []),
    )
    add(
        "reachable_networks",
        exposure.get(
            "reachable_networks",
            [],
        ),
    )
    add(
        "firewall_enabled",
        controls.get("firewall_enabled"),
    )
    add(
        "network_segmentation",
        controls.get(
            "network_segmentation"
        ),
    )
    add(
        "ids_ips_enabled",
        controls.get("ids_ips_enabled"),
    )

    service_name = runtime.get("service_name")

    if service_name:
        add(
            "service_running",
            service_name,
            subject="asset_service",
            confidence=0.65,
        )

    return claims


def fuse_evidence(
    exchanged_claims: Iterable[
        Mapping[str, Any]
    ],
    *,
    asset_input: Mapping[str, Any] | None = None,
    context_id: str | None = None,
    task_id: str | None = None,
    conflict_threshold: float = 0.55,
) -> dict[str, Any]:
    """
    Normalize and fuse A2A claims by subject and predicate.

    The result keeps both the winning value and competing
    alternatives. A fact is marked conflicted when at least
    two incompatible values each receive substantial support.
    """

    claims = [
        normalize_claim(raw_claim)
        for raw_claim in exchanged_claims
    ]

    if asset_input:
        claims.extend(
            _operator_claims(
                asset_input,
                context_id=context_id,
                task_id=task_id,
            )
        )

    grouped: dict[
        tuple[str, str],
        list[EvidenceClaim],
    ] = {}

    for claim in claims:
        key = (
            claim.subject,
            claim.predicate,
        )
        grouped.setdefault(key, []).append(claim)

    fused_facts: list[FusedFact] = []

    for (
        subject,
        predicate,
    ), relevant_claims in grouped.items():
        value_groups: dict[
            str,
            list[EvidenceClaim],
        ] = {}

        for claim in relevant_claims:
            value_key = _canonical_value_key(
                claim.value
            )
            value_groups.setdefault(
                value_key,
                [],
            ).append(claim)

        alternatives: list[dict[str, Any]] = []

        for value_key, value_claims in (
            value_groups.items()
        ):
            support = _combine_support(
                _effective_confidence(claim)
                for claim in value_claims
            )

            alternatives.append(
                {
                    "value": value_claims[0].value,
                    "value_key": value_key,
                    "confidence": support,
                    "claim_ids": [
                        claim.claim_id
                        for claim in value_claims
                    ],
                    "evidence_types": sorted(
                        {
                            claim.evidence_type
                            for claim in value_claims
                        }
                    ),
                    "agents": sorted(
                        {
                            claim.agent_name
                            for claim in value_claims
                        }
                    ),
                }
            )

        alternatives.sort(
            key=lambda item: item["confidence"],
            reverse=True,
        )

        winner = alternatives[0]

        conflicting = [
            alternative
            for alternative in alternatives[1:]
            if (
                alternative["confidence"]
                >= conflict_threshold
                and winner["confidence"]
                >= conflict_threshold
            )
        ]

        supporting_claim_ids = list(
            winner["claim_ids"]
        )

        contradicting_claim_ids = [
            claim_id
            for alternative in alternatives[1:]
            for claim_id in alternative["claim_ids"]
        ]

        fused_facts.append(
            FusedFact(
                fact_id=(
                    f"fact-{_normalize_token(subject)}-"
                    f"{predicate}"
                ),
                subject=subject,
                predicate=predicate,
                value=winner["value"],
                confidence=winner["confidence"],
                supporting_claim_ids=(
                    supporting_claim_ids
                ),
                contradicting_claim_ids=(
                    contradicting_claim_ids
                ),
                evidence_types=list(
                    winner["evidence_types"]
                ),
                agents=list(winner["agents"]),
                conflicted=bool(conflicting),
                alternatives=alternatives,
            )
        )

    return {
        "claims": [
            claim.to_dict()
            for claim in claims
        ],
        "facts": [
            fact.to_dict()
            for fact in fused_facts
        ],
        "conflicted_fact_ids": [
            fact.fact_id
            for fact in fused_facts
            if fact.conflicted
        ],
        "supporting_claim_ids": [
            claim.claim_id
            for claim in claims
        ],
    }
