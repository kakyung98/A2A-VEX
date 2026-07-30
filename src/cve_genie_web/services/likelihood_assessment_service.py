from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Iterable, Mapping


@dataclass
class ConditionEvaluation:
    condition_id: str
    predicate: str
    expected_value: Any
    observed_value: Any
    result: str
    importance: str
    weight: float
    condition_confidence: float
    evidence_confidence: float
    score_contribution: float
    supporting_claim_ids: list[str] = field(
        default_factory=list
    )
    contradicting_claim_ids: list[str] = field(
        default_factory=list
    )
    explanation: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class LikelihoodAssessment:
    base_vex_status: str
    likelihood_status: str
    confidence: float
    score: float
    matched_conditions: list[dict[str, Any]]
    unmatched_conditions: list[dict[str, Any]]
    unknown_conditions: list[dict[str, Any]]
    conflicted_conditions: list[dict[str, Any]]
    supporting_claim_ids: list[str]
    contradicting_claim_ids: list[str]
    reasons: list[str]
    recommendation: str

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
        lowered = value.strip().lower()

        if lowered in {"true", "yes", "enabled"}:
            return True

        if lowered in {"false", "no", "disabled"}:
            return False

        return _normalize_token(value)

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


def _to_float(
    value: Any,
    default: float,
) -> float:
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        return default

    return max(0.0, min(1.0, parsed))


def _value_matches(
    expected: Any,
    observed: Any,
) -> bool | None:
    expected = _normalize_value(expected)
    observed = _normalize_value(observed)

    if observed is None:
        return None

    if isinstance(observed, list):
        if isinstance(expected, list):
            return all(
                item in observed
                for item in expected
            )

        return expected in observed

    if isinstance(expected, list):
        return observed in expected

    return observed == expected


def _fact_index(
    facts: Iterable[Mapping[str, Any]],
) -> dict[str, list[Mapping[str, Any]]]:
    index: dict[
        str,
        list[Mapping[str, Any]],
    ] = {}

    for fact in facts:
        predicate = _normalize_token(
            str(fact.get("predicate") or "")
        )

        if not predicate:
            continue

        index.setdefault(
            predicate,
            [],
        ).append(fact)

    return index


def _candidate_facts(
    predicate: str,
    index: Mapping[
        str,
        list[Mapping[str, Any]],
    ],
) -> list[Mapping[str, Any]]:
    aliases = {
        "remote_reachability": {
            "remote_reachability",
            "component_reachable",
            "network_reachable",
        },
        "protocol_enabled": {
            "protocol_enabled",
            "enabled_protocols",
            "protocol",
        },
        "listening_port": {
            "listening_port",
            "listening_ports",
        },
        "service_running": {
            "service_running",
            "running_service",
            "service_name",
        },
        "feature_enabled": {
            "feature_enabled",
            "enabled_features",
            "vulnerable_feature_enabled",
        },
        "authentication_required": {
            "authentication_required",
            "authentication_enforced",
        },
        "user_interaction_possible": {
            "user_interaction_possible",
            "user_interaction_required",
        },
    }

    predicates = aliases.get(
        predicate,
        {predicate},
    )

    result: list[Mapping[str, Any]] = []

    for candidate in predicates:
        result.extend(
            index.get(candidate, [])
        )

    return result


def _evaluate_condition(
    condition: Mapping[str, Any],
    fact_index: Mapping[
        str,
        list[Mapping[str, Any]],
    ],
) -> ConditionEvaluation:
    condition_id = str(
        condition.get("condition_id")
        or "condition-unknown"
    )

    predicate = _normalize_token(
        str(condition.get("predicate") or "")
    )

    expected = condition.get("expected_value")
    importance = str(
        condition.get("importance")
        or "required"
    )
    weight = float(
        condition.get("weight", 1.0)
    )
    condition_confidence = _to_float(
        condition.get("confidence"),
        0.5,
    )

    candidates = _candidate_facts(
        predicate,
        fact_index,
    )

    if not candidates:
        return ConditionEvaluation(
            condition_id=condition_id,
            predicate=predicate,
            expected_value=expected,
            observed_value=None,
            result="unknown",
            importance=importance,
            weight=weight,
            condition_confidence=(
                condition_confidence
            ),
            evidence_confidence=0.0,
            score_contribution=0.0,
            explanation=(
                "No asset or A2A evidence was available "
                "for this prerequisite."
            ),
        )

    candidates = sorted(
        candidates,
        key=lambda fact: float(
            fact.get("confidence", 0.0)
        ),
        reverse=True,
    )

    fact = candidates[0]
    observed = fact.get("value")
    evidence_confidence = _to_float(
        fact.get("confidence"),
        0.0,
    )

    if bool(fact.get("conflicted")):
        return ConditionEvaluation(
            condition_id=condition_id,
            predicate=predicate,
            expected_value=expected,
            observed_value=observed,
            result="conflicted",
            importance=importance,
            weight=weight,
            condition_confidence=(
                condition_confidence
            ),
            evidence_confidence=(
                evidence_confidence
            ),
            score_contribution=0.0,
            supporting_claim_ids=[
                str(item)
                for item in fact.get(
                    "supporting_claim_ids",
                    [],
                )
            ],
            contradicting_claim_ids=[
                str(item)
                for item in fact.get(
                    "contradicting_claim_ids",
                    [],
                )
            ],
            explanation=(
                "Strong incompatible evidence exists "
                "for this prerequisite."
            ),
        )

    matched = _value_matches(
        expected,
        observed,
    )

    if matched is None:
        result = "unknown"
        contribution = 0.0
    elif matched:
        result = "matched"
        contribution = (
            weight
            * condition_confidence
            * evidence_confidence
        )
    else:
        result = "unmatched"
        mismatch_factor = (
            1.35
            if importance == "required"
            else 0.75
        )
        contribution = -(
            weight
            * mismatch_factor
            * condition_confidence
            * evidence_confidence
        )

    return ConditionEvaluation(
        condition_id=condition_id,
        predicate=predicate,
        expected_value=expected,
        observed_value=observed,
        result=result,
        importance=importance,
        weight=weight,
        condition_confidence=(
            condition_confidence
        ),
        evidence_confidence=evidence_confidence,
        score_contribution=contribution,
        supporting_claim_ids=[
            str(item)
            for item in fact.get(
                "supporting_claim_ids",
                [],
            )
        ],
        contradicting_claim_ids=[
            str(item)
            for item in fact.get(
                "contradicting_claim_ids",
                [],
            )
        ],
        explanation=(
            "Observed asset evidence matches "
            "the CVE prerequisite."
            if result == "matched"
            else (
                "Observed asset evidence does not match "
                "the CVE prerequisite."
                if result == "unmatched"
                else (
                    "The prerequisite could not be "
                    "evaluated."
                )
            )
        ),
    )


def assess_likelihood(
    semantic_profile: Mapping[str, Any],
    fused_evidence: Mapping[str, Any],
    *,
    likely_affected_threshold: float = 0.65,
    likely_not_affected_threshold: float = 0.35,
    minimum_coverage: float = 0.40,
) -> dict[str, Any]:
    """
    Estimate asset impact likelihood.

    The returned base_vex_status always remains
    under_investigation. likelihood_status is advisory and
    does not become a final VEX assertion.
    """

    conditions = semantic_profile.get(
        "conditions",
        [],
    )

    if not isinstance(conditions, list):
        conditions = []

    facts = fused_evidence.get(
        "facts",
        [],
    )

    if not isinstance(facts, list):
        facts = []

    index = _fact_index(facts)

    evaluations = [
        _evaluate_condition(
            condition,
            index,
        )
        for condition in conditions
        if isinstance(condition, Mapping)
    ]

    matched = [
        evaluation
        for evaluation in evaluations
        if evaluation.result == "matched"
    ]

    unmatched = [
        evaluation
        for evaluation in evaluations
        if evaluation.result == "unmatched"
    ]

    unknown = [
        evaluation
        for evaluation in evaluations
        if evaluation.result == "unknown"
    ]

    conflicted = [
        evaluation
        for evaluation in evaluations
        if evaluation.result == "conflicted"
    ]

    required = [
        evaluation
        for evaluation in evaluations
        if evaluation.importance == "required"
    ]

    known_required = [
        evaluation
        for evaluation in required
        if evaluation.result in {
            "matched",
            "unmatched",
        }
    ]

    coverage = (
        len(known_required) / len(required)
        if required
        else 0.0
    )

    positive_capacity = sum(
        max(
            0.0,
            evaluation.weight
            * evaluation.condition_confidence
            * max(
                evaluation.evidence_confidence,
                0.5,
            ),
        )
        for evaluation in evaluations
    )

    raw_score = sum(
        evaluation.score_contribution
        for evaluation in evaluations
    )

    normalized_score = (
        0.5
        if positive_capacity <= 0
        else max(
            0.0,
            min(
                1.0,
                0.5
                + raw_score
                / (2.0 * positive_capacity),
            ),
        )
    )

    strong_required_mismatch = any(
        evaluation.importance == "required"
        and evaluation.result == "unmatched"
        and evaluation.evidence_confidence >= 0.70
        and evaluation.condition_confidence >= 0.60
        for evaluation in evaluations
    )

    all_known_required_matched = bool(
        known_required
    ) and all(
        evaluation.result == "matched"
        for evaluation in known_required
    )

    reasons: list[str] = []

    if conflicted:
        likelihood_status = "under_investigation"
        reasons.append(
            "Conflicting A2A or asset evidence prevents "
            "a stable likelihood estimate."
        )

    elif coverage < minimum_coverage:
        likelihood_status = "under_investigation"
        reasons.append(
            "Too few required exploitation prerequisites "
            "could be evaluated."
        )

    elif (
        strong_required_mismatch
        and normalized_score
        <= likely_not_affected_threshold
    ):
        likelihood_status = "likely_not_affected"
        reasons.append(
            "One or more important exploitation "
            "prerequisites are strongly inconsistent "
            "with the asset context."
        )

    elif (
        all_known_required_matched
        and normalized_score
        >= likely_affected_threshold
    ):
        likelihood_status = "likely_affected"
        reasons.append(
            "The evaluated exploitation prerequisites "
            "substantially match the asset context."
        )

    elif (
        normalized_score
        <= likely_not_affected_threshold
    ):
        likelihood_status = "likely_not_affected"
        reasons.append(
            "The overall prerequisite compatibility "
            "score is low."
        )

    elif (
        normalized_score
        >= likely_affected_threshold
    ):
        likelihood_status = "likely_affected"
        reasons.append(
            "The overall prerequisite compatibility "
            "score is high."
        )

    else:
        likelihood_status = "under_investigation"
        reasons.append(
            "The prerequisite compatibility score is "
            "not decisive."
        )

    reasons.append(
        f"Evaluated required-condition coverage: "
        f"{coverage:.2f}."
    )

    reasons.append(
        f"Normalized likelihood score: "
        f"{normalized_score:.2f}."
    )

    confidence = (
        min(
            0.95,
            (
                coverage
                * 0.55
                + float(
                    semantic_profile.get(
                        "confidence",
                        0.0,
                    )
                )
                * 0.25
                + (
                    1.0
                    - min(
                        1.0,
                        len(conflicted)
                        / max(
                            1,
                            len(evaluations),
                        ),
                    )
                )
                * 0.20
            ),
        )
        if evaluations
        else 0.0
    )

    supporting_claim_ids = sorted(
        {
            claim_id
            for evaluation in matched
            for claim_id in (
                evaluation.supporting_claim_ids
            )
        }
    )

    contradicting_claim_ids = sorted(
        {
            claim_id
            for evaluation in (
                unmatched + conflicted
            )
            for claim_id in (
                evaluation.supporting_claim_ids
                + evaluation.contradicting_claim_ids
            )
        }
    )

    if likelihood_status == "likely_affected":
        recommendation = (
            "Prioritize validation, compensating controls, "
            "and source or binary acquisition. The result "
            "is an estimate, not confirmed exploitation."
        )
    elif (
        likelihood_status
        == "likely_not_affected"
    ):
        recommendation = (
            "Preserve the unmet-prerequisite evidence and "
            "seek independent operational verification. "
            "Do not convert this estimate directly into "
            "a final not_affected VEX assertion."
        )
    else:
        recommendation = (
            "Collect additional prerequisite-specific "
            "asset evidence before making an impact claim."
        )

    assessment = LikelihoodAssessment(
        base_vex_status="under_investigation",
        likelihood_status=likelihood_status,
        confidence=max(
            0.0,
            min(1.0, confidence),
        ),
        score=normalized_score,
        matched_conditions=[
            item.to_dict()
            for item in matched
        ],
        unmatched_conditions=[
            item.to_dict()
            for item in unmatched
        ],
        unknown_conditions=[
            item.to_dict()
            for item in unknown
        ],
        conflicted_conditions=[
            item.to_dict()
            for item in conflicted
        ],
        supporting_claim_ids=(
            supporting_claim_ids
        ),
        contradicting_claim_ids=(
            contradicting_claim_ids
        ),
        reasons=reasons,
        recommendation=recommendation,
    )

    return assessment.to_dict()
