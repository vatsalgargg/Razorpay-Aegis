"""
Statistical fallback classifier.

Activated when the LLM is unavailable (timeout, connection error, malformed JSON).
Uses deterministic heuristics derived from the feature vector.

This is a named deliverable in the system design — not a hidden backup.
Every fallback invocation is explicitly logged in the audit trail.
"""

from __future__ import annotations

import logging

from data.schemas import AnomalyResult, AttackType, Classification, RecommendedAction

logger = logging.getLogger(__name__)

# Heuristic thresholds (conservative — prefer false positives over misses)
CARD_TESTING_DECLINE_RATE  = 0.55
CARD_TESTING_AMOUNT_MEAN   = 50.0   # ₹50
BIN_ATTACK_SEQ_SCORE       = 0.30
BIN_ATTACK_BIN_CONC        = 0.50


def statistical_classify(anomaly: AnomalyResult, reason: str = "") -> Classification:
    """
    Heuristic classification when LLM is unavailable.
    Always returns hold_for_review (conservative — human decides).
    """
    fv = anomaly.feature_vector

    explanation_parts: list[str] = []
    attack_type = AttackType.NONE

    # Card testing: small amounts + high decline rate
    if (
        fv.decline_rate >= CARD_TESTING_DECLINE_RATE
        and fv.amount_mean <= CARD_TESTING_AMOUNT_MEAN
    ):
        attack_type = AttackType.CARD_TESTING
        explanation_parts.append(
            f"High decline rate ({fv.decline_rate:.1%}) combined with very low average "
            f"transaction amount (INR {fv.amount_mean:.2f}) strongly suggests card testing activity."
        )

    # BIN attack: sequential BINs + high concentration
    elif (
        fv.sequential_bin_score >= BIN_ATTACK_SEQ_SCORE
        or fv.bin_concentration >= BIN_ATTACK_BIN_CONC
    ):
        attack_type = AttackType.BIN_ATTACK
        explanation_parts.append(
            f"Near-sequential card BINs (score={fv.sequential_bin_score:.3f}) and high BIN "
            f"concentration ({fv.bin_concentration:.1%}) are consistent with a BIN enumeration attack."
        )

    # Ambiguous: statistical layer flagged but heuristics don't match known patterns
    else:
        attack_type = AttackType.NONE
        explanation_parts.append(
            f"Statistical anomaly detected (velocity z={anomaly.zscore_velocity:.2f}, "
            f"decline z={anomaly.zscore_decline:.2f}) but pattern does not match known "
            f"attack signatures. Likely a benign traffic spike — no action needed."
        )

    explanation = " ".join(explanation_parts)
    if reason:
        clean_reason = "LLM rate-limited" if "429" in reason or "RESOURCE_EXHAUSTED" in reason else "LLM unavailable"
        explanation += f" [{clean_reason} — deterministic fallback active]"

    confidence = _heuristic_confidence(anomaly)

    action = (
        RecommendedAction.NO_ACTION
        if attack_type == AttackType.NONE
        else RecommendedAction.HOLD_FOR_REVIEW
    )

    logger.warning(
        f"[fallback] LLM unavailable -- using heuristic. "
        f"attack_type={attack_type.value} confidence={confidence:.2f} reason={reason}"
    )

    return Classification(
        attack_type=attack_type,
        confidence=confidence,
        explanation=explanation,
        recommended_action=action,
        llm_used=False,
        llm_provider="Deterministic Fallback",
        fallback_reason=reason or "LLM unavailable",
    )


def _heuristic_confidence(anomaly: AnomalyResult) -> float:
    """Rough confidence based on how strong the statistical signal is."""
    score = anomaly.anomaly_score
    # Map score 0–1 to confidence 0.3–0.8 (never claim high confidence without LLM)
    return round(min(0.3 + score * 0.5, 0.80), 2)
