"""
Tests for LLM fallback behavior.

Verifies that:
  1. When LLM raises LLMUnavailableError, the fallback classifier activates.
  2. The fallback correctly identifies card_testing and bin_attack patterns.
  3. Fallback always returns hold_for_review (conservative).
  4. Fallback result is logged in audit trail (llm_used=False, fallback_used=True).
"""

from __future__ import annotations

import sys
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from data.schemas import AnomalyResult, AttackType, Classification, FeatureVector, RecommendedAction
from reasoning.fallback import statistical_classify
from reasoning.llm_client import LLMUnavailableError


BASE_TIME = datetime(2024, 1, 1, 12, 0, 0)


def _make_anomaly(
    txn_velocity: float = 50.0,
    decline_rate: float = 0.75,
    amount_mean: float = 5.0,
    amount_std: float = 2.0,
    bin_concentration: float = 1.0,
    sequential_bin_score: float = 0.05,
    is_attack: bool = True,
    attack_type: AttackType = AttackType.CARD_TESTING,
) -> AnomalyResult:
    t = BASE_TIME
    fv = FeatureVector(
        window_start=t,
        window_end=t + timedelta(minutes=5),
        txn_count=35,
        txn_velocity=txn_velocity,
        decline_rate=decline_rate,
        amount_mean=amount_mean,
        amount_std=amount_std,
        amount_max=10.0,
        unique_cards=33,
        unique_ips=1,
        bin_concentration=bin_concentration,
        sequential_bin_score=sequential_bin_score,
        is_attack=is_attack,
        attack_type=attack_type,
    )
    return AnomalyResult(
        window_start=t,
        window_end=t + timedelta(minutes=5),
        is_anomaly=True,
        anomaly_score=0.75,
        zscore_velocity=8.0,
        zscore_decline=9.0,
        triggered_features=["velocity_zscore=8.00", "decline_zscore=9.00"],
        feature_vector=fv,
    )


# ---------------------------------------------------------------------------
# Fallback classifier tests
# ---------------------------------------------------------------------------

def test_fallback_classifies_card_testing():
    anomaly = _make_anomaly(
        decline_rate=0.80,
        amount_mean=5.0,
        attack_type=AttackType.CARD_TESTING,
    )
    result = statistical_classify(anomaly, reason="LLM timeout")
    assert result.attack_type == AttackType.CARD_TESTING
    assert result.llm_used is False
    assert result.fallback_reason is not None


def test_fallback_classifies_bin_attack():
    anomaly = _make_anomaly(
        decline_rate=0.60,
        amount_mean=800.0,
        bin_concentration=0.90,
        sequential_bin_score=0.95,
        attack_type=AttackType.BIN_ATTACK,
    )
    result = statistical_classify(anomaly, reason="connection error")
    assert result.attack_type == AttackType.BIN_ATTACK
    assert result.llm_used is False


def test_fallback_always_hold_for_review():
    """Fallback must always recommend hold_for_review — never auto-flag or no_action."""
    for decline, amount, seq in [
        (0.80, 5.0, 0.05),    # card testing
        (0.60, 800.0, 0.95),  # bin attack
        (0.10, 2000.0, 0.01), # ambiguous
    ]:
        anomaly = _make_anomaly(decline_rate=decline, amount_mean=amount, sequential_bin_score=seq)
        result = statistical_classify(anomaly)
        assert result.recommended_action == RecommendedAction.HOLD_FOR_REVIEW, (
            f"Fallback should always return hold_for_review, got {result.recommended_action}"
        )


def test_fallback_confidence_bounded():
    anomaly = _make_anomaly()
    result = statistical_classify(anomaly)
    assert 0.0 <= result.confidence <= 1.0
    # Fallback should not claim > 0.80 confidence
    assert result.confidence <= 0.80


def test_fallback_explanation_mentions_llm_unavailable():
    anomaly = _make_anomaly()
    result = statistical_classify(anomaly, reason="Timeout after 8s")
    assert "fallback" in result.explanation.lower() or "unavailable" in result.explanation.lower()


# ---------------------------------------------------------------------------
# LLM client raises → action layer uses fallback
# ---------------------------------------------------------------------------

def test_action_layer_uses_fallback_on_llm_error(tmp_path):
    """Integration: ActionLayer should fall back when LLM raises LLMUnavailableError."""
    import sqlite3
    from data.seed_db import DDL
    from gateway.action_layer import ActionLayer
    from gateway.audit_log import AuditLog

    # Set up temp DB
    db = tmp_path / "test.db"
    con = sqlite3.connect(db)
    con.executescript(DDL)
    con.commit()
    con.close()

    audit = AuditLog(db_path=db)

    with patch("gateway.action_layer.LLMReasoningClient") as MockLLM:
        mock_instance = MagicMock()
        mock_instance.classify.side_effect = LLMUnavailableError("Simulated timeout")
        MockLLM.return_value = mock_instance

        action = ActionLayer(audit)
        anomaly = _make_anomaly()
        alert = action.process(anomaly)

    assert alert is not None
    assert alert.classification.llm_used is False
    assert alert.classification.fallback_reason is not None

    # Verify audit log entry
    entries = audit.fetch_all()
    assert len(entries) == 1
    assert entries[0]["llm_used"] == 0
    assert entries[0]["fallback_used"] == 1


def test_action_layer_returns_none_for_non_anomaly(tmp_path):
    import sqlite3
    from data.seed_db import DDL
    from gateway.action_layer import ActionLayer
    from gateway.audit_log import AuditLog

    db = tmp_path / "test.db"
    con = sqlite3.connect(db)
    con.executescript(DDL)
    con.commit()
    con.close()

    audit = AuditLog(db_path=db)
    action = ActionLayer(audit)

    # Non-anomalous window
    t = BASE_TIME
    fv = FeatureVector(
        window_start=t, window_end=t + timedelta(minutes=5),
        txn_count=10, txn_velocity=2.0, decline_rate=0.05,
        amount_mean=2000.0, amount_std=500.0, amount_max=5000.0,
        unique_cards=10, unique_ips=8, bin_concentration=0.1,
        sequential_bin_score=0.01,
    )
    non_anomaly = AnomalyResult(
        window_start=t, window_end=t + timedelta(minutes=5),
        is_anomaly=False,
        anomaly_score=0.05,
        zscore_velocity=0.2,
        zscore_decline=0.1,
        triggered_features=[],
        feature_vector=fv,
    )
    result = action.process(non_anomaly)
    assert result is None
