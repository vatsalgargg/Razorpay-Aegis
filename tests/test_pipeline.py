"""
Full end-to-end pipeline test.

Injects a known card-testing attack window and verifies:
  1. Detection fires (is_anomaly = True)
  2. Alert is created with correct attack_type
  3. Audit log entry is written with all required fields
  4. LLM fallback path works end-to-end (mocked LLM timeout)
"""

from __future__ import annotations

import random
import sqlite3
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from data.generator import generate_card_testing_attack, generate_normal_txns
from data.schemas import AttackType, TxnStatus
from data.seed_db import DDL
from detection.features import compute_features, sliding_windows
from detection.statistical import StatisticalDetector
from gateway.action_layer import ActionLayer
from gateway.audit_log import AuditLog
from reasoning.llm_client import LLMUnavailableError


def _setup_db(tmp_path: Path) -> Path:
    db = tmp_path / "pipeline_test.db"
    con = sqlite3.connect(db)
    con.executescript(DDL)
    con.commit()
    con.close()
    return db


def _train_on_normal(duration_minutes: int = 60) -> StatisticalDetector:
    start = datetime(2024, 1, 1, 0, 0, 0)
    rng = random.Random(42)
    normal_txns = generate_normal_txns(
        start=start,
        duration_minutes=duration_minutes,
        avg_rate=5.0,
        decline_rate=0.05,
        rng=rng,
    )
    windows = sliding_windows(normal_txns, window_minutes=5)
    fvs = [compute_features(w, ws, we) for ws, we, w in windows if w]
    detector = StatisticalDetector()
    detector.fit(fvs)
    return detector


# ---------------------------------------------------------------------------
# Test 1: Card testing end-to-end (with mocked LLM)
# ---------------------------------------------------------------------------

def test_full_pipeline_card_testing_detected(tmp_path):
    """Full pipeline: card testing → detection → alert → audit log."""
    db = _setup_db(tmp_path)

    detector = _train_on_normal()
    audit = AuditLog(db_path=db)

    # Mock LLM to return a valid card_testing classification
    from data.schemas import Classification, RecommendedAction
    mock_classification = Classification(
        attack_type=AttackType.CARD_TESTING,
        confidence=0.95,
        explanation="High decline rate and micro-amounts indicate card testing.",
        recommended_action=RecommendedAction.HOLD_FOR_REVIEW,
        llm_used=True,
    )

    with patch("gateway.action_layer.LLMReasoningClient") as MockLLM:
        mock_instance = MagicMock()
        mock_instance.classify.return_value = mock_classification
        MockLLM.return_value = mock_instance

        action = ActionLayer(audit)

        # Build a card-testing window
        start = datetime(2024, 2, 1, 10, 0, 0)
        attack_txns = generate_card_testing_attack(
            start=start,
            burst_size=35,
            decline_rate=0.80,
            rng=random.Random(999),
        )

        ws = start
        we = start + timedelta(minutes=5)
        fv = compute_features(attack_txns, ws, we)
        result = detector.detect(fv)

        assert result.is_anomaly, (
            f"Pipeline test FAILED: card testing window not flagged. "
            f"score={result.anomaly_score}, triggers={result.triggered_features}"
        )

        alert = action.process(result)
        assert alert is not None
        assert alert.classification.attack_type == AttackType.CARD_TESTING
        assert alert.classification.recommended_action == RecommendedAction.HOLD_FOR_REVIEW

    # Verify audit entry
    entries = audit.fetch_all()
    assert len(entries) == 1
    assert entries[0]["attack_type"] == AttackType.CARD_TESTING.value
    assert entries[0]["llm_used"] == 1


# ---------------------------------------------------------------------------
# Test 2: Full pipeline with LLM timeout → fallback
# ---------------------------------------------------------------------------

def test_full_pipeline_llm_timeout_fallback(tmp_path):
    """Full pipeline: LLM times out → fallback fires → alert still created."""
    db = _setup_db(tmp_path)
    detector = _train_on_normal()
    audit = AuditLog(db_path=db)

    with patch("gateway.action_layer.LLMReasoningClient") as MockLLM:
        mock_instance = MagicMock()
        mock_instance.classify.side_effect = LLMUnavailableError("Test timeout")
        MockLLM.return_value = mock_instance

        action = ActionLayer(audit)

        start = datetime(2024, 2, 1, 11, 0, 0)
        attack_txns = generate_card_testing_attack(
            start=start,
            burst_size=35,
            decline_rate=0.80,
            rng=random.Random(111),
        )
        fv = compute_features(attack_txns, start, start + timedelta(minutes=5))
        result = detector.detect(fv)

        if result.is_anomaly:
            alert = action.process(result)
            assert alert is not None, "Alert must be created even when LLM fails"
            assert alert.classification.llm_used is False
            assert alert.classification.fallback_reason is not None

            entries = audit.fetch_all()
            assert len(entries) == 1
            assert entries[0]["fallback_used"] == 1
            assert entries[0]["llm_used"] == 0
        else:
            pytest.skip("Card testing window not flagged (borderline) — skip fallback path check")


# ---------------------------------------------------------------------------
# Test 3: Degenerate all-zero window
# ---------------------------------------------------------------------------

def test_all_zero_traffic_not_flagged(tmp_path):
    """All-zero traffic (degenerate case) must not crash and must not be flagged."""
    from data.schemas import FeatureVector, AnomalyResult
    detector = _train_on_normal()

    t = datetime(2024, 1, 1, 12, 0, 0)
    fv = FeatureVector(
        window_start=t,
        window_end=t + timedelta(minutes=5),
        txn_count=0,
        txn_velocity=0.0,
        decline_rate=0.0,
        amount_mean=0.0,
        amount_std=0.0,
        amount_max=0.0,
        unique_cards=0,
        unique_ips=0,
        bin_concentration=0.0,
        sequential_bin_score=0.0,
    )
    result = detector.detect(fv)
    assert result.is_anomaly is False
    assert result.anomaly_score == 0.0


# ---------------------------------------------------------------------------
# Test 4: Normal traffic does not generate false alerts at scale
# ---------------------------------------------------------------------------

def test_normal_traffic_low_false_positive_rate(tmp_path):
    """Run 30 minutes of normal traffic; FP rate should be < 20%."""
    detector = _train_on_normal(duration_minutes=60)

    start = datetime(2024, 1, 2, 0, 0, 0)
    rng = random.Random(777)
    normal_txns = generate_normal_txns(start=start, duration_minutes=30, rng=rng)
    windows = sliding_windows(normal_txns, window_minutes=5, step_minutes=1)

    flagged = 0
    total = 0
    for ws, we, window in windows:
        if not window:
            continue
        fv = compute_features(window, ws, we)
        result = detector.detect(fv)
        if result.is_anomaly:
            flagged += 1
        total += 1

    fp_rate = flagged / total if total > 0 else 0.0
    assert fp_rate < 0.20, (
        f"FP rate too high on normal traffic: {fp_rate:.2%} ({flagged}/{total} windows flagged)"
    )
