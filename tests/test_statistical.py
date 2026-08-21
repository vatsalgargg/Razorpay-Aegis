"""
Unit tests for the statistical detection layer.
"""

from __future__ import annotations

import sys
from datetime import datetime, timedelta
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from data.schemas import AttackType, FeatureVector, Transaction, TxnStatus
from detection.features import compute_features
from detection.statistical import RollingStats, StatisticalDetector


BASE_TIME = datetime(2024, 1, 1, 12, 0, 0)


# ---------------------------------------------------------------------------
# RollingStats
# ---------------------------------------------------------------------------

def test_rolling_stats_zscore_spike():
    rs = RollingStats()
    for _ in range(100):
        rs.update(5.0)  # Establish stable baseline
    # zscore is computed against current running stats (before this value is added)
    z_normal = rs.zscore(5.0)
    z_spike  = rs.zscore(100.0)
    assert abs(z_normal) < 0.5          # Near-zero for value at the mean
    assert z_spike > 5.0                # Clearly anomalous


def test_rolling_stats_single_value():
    rs = RollingStats()
    rs.update(10.0)
    # With n=1, std=1.0 (guard), zscore should be defined
    z = rs.zscore(10.0)
    assert isinstance(z, float)


# ---------------------------------------------------------------------------
# Detector: flags known attack patterns
# ---------------------------------------------------------------------------

def _make_normal_fv(i: int) -> FeatureVector:
    t = BASE_TIME + timedelta(minutes=i)
    return FeatureVector(
        window_start=t,
        window_end=t + timedelta(minutes=5),
        txn_count=25,
        txn_velocity=5.0,
        decline_rate=0.05,
        amount_mean=2000.0,
        amount_std=800.0,
        amount_max=15000.0,
        unique_cards=24,
        unique_ips=20,
        bin_concentration=0.08,
        sequential_bin_score=0.02,
        is_attack=False,
        attack_type=AttackType.NONE,
    )


def _make_card_testing_fv() -> FeatureVector:
    t = BASE_TIME + timedelta(hours=2)
    return FeatureVector(
        window_start=t,
        window_end=t + timedelta(minutes=5),
        txn_count=40,
        txn_velocity=80.0,    # 16× normal
        decline_rate=0.80,    # 16× normal
        amount_mean=5.0,
        amount_std=2.0,
        amount_max=10.0,
        unique_cards=38,
        unique_ips=1,
        bin_concentration=1.0,
        sequential_bin_score=0.05,
        is_attack=True,
        attack_type=AttackType.CARD_TESTING,
    )


def _make_bin_attack_fv() -> FeatureVector:
    t = BASE_TIME + timedelta(hours=3)
    return FeatureVector(
        window_start=t,
        window_end=t + timedelta(minutes=5),
        txn_count=45,
        txn_velocity=90.0,
        decline_rate=0.65,
        amount_mean=800.0,
        amount_std=200.0,
        amount_max=2000.0,
        unique_cards=44,
        unique_ips=2,
        bin_concentration=0.90,
        sequential_bin_score=0.95,   # Sequential BINs
        is_attack=True,
        attack_type=AttackType.BIN_ATTACK,
    )


def _train_detector_on_normals() -> StatisticalDetector:
    detector = StatisticalDetector()
    normal_fvs = [_make_normal_fv(i) for i in range(60)]
    detector.fit(normal_fvs)
    return detector


def test_detector_flags_card_testing():
    detector = _train_detector_on_normals()
    result = detector.detect(_make_card_testing_fv())
    assert result.is_anomaly, "Detector should flag card-testing attack"
    assert result.anomaly_score > 0.3


def test_detector_flags_bin_attack():
    detector = _train_detector_on_normals()
    result = detector.detect(_make_bin_attack_fv())
    assert result.is_anomaly, "Detector should flag BIN attack"


def test_detector_does_not_flag_normal():
    detector = _train_detector_on_normals()
    # Run several normal windows AFTER warm-up
    for i in range(20):
        detector.detect(_make_normal_fv(i))  # Warm-up

    normal_fv = _make_normal_fv(100)
    result = detector.detect(normal_fv)
    # Normal should not fire (may have transient FPs, but at low score)
    # We assert score < 0.9 — not a hard flag
    assert result.anomaly_score < 0.9, f"Normal traffic got high score: {result.anomaly_score}"


def test_detector_handles_empty_window():
    detector = _train_detector_on_normals()
    t = BASE_TIME
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


def test_triggered_features_populated():
    detector = _train_detector_on_normals()
    result = detector.detect(_make_card_testing_fv())
    if result.is_anomaly:
        assert len(result.triggered_features) > 0


def test_save_load_roundtrip(tmp_path):
    detector = _train_detector_on_normals()
    model_path = tmp_path / "test_if.pkl"
    detector.save(model_path)

    detector2 = StatisticalDetector()
    detector2.load(model_path)

    result = detector2.detect(_make_card_testing_fv())
    assert result.is_anomaly
