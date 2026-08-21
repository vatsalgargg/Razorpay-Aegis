"""
Unit tests for the feature engineering layer.
"""

from __future__ import annotations

import pytest
from datetime import datetime, timedelta

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from data.schemas import AttackType, Transaction, TxnStatus
from detection.features import compute_features, sliding_windows, _sequential_bin_score


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _make_txn(**kwargs) -> Transaction:
    defaults = dict(
        txn_id="test-1",
        timestamp=datetime(2024, 1, 1, 12, 0, 0),
        card_bin="411111",
        card_last4="1234",
        amount=500.0,
        ip_address="1.2.3.4",
        device_id="DEV_ABCDE",
        merchant_id="MERCH_0001",
        status=TxnStatus.SUCCESS,
        is_attack=False,
        attack_type=AttackType.NONE,
    )
    defaults.update(kwargs)
    return Transaction(**defaults)


BASE_TIME = datetime(2024, 1, 1, 12, 0, 0)
W_START   = BASE_TIME
W_END     = BASE_TIME + timedelta(minutes=5)


# ---------------------------------------------------------------------------
# Empty window
# ---------------------------------------------------------------------------

def test_compute_features_empty_window():
    fv = compute_features([], W_START, W_END)
    assert fv.txn_count == 0
    assert fv.txn_velocity == 0.0
    assert fv.decline_rate == 0.0
    assert fv.is_attack is False


# ---------------------------------------------------------------------------
# Velocity
# ---------------------------------------------------------------------------

def test_velocity_calculation():
    txns = [
        _make_txn(txn_id=str(i), timestamp=W_START + timedelta(seconds=i * 30))
        for i in range(10)
    ]
    fv = compute_features(txns, W_START, W_END)
    # 10 txns in 5 minutes = 2 txns/min
    assert abs(fv.txn_velocity - 2.0) < 0.1


# ---------------------------------------------------------------------------
# Decline rate
# ---------------------------------------------------------------------------

def test_decline_rate_all_failures():
    txns = [
        _make_txn(txn_id=str(i), timestamp=W_START + timedelta(seconds=i), status=TxnStatus.FAILURE)
        for i in range(20)
    ]
    fv = compute_features(txns, W_START, W_END)
    assert fv.decline_rate == 1.0


def test_decline_rate_no_failures():
    txns = [
        _make_txn(txn_id=str(i), timestamp=W_START + timedelta(seconds=i), status=TxnStatus.SUCCESS)
        for i in range(10)
    ]
    fv = compute_features(txns, W_START, W_END)
    assert fv.decline_rate == 0.0


# ---------------------------------------------------------------------------
# Amount distribution
# ---------------------------------------------------------------------------

def test_amount_stats():
    amounts = [10.0, 20.0, 30.0]
    txns = [
        _make_txn(txn_id=str(i), timestamp=W_START + timedelta(seconds=i), amount=a)
        for i, a in enumerate(amounts)
    ]
    fv = compute_features(txns, W_START, W_END)
    assert abs(fv.amount_mean - 20.0) < 0.01
    assert fv.amount_max == 30.0


# ---------------------------------------------------------------------------
# BIN concentration
# ---------------------------------------------------------------------------

def test_bin_concentration_all_same():
    txns = [
        _make_txn(txn_id=str(i), timestamp=W_START + timedelta(seconds=i), card_bin="411111")
        for i in range(10)
    ]
    fv = compute_features(txns, W_START, W_END)
    assert fv.bin_concentration == 1.0


def test_bin_concentration_all_different():
    txns = [
        _make_txn(txn_id=str(i), timestamp=W_START + timedelta(seconds=i), card_bin=f"4{i}1111")
        for i in range(10)
    ]
    fv = compute_features(txns, W_START, W_END)
    assert fv.bin_concentration == 0.1


# ---------------------------------------------------------------------------
# Sequential BIN score
# ---------------------------------------------------------------------------

def test_sequential_bin_score_sequential():
    bins = ["452301", "452302", "452303", "452304", "452305"]
    score = _sequential_bin_score(bins)
    assert score > 0.8, f"Expected high sequential score, got {score}"


def test_sequential_bin_score_random():
    bins = ["411111", "524242", "601100", "370000", "400000"]
    score = _sequential_bin_score(bins)
    assert score < 0.5, f"Expected low sequential score for random BINs, got {score}"


def test_sequential_bin_score_single():
    assert _sequential_bin_score(["411111"]) == 0.0


# ---------------------------------------------------------------------------
# Ground-truth propagation
# ---------------------------------------------------------------------------

def test_ground_truth_attack_propagated():
    normal_txn = _make_txn(txn_id="n1", timestamp=W_START, is_attack=False)
    attack_txn = _make_txn(
        txn_id="a1",
        timestamp=W_START + timedelta(seconds=10),
        is_attack=True,
        attack_type=AttackType.CARD_TESTING,
    )
    fv = compute_features([normal_txn, attack_txn], W_START, W_END)
    assert fv.is_attack is True
    assert fv.attack_type == AttackType.CARD_TESTING


def test_ground_truth_no_attack():
    txns = [_make_txn(txn_id=str(i), timestamp=W_START + timedelta(seconds=i)) for i in range(5)]
    fv = compute_features(txns, W_START, W_END)
    assert fv.is_attack is False
    assert fv.attack_type == AttackType.NONE


# ---------------------------------------------------------------------------
# Sliding windows
# ---------------------------------------------------------------------------

def test_sliding_windows_basic():
    txns = [
        _make_txn(txn_id=str(i), timestamp=W_START + timedelta(minutes=i))
        for i in range(10)
    ]
    windows = sliding_windows(txns, window_minutes=5, step_minutes=1)
    assert len(windows) > 0
    for ws, we, w in windows:
        assert ws < we


def test_sliding_windows_empty():
    assert sliding_windows([], window_minutes=5) == []
