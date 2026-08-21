"""
Tests for the audit log.

Verifies:
  1. Append-only: no silent overwrites.
  2. Overlapping attack windows create separate entries.
  3. Duplicate alert_id is rejected (not overwritten).
  4. All required fields are persisted.
"""

from __future__ import annotations

import json
import sqlite3
import sys
import uuid
from datetime import datetime, timezone, timedelta
from pathlib import Path
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from data.schemas import (
    Alert, AnomalyResult, AttackType, Classification, FeatureVector, RecommendedAction,
)
from data.seed_db import DDL
from gateway.audit_log import AuditLog


def _make_alert(
    alert_id: str | None = None,
    attack_type: AttackType = AttackType.CARD_TESTING,
    is_attack: bool = True,
    window_offset_hours: int = 0,
) -> Alert:
    t = datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc) + timedelta(hours=window_offset_hours)
    fv = FeatureVector(
        window_start=t,
        window_end=t + timedelta(minutes=5),
        txn_count=35,
        txn_velocity=70.0,
        decline_rate=0.80,
        amount_mean=5.0,
        amount_std=2.0,
        amount_max=10.0,
        unique_cards=33,
        unique_ips=1,
        bin_concentration=1.0,
        sequential_bin_score=0.05,
        is_attack=is_attack,
        attack_type=attack_type,
    )
    ar = AnomalyResult(
        window_start=t,
        window_end=t + timedelta(minutes=5),
        is_anomaly=True,
        anomaly_score=0.85,
        zscore_velocity=12.0,
        zscore_decline=15.0,
        triggered_features=["velocity_zscore=12.00"],
        feature_vector=fv,
    )
    cl = Classification(
        attack_type=attack_type,
        confidence=0.92,
        explanation="High decline rate and small amounts indicate card testing.",
        recommended_action=RecommendedAction.HOLD_FOR_REVIEW,
        llm_used=True,
    )
    return Alert(
        alert_id=alert_id or str(uuid.uuid4()),
        timestamp=datetime.now(timezone.utc),
        anomaly_result=ar,
        classification=cl,
        ground_truth_is_attack=is_attack,
        ground_truth_attack_type=attack_type,
    )


def _setup_db(tmp_path: Path) -> Path:
    db = tmp_path / "test_audit.db"
    con = sqlite3.connect(db)
    con.executescript(DDL)
    con.commit()
    con.close()
    return db


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_write_and_fetch(tmp_path):
    db = _setup_db(tmp_path)
    audit = AuditLog(db_path=db)
    alert = _make_alert()
    audit.write(alert)

    entries = audit.fetch_all()
    assert len(entries) == 1
    entry = entries[0]
    assert entry["alert_id"] == alert.alert_id
    assert entry["attack_type"] == AttackType.CARD_TESTING.value
    assert entry["llm_used"] == 1
    assert entry["ground_truth_is_attack"] == 1


def test_overlapping_windows_separate_entries(tmp_path):
    """Two attacks in overlapping time windows must create TWO separate audit entries."""
    db = _setup_db(tmp_path)
    audit = AuditLog(db_path=db)

    alert1 = _make_alert(attack_type=AttackType.CARD_TESTING, window_offset_hours=0)
    alert2 = _make_alert(attack_type=AttackType.BIN_ATTACK, window_offset_hours=0)  # Same time!

    audit.write(alert1)
    audit.write(alert2)

    entries = audit.fetch_all()
    assert len(entries) == 2, "Overlapping windows must produce separate entries"
    attack_types = {e["attack_type"] for e in entries}
    assert AttackType.CARD_TESTING.value in attack_types
    assert AttackType.BIN_ATTACK.value in attack_types


def test_duplicate_alert_id_rejected(tmp_path):
    """Same alert_id must not overwrite an existing entry."""
    db = _setup_db(tmp_path)
    audit = AuditLog(db_path=db)

    fixed_id = str(uuid.uuid4())
    alert1 = _make_alert(alert_id=fixed_id)
    alert2 = _make_alert(alert_id=fixed_id, attack_type=AttackType.BIN_ATTACK)

    audit.write(alert1)
    audit.write(alert2)  # Should be silently rejected

    entries = audit.fetch_all()
    assert len(entries) == 1, "Duplicate alert_id must be rejected"
    assert entries[0]["attack_type"] == AttackType.CARD_TESTING.value


def test_all_fields_persisted(tmp_path):
    db = _setup_db(tmp_path)
    audit = AuditLog(db_path=db)
    alert = _make_alert()
    audit.write(alert)

    entries = audit.fetch_all()
    entry = entries[0]

    required_fields = [
        "alert_id", "timestamp", "window_start", "window_end",
        "txn_count", "anomaly_score", "zscore_velocity", "zscore_decline",
        "triggered_features", "attack_type", "confidence", "explanation",
        "recommended_action", "llm_used", "fallback_used",
        "ground_truth_is_attack", "ground_truth_attack_type", "feature_vector_json",
    ]
    for field in required_fields:
        assert field in entry, f"Field '{field}' missing from audit entry"
        assert entry[field] is not None, f"Field '{field}' is None"


def test_fetch_recent_respects_limit(tmp_path):
    db = _setup_db(tmp_path)
    audit = AuditLog(db_path=db)

    for i in range(10):
        audit.write(_make_alert(window_offset_hours=i))

    recent = audit.fetch_recent(limit=5)
    assert len(recent) == 5


def test_append_only_no_updates(tmp_path):
    """Verify the table has no UPDATE triggers by checking entry count stays consistent."""
    db = _setup_db(tmp_path)
    audit = AuditLog(db_path=db)

    alert = _make_alert()
    audit.write(alert)
    count_before = len(audit.fetch_all())

    # Writing same alert again should be rejected (duplicate ID), count stays same
    audit.write(alert)
    count_after = len(audit.fetch_all())

    assert count_before == count_after == 1
