"""
Full evaluation on the held-out test set.

Runs the complete detection pipeline against all test-split transactions,
computes precision/recall/F1, and reports the ₹ false-positive cost.

This script touches the held-out set ONLY — never during training.
Run AFTER the server has been started and the model trained:
  python -m evaluation.evaluate
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from data.schemas import AttackType, Transaction, TxnStatus
from data.seed_db import DB_PATH
from detection.features import compute_features, sliding_windows
from detection.statistical import StatisticalDetector, MODEL_PATH
from gateway.action_layer import ActionLayer
from gateway.audit_log import AuditLog

logging.basicConfig(level=logging.WARNING)

# ₹ false-positive cost assumption (documented, not hidden)
# Each FP triggers a 15-minute manual review by a risk analyst.
# Analyst cost: ₹800/hour → ₹200 per false-positive event.
FP_COST_PER_EVENT_INR = 200.0


# ---------------------------------------------------------------------------
# Load test transactions from SQLite
# ---------------------------------------------------------------------------

def _load_test_txns() -> list[Transaction]:
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    rows = con.execute(
        "SELECT * FROM transactions WHERE split_set='test' ORDER BY timestamp ASC"
    ).fetchall()
    con.close()

    txns = []
    for r in rows:
        txns.append(Transaction(
            txn_id=r["txn_id"],
            timestamp=datetime.fromisoformat(r["timestamp"]),
            card_bin=r["card_bin"],
            card_last4=r["card_last4"],
            amount=r["amount"],
            currency=r["currency"],
            ip_address=r["ip_address"],
            device_id=r["device_id"],
            merchant_id=r["merchant_id"],
            status=TxnStatus(r["status"]),
            is_attack=bool(r["is_attack"]),
            attack_type=AttackType(r["attack_type"]),
            attack_window_id=r["attack_window_id"],
        ))
    return txns


# ---------------------------------------------------------------------------
# Run evaluation
# ---------------------------------------------------------------------------

def evaluate(window_minutes: int = 5) -> dict:
    print("=" * 60)
    print("  Razorpay AI Risk Manager — Held-Out Test Evaluation")
    print("=" * 60)

    # Load or train model
    detector = StatisticalDetector()
    if MODEL_PATH.exists():
        detector.load()
    else:
        print("[evaluate] Model not found — training on baseline train dataset...")
        con = sqlite3.connect(DB_PATH)
        con.row_factory = sqlite3.Row
        train_rows = con.execute("SELECT * FROM transactions WHERE split_set='train' AND is_attack=0").fetchall()
        con.close()
        train_txns = [
            Transaction(
                txn_id=r["txn_id"],
                timestamp=datetime.fromisoformat(r["timestamp"]),
                card_bin=r["card_bin"],
                card_last4=r["card_last4"],
                amount=r["amount"],
                currency=r["currency"],
                ip_address=r["ip_address"],
                device_id=r["device_id"],
                merchant_id=r["merchant_id"],
                status=TxnStatus(r["status"]),
                is_attack=bool(r["is_attack"]),
                attack_type=AttackType(r["attack_type"]),
                attack_window_id=r["attack_window_id"],
            )
            for r in train_rows
        ]
        train_windows = sliding_windows(train_txns, window_minutes=window_minutes)
        fvs = [compute_features(w, ws, we) for ws, we, w in train_windows if w]
        detector.fit(fvs)
        detector.save(MODEL_PATH)

    audit = AuditLog()
    action = ActionLayer(audit)

    # Load test transactions
    test_txns = _load_test_txns()
    if not test_txns:
        print("ERROR: No test transactions found. Run data/seed_db.py first.")
        sys.exit(1)

    print(f"\nTest set: {len(test_txns)} transactions")
    attack_txns = [t for t in test_txns if t.is_attack]
    print(f"  Attack txns : {len(attack_txns)}")
    print(f"  Normal txns : {len(test_txns) - len(attack_txns)}")

    # Slide windows over test set
    windows = sliding_windows(test_txns, window_minutes=window_minutes)
    print(f"  Windows     : {len(windows)} (step=1 min)")

    # For evaluation, track window-level ground truth
    tp = fp = fn = tn = 0
    window_results = []

    for ws, we, window in windows:
        if not window:
            continue

        fv     = compute_features(window, ws, we)
        result = detector.detect(fv)

        predicted_attack = result.is_anomaly
        actual_attack    = fv.is_attack

        if predicted_attack and actual_attack:
            tp += 1
        elif predicted_attack and not actual_attack:
            fp += 1
        elif not predicted_attack and actual_attack:
            fn += 1
        else:
            tn += 1

        window_results.append({
            "window_start":    ws.isoformat(),
            "is_anomaly":      predicted_attack,
            "actual_attack":   actual_attack,
            "anomaly_score":   result.anomaly_score,
            "attack_type":     fv.attack_type.value,
        })

    # Compute metrics
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall    = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1        = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0

    fp_cost_inr = fp * FP_COST_PER_EVENT_INR

    print("\n" + "-" * 60)
    print("  RESULTS (held-out test set only)")
    print("-" * 60)
    print(f"  TP (correct attack detections) : {tp}")
    print(f"  FP (false alarms)              : {fp}")
    print(f"  FN (missed attacks)            : {fn}")
    print(f"  TN (correct no-alert)          : {tn}")
    print("-" * 60)
    print(f"  Precision                      : {precision:.4f}  ({precision*100:.1f}%)")
    print(f"  Recall                         : {recall:.4f}  ({recall*100:.1f}%)")
    print(f"  F1 Score                       : {f1:.4f}")
    print("-" * 60)
    print(f"  False-Positive Cost (INR)")
    print(f"    Assumption: INR {FP_COST_PER_EVENT_INR:.0f} per FP (15 min analyst review @ INR 800/hr)")
    print(f"    FP events  : {fp}")
    print(f"    Total cost : INR {fp_cost_inr:.2f}")
    print("-" * 60)

    results = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "split": "test",
        "window_minutes": window_minutes,
        "total_windows": len(window_results),
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "fp_cost_assumption_inr_per_event": FP_COST_PER_EVENT_INR,
        "fp_cost_total_inr": fp_cost_inr,
    }

    # Persist metrics to DB
    try:
        con = sqlite3.connect(DB_PATH)
        con.execute(
            """INSERT INTO model_run_metrics
               (run_timestamp, split_set, tp, fp, fn, tn, precision, recall, f1, fp_cost_inr, notes)
               VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
            (
                results["timestamp"], "test",
                tp, fp, fn, tn,
                precision, recall, f1, fp_cost_inr,
                f"window={window_minutes}min FP_cost_assumption=INR {FP_COST_PER_EVENT_INR}/event",
            ),
        )
        con.commit()
        con.close()
        print("\n  [OK] Metrics saved to model_run_metrics table.")
    except Exception as e:
        print(f"\n  [WARN] Could not save metrics to DB: {e}")

    # Save JSON report
    report_path = Path(__file__).resolve().parent / "report.json"
    report_path.parent.mkdir(exist_ok=True)
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)
    print(f"  [OK] Full report saved to {report_path}")
    print("=" * 60)

    return results


if __name__ == "__main__":
    evaluate()
