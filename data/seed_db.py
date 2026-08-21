"""
Database seeder: generates synthetic data and loads it into SQLite.
Creates tables for transactions, audit log, and model metrics.
Run once before starting the detector.
"""

from __future__ import annotations

import json
import os
import sqlite3
from pathlib import Path

from data.generator import build_dataset
from data.schemas import Transaction

DB_PATH = Path(os.getenv("DB_PATH", "razorpay_risk.db"))


# ---------------------------------------------------------------------------
# Schema DDL
# ---------------------------------------------------------------------------

DDL = """
CREATE TABLE IF NOT EXISTS transactions (
    txn_id           TEXT PRIMARY KEY,
    timestamp        TEXT NOT NULL,
    card_bin         TEXT NOT NULL,
    card_last4       TEXT NOT NULL,
    amount           REAL NOT NULL,
    currency         TEXT NOT NULL DEFAULT 'INR',
    ip_address       TEXT NOT NULL,
    device_id        TEXT NOT NULL,
    merchant_id      TEXT NOT NULL,
    status           TEXT NOT NULL,
    split_set        TEXT NOT NULL,   -- 'train' or 'test'
    is_attack        INTEGER NOT NULL DEFAULT 0,
    attack_type      TEXT NOT NULL DEFAULT 'none',
    attack_window_id TEXT
);

CREATE TABLE IF NOT EXISTS audit_log (
    id                    INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id              TEXT NOT NULL UNIQUE,
    timestamp             TEXT NOT NULL,
    window_start          TEXT NOT NULL,
    window_end            TEXT NOT NULL,
    txn_count             INTEGER NOT NULL,
    anomaly_score         REAL NOT NULL,
    zscore_velocity       REAL NOT NULL,
    zscore_decline        REAL NOT NULL,
    triggered_features    TEXT NOT NULL,   -- JSON list
    attack_type           TEXT NOT NULL,
    confidence            REAL NOT NULL,
    explanation           TEXT NOT NULL,
    recommended_action    TEXT NOT NULL,
    llm_used              INTEGER NOT NULL DEFAULT 0,
    fallback_used         INTEGER NOT NULL DEFAULT 0,
    fallback_reason       TEXT,
    ground_truth_is_attack INTEGER NOT NULL DEFAULT 0,
    ground_truth_attack_type TEXT NOT NULL DEFAULT 'none',
    feature_vector_json   TEXT NOT NULL    -- Full feature snapshot for audit
);

CREATE TABLE IF NOT EXISTS model_run_metrics (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    run_timestamp TEXT NOT NULL,
    split_set     TEXT NOT NULL,
    tp            INTEGER,
    fp            INTEGER,
    fn            INTEGER,
    tn            INTEGER,
    precision     REAL,
    recall        REAL,
    f1            REAL,
    fp_cost_inr   REAL,
    notes         TEXT
);

CREATE INDEX IF NOT EXISTS idx_txn_timestamp ON transactions(timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp);
"""


# ---------------------------------------------------------------------------
# Seeder
# ---------------------------------------------------------------------------

def seed(db_path: Path = DB_PATH, force: bool = False) -> None:
    if db_path.exists() and not force:
        print(f"[seed] DB already exists at {db_path}. Use --force to re-seed.")
        return

    if db_path.exists():
        db_path.unlink()
        print(f"[seed] Removed existing DB.")

    con = sqlite3.connect(db_path)
    cur = con.cursor()
    cur.executescript(DDL)
    con.commit()

    print("[seed] Generating synthetic dataset...")
    dataset = build_dataset(
        total_duration_minutes=480,
        num_card_testing_attacks=10,
        num_bin_attacks=8,
    )

    rows: list[tuple] = []
    for split, txns in dataset.items():
        for txn in txns:
            rows.append((
                txn.txn_id,
                txn.timestamp.isoformat(),
                txn.card_bin,
                txn.card_last4,
                txn.amount,
                txn.currency,
                txn.ip_address,
                txn.device_id,
                txn.merchant_id,
                txn.status.value,
                split,
                int(txn.is_attack),
                txn.attack_type.value,
                txn.attack_window_id,
            ))

    cur.executemany(
        """INSERT OR IGNORE INTO transactions
           (txn_id, timestamp, card_bin, card_last4, amount, currency,
            ip_address, device_id, merchant_id, status, split_set,
            is_attack, attack_type, attack_window_id)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        rows,
    )
    con.commit()
    con.close()

    print(f"[seed] Inserted {len(rows)} transactions into {db_path}")
    
    # Train and save Isolation Forest baseline model
    try:
        from detection.features import compute_features, sliding_windows
        from detection.statistical import StatisticalDetector, MODEL_PATH
        from datetime import datetime

        print("[seed] Training baseline Isolation Forest model on normal traffic...")
        con = sqlite3.connect(db_path)
        con.row_factory = sqlite3.Row
        train_rows = con.execute(
            "SELECT * FROM transactions WHERE split_set='train' AND is_attack=0 ORDER BY timestamp ASC"
        ).fetchall()
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
                status=r["status"],
                is_attack=bool(r["is_attack"]),
                attack_type=r["attack_type"],
                attack_window_id=r["attack_window_id"],
            )
            for r in train_rows
        ]
        windows = sliding_windows(train_txns, window_minutes=5)
        fvs = [compute_features(w, ws, we) for ws, we, w in windows if w]
        if fvs:
            detector = StatisticalDetector()
            detector.fit(fvs)
            detector.save(MODEL_PATH)
            print(f"[seed] Trained and saved model to {MODEL_PATH}")
    except Exception as e:
        print(f"[seed] Warning: could not auto-train model during seed: {e}")

    print("[seed] Done. DB and models ready.")


def get_connection(db_path: Path = DB_PATH) -> sqlite3.Connection:
    con = sqlite3.connect(db_path)
    con.row_factory = sqlite3.Row
    return con


if __name__ == "__main__":
    import sys
    force = "--force" in sys.argv
    seed(force=force)
