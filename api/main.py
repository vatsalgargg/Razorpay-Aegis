"""
FastAPI application — the central runtime for the Risk Manager.

Endpoints:
  POST /ingest          Accept a transaction; trigger detection on rolling window
  GET  /alerts          Recent alerts from audit log
  GET  /audit           Full audit trail
  GET  /metrics         Live detection metrics (on labeled test data)
  GET  /health          Liveness check
"""

from __future__ import annotations

import logging
import os
import sys
from collections import deque
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from dotenv import load_dotenv

# Ensure project root is on path and load .env
PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))
load_dotenv(PROJECT_ROOT / ".env")
load_dotenv()

from api.dashboard_html import HTML_TEMPLATE
from data.schemas import Transaction, TxnStatus
from data.seed_db import seed, DB_PATH
from detection.features import compute_features, sliding_windows
from detection.statistical import StatisticalDetector, MODEL_PATH
from gateway.action_layer import ActionLayer
from gateway.audit_log import AuditLog

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Global state
# ---------------------------------------------------------------------------
WINDOW_MINUTES = int(os.getenv("WINDOW_MINUTES", "5"))
MAX_BUFFER     = int(os.getenv("MAX_BUFFER_TXN", "2000"))

import threading

_txn_buffer: deque[Transaction] = deque(maxlen=MAX_BUFFER)
_recent_alerts: deque[dict] = deque(maxlen=200)
_recent_txns: deque[dict] = deque(maxlen=60)
_state_lock = threading.Lock()
_detector: StatisticalDetector
_action_layer: ActionLayer
_audit_log: AuditLog


# ---------------------------------------------------------------------------
# Startup / shutdown
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    global _detector, _action_layer, _audit_log

    logger.info("[startup] Seeding database (if needed)...")
    seed(force=False)

    logger.info("[startup] Loading / training detection model...")
    _audit_log = AuditLog()
    _detector  = StatisticalDetector()

    if MODEL_PATH.exists():
        _detector.load()
        logger.info("[startup] Loaded pre-trained Isolation Forest.")
    else:
        # Train on the seeded train-split data
        _train_detector()

    _action_layer = ActionLayer(_audit_log)
    logger.info("[startup] Risk Manager ready.")
    yield
    logger.info("[shutdown] Exiting.")


def _train_detector() -> None:
    """Fit Isolation Forest on normal baseline from the train-split data."""
    global _detector
    import sqlite3
    from data.schemas import FeatureVector, AttackType
    from datetime import datetime

    logger.info("[train] Loading train baseline transactions from DB...")
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    # Train baseline on normal traffic so the detector learns normal profile
    rows = con.execute(
        "SELECT * FROM transactions WHERE split_set='train' AND is_attack=0 ORDER BY timestamp ASC"
    ).fetchall()
    con.close()

    txns = _rows_to_txns(rows)
    windows = sliding_windows(txns, window_minutes=WINDOW_MINUTES)
    fvs = [compute_features(w, ws, we) for ws, we, w in windows if w]

    if not fvs:
        logger.warning("[train] No feature vectors computed — skipping IF training.")
        return

    _detector = StatisticalDetector()
    _detector.fit(fvs)
    _detector.save()
    logger.info(f"[train] Isolation Forest trained on {len(fvs)} baseline windows.")


def _rows_to_txns(rows) -> list[Transaction]:
    txns = []
    for r in rows:
        from data.schemas import AttackType, TxnStatus
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
# App
# ---------------------------------------------------------------------------

app = FastAPI(
    title="Razorpay AI Risk Manager",
    version="1.0.0",
    description="Defense-only fraud-spike detector. Statistical layer + LLM classification.",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.get("/health")
def health() -> dict:
    return {"status": "ok", "buffer_size": len(_txn_buffer)}


@app.post("/ingest")
def ingest(txn: Transaction) -> dict[str, Any]:
    """
    Accept a single transaction, update the rolling window,
    run detection, and return any alert raised.
    """
    with _state_lock:
        _txn_buffer.append(txn)
        _recent_txns.appendleft(txn.model_dump(mode="json"))

        # Build rolling window strictly bounded within [now - WINDOW_MINUTES, now]
        now = txn.timestamp
        window_start = now - timedelta(minutes=WINDOW_MINUTES)
        window = [t for t in _txn_buffer if window_start <= t.timestamp <= now]

    # Need minimum warmup buffer to calculate meaningful rolling statistics
    if len(window) < 10:
        return {
            "txn_id": txn.txn_id,
            "is_anomaly": False,
            "anomaly_score": 0.0,
            "alert": None,
        }

    fv     = compute_features(window, window_start, now)
    result = _detector.detect(fv)

    alert_data: dict | None = None
    if result.is_anomaly:
        alert = _action_layer.process(result)
        if alert:
            alert_data = {
                "alert_id":          alert.alert_id,
                "timestamp":         alert.timestamp.isoformat(),
                "attack_type":       alert.classification.attack_type.value,
                "confidence":        alert.classification.confidence,
                "recommended_action": alert.classification.recommended_action.value,
                "explanation":       alert.classification.explanation,
                "anomaly_score":     result.anomaly_score,
                "triggered_features": result.triggered_features,
                "llm_used":          alert.classification.llm_used,
                "llm_provider":      alert.classification.llm_provider or ("Groq AI" if alert.classification.llm_used else "Deterministic Fallback"),
            }
            with _state_lock:
                _recent_alerts.appendleft(alert_data)

    return {
        "txn_id":        txn.txn_id,
        "is_anomaly":    result.is_anomaly,
        "anomaly_score": result.anomaly_score,
        "alert":         alert_data,
    }


@app.get("/", response_class=HTMLResponse)
@app.get("/dashboard", response_class=HTMLResponse)
def get_dashboard() -> HTMLResponse:
    """Serve the sleek interactive real-time Web Dashboard."""
    return HTMLResponse(content=HTML_TEMPLATE, status_code=200)


@app.get("/alerts")
def get_alerts(limit: int = 20) -> list[dict]:
    """Return recent REAL attack alerts only (newest first). Excludes 'none' classifications."""
    with _state_lock:
        real_alerts = [
            a for a in _recent_alerts
            if a.get("attack_type") not in ("none", None)
        ]
        return real_alerts[:limit]


@app.get("/transactions")
def get_transactions(limit: int = 30) -> list[dict]:
    """Return recent ingested transactions for live UI ticker."""
    with _state_lock:
        return list(_recent_txns)[:limit]


@app.get("/audit")
def get_audit(limit: int = 100) -> list[dict]:
    """Return audit trail entries (newest first)."""
    return _audit_log.fetch_recent(limit)


@app.get("/metrics")
def get_metrics() -> dict[str, Any]:
    """
    Compute precision/recall on the audit log against ground-truth labels.
    Only meaningful once test-set transactions have been ingested.
    """
    entries = _audit_log.fetch_all()
    if not entries:
        return {"message": "No audit entries yet."}

    tp = sum(1 for e in entries if e["ground_truth_is_attack"] and e["attack_type"] != "none")
    fp = sum(1 for e in entries if not e["ground_truth_is_attack"] and e["attack_type"] != "none")
    fn = 0  # Misses not tracked via audit log — tracked in evaluate.py

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    f1        = (2 * tp) / (2 * tp + fp + fn) if (2 * tp + fp + fn) > 0 else 0.0

    # ₹ false-positive cost
    # Assumption: 15 min risk-analyst review at ₹800/hr = ₹200 per FP
    fp_cost_inr = fp * 200.0

    return {
        "alerts_total":  len(entries),
        "tp":            tp,
        "fp":            fp,
        "precision":     round(precision, 4),
        "f1_partial":    round(f1, 4),
        "fp_cost_inr":   fp_cost_inr,
        "note":          "Recall requires full test-set replay. Run evaluation/evaluate.py for complete metrics.",
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("api.main:app", host="0.0.0.0", port=8000, reload=False)
