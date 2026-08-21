"""
Audit log — append-only SQLite writer.

Every flagged window gets a single, complete, immutable audit entry.
No UPDATEs. No DELETEs. Overlapping attack windows create separate entries.
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
from pathlib import Path

from data.schemas import Alert

logger = logging.getLogger(__name__)

DB_PATH = Path(os.getenv("DB_PATH", "razorpay_risk.db"))

INSERT_SQL = """
INSERT INTO audit_log (
    alert_id, timestamp, window_start, window_end, txn_count,
    anomaly_score, zscore_velocity, zscore_decline, triggered_features,
    attack_type, confidence, explanation, recommended_action,
    llm_used, fallback_used, fallback_reason,
    ground_truth_is_attack, ground_truth_attack_type, feature_vector_json
) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
"""


class AuditLog:
    def __init__(self, db_path: Path = DB_PATH) -> None:
        self._db_path = db_path

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self._db_path)

    def write(self, alert: Alert) -> None:
        """Append a single audit entry. Thread-safe via SQLite serialization."""
        ar = alert.anomaly_result
        cl = alert.classification
        fv = ar.feature_vector

        row = (
            alert.alert_id,
            alert.timestamp.isoformat(),
            ar.window_start.isoformat(),
            ar.window_end.isoformat(),
            fv.txn_count,
            ar.anomaly_score,
            ar.zscore_velocity,
            ar.zscore_decline,
            json.dumps(ar.triggered_features),
            cl.attack_type.value,
            cl.confidence,
            cl.explanation,
            cl.recommended_action.value,
            int(cl.llm_used),
            int(not cl.llm_used),          # fallback_used = not llm_used
            cl.fallback_reason or "",
            int(alert.ground_truth_is_attack),
            alert.ground_truth_attack_type.value,
            fv.model_dump_json(),
        )

        try:
            con = self._connect()
            con.execute(INSERT_SQL, row)
            con.commit()
            con.close()
            logger.info(f"[audit] Written alert_id={alert.alert_id}")
        except sqlite3.IntegrityError:
            logger.warning(f"[audit] Duplicate alert_id={alert.alert_id} — skipped.")
        except Exception as e:
            logger.error(f"[audit] Failed to write audit entry: {e}")

    def fetch_recent(self, limit: int = 50) -> list[dict[str, Any]]:
        """Fetch the most recent alert entries, newest first."""
        con = sqlite3.connect(self._db_path)
        con.row_factory = sqlite3.Row
        rows = con.execute(
            """SELECT * FROM audit_log
               ORDER BY timestamp DESC
               LIMIT ?""",
            (limit,),
        ).fetchall()
        con.close()
        return [dict(r) for r in rows]

    def fetch_all(self) -> list[dict]:
        con = self._connect()
        con.row_factory = sqlite3.Row
        cur = con.execute("SELECT * FROM audit_log ORDER BY timestamp ASC")
        rows = [dict(r) for r in cur.fetchall()]
        con.close()
        return rows
