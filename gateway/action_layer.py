"""
Gated action layer.

Assembles the final Alert from the statistical anomaly result + LLM classification.
Falls back to heuristic classification if LLM is unavailable.

Design constraint: this layer has NO write access to any block list, card list,
or merchant list. It can only write to the audit log. A human decides all actions.
"""

from __future__ import annotations

import logging
import threading
import uuid
from datetime import datetime, timezone

from data.schemas import Alert, AnomalyResult, Classification, RecommendedAction
from gateway.audit_log import AuditLog
from gateway.threat_mesh import ThreatMesh
from reasoning.fallback import statistical_classify
from reasoning.llm_client import LLMReasoningClient, LLMUnavailableError

logger = logging.getLogger(__name__)


class ActionLayer:
    """
    Coordinates LLM classification → fallback → audit logging → threat mesh.
    One instance per running detector process. Thread-safe.
    """

    def __init__(self, audit_log: AuditLog, threat_mesh: ThreatMesh | None = None) -> None:
        self._llm         = LLMReasoningClient()
        self._audit       = audit_log
        self._threat_mesh = threat_mesh
        self._lock        = threading.Lock()
        self._burst_cache: dict[str, tuple[Classification, datetime]] = {}

    def _get_signature_key(self, anomaly: AnomalyResult) -> str:
        """Derive a pattern signature key from triggered features and metrics."""
        triggers = "_".join(sorted(anomaly.triggered_features))
        fv = anomaly.feature_vector
        # Group by pattern type & decline magnitude
        dec_bucket = round(fv.decline_rate * 2) / 2  # 0.0, 0.5, 1.0
        amt_bucket = "micro" if fv.amount_mean <= 100.0 else "normal"
        return f"{triggers}:{dec_bucket}:{amt_bucket}"

    def process(self, anomaly: AnomalyResult) -> Alert | None:
        """
        Process a flagged anomaly window.
        Returns an Alert (written to audit log) or None if the window is not anomalous.
        """
        if not anomaly.is_anomaly:
            return None

        # --- LLM classification (with 15s burst reuse per signature to respect API rate limits) ---
        now = datetime.now(timezone.utc)
        sig_key = self._get_signature_key(anomaly)
        classification = None

        with self._lock:
            cached = self._burst_cache.get(sig_key)
            if cached is not None:
                cached_class, cached_time = cached
                if (now - cached_time).total_seconds() < 15.0:
                    classification = cached_class

            if classification is None:
                try:
                    classification = self._llm.classify(anomaly)
                    self._burst_cache[sig_key] = (classification, now)
                    logger.info(
                        f"[action] LLM classified: {classification.attack_type.value} "
                        f"confidence={classification.confidence:.2f}"
                    )
                except LLMUnavailableError as e:
                    logger.warning(f"[action] LLM unavailable, using fallback: {e}")
                    classification = statistical_classify(anomaly, reason=str(e))
                except Exception as e:
                    logger.error(f"[action] Unexpected error during classification, falling back: {e}")
                    classification = statistical_classify(anomaly, reason=f"Internal error: {e}")

        # --- Assemble alert ---
        alert = Alert(
            alert_id=str(uuid.uuid4()),
            timestamp=datetime.now(timezone.utc),
            anomaly_result=anomaly,
            classification=classification,
            ground_truth_is_attack=anomaly.feature_vector.is_attack,
            ground_truth_attack_type=anomaly.feature_vector.attack_type,
        )

        # --- Write to audit log (append-only) ---
        self._audit.write(alert)

        logger.info(
            f"[action] Alert {alert.alert_id[:8]}... written | "
            f"action={classification.recommended_action.value} | "
            f"llm_used={classification.llm_used}"
        )

        return alert
