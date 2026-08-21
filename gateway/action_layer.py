"""
Gated action layer.

Assembles the final Alert from the statistical anomaly result + LLM classification.
Falls back to heuristic classification if LLM is unavailable.

Design constraint: this layer has NO write access to any block list, card list,
or merchant list. It can only write to the audit log. A human decides all actions.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone

from data.schemas import Alert, AnomalyResult, Classification
from gateway.audit_log import AuditLog
from reasoning.fallback import statistical_classify
from reasoning.llm_client import LLMReasoningClient, LLMUnavailableError

logger = logging.getLogger(__name__)


class ActionLayer:
    """
    Coordinates LLM classification → fallback → audit logging.
    One instance per running detector process.
    """

    def __init__(self, audit_log: AuditLog) -> None:
        self._llm = LLMReasoningClient()
        self._audit = audit_log
        self._last_classification: Classification | None = None
        self._last_classified_time: datetime | None = None

    def process(self, anomaly: AnomalyResult) -> Alert | None:
        """
        Process a flagged anomaly window.
        Returns an Alert (written to audit log) or None if the window is not anomalous.
        """
        if not anomaly.is_anomaly:
            return None

        # --- LLM classification (with 15s burst reuse to respect API rate limits) ---
        now = datetime.now(timezone.utc)
        classification = None

        if (
            self._last_classification is not None
            and self._last_classified_time is not None
            and (now - self._last_classified_time).total_seconds() < 15.0
        ):
            # Reuse active burst classification
            classification = self._last_classification
        else:
            try:
                classification = self._llm.classify(anomaly)
                self._last_classification = classification
                self._last_classified_time = now
                logger.info(
                    f"[action] LLM classified: {classification.attack_type.value} "
                    f"confidence={classification.confidence:.2f}"
                )
            except LLMUnavailableError as e:
                logger.warning(f"[action] LLM unavailable, using fallback: {e}")
                classification = statistical_classify(anomaly, reason=str(e))

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
