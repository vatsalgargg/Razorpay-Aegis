"""
Statistical detection layer.

No LLM. Deterministic arithmetic that runs in milliseconds.
Uses:
  1. Rolling z-scores on velocity and decline rate
  2. Isolation Forest on the full feature vector

Thresholds are tuned on the train set only.
The held-out test set is never touched during training.
"""

from __future__ import annotations

import logging
import math
import os
import pickle
from collections import deque
from pathlib import Path
from typing import Sequence

import numpy as np
from sklearn.ensemble import IsolationForest

from data.schemas import AnomalyResult, FeatureVector

logger = logging.getLogger(__name__)

MODEL_PATH = Path(os.getenv("MODEL_PATH", "detection/models/isolation_forest.pkl"))

# ---------------------------------------------------------------------------
# Configuration (tuned on train set — defense-only design)
# ---------------------------------------------------------------------------

ZSCORE_VELOCITY_THRESHOLD = 2.5
ZSCORE_DECLINE_THRESHOLD  = 2.5
IF_CONTAMINATION          = 0.03


# ---------------------------------------------------------------------------
# Rolling statistics tracker (online, O(1) per update)
# ---------------------------------------------------------------------------

class RollingStats:
    """Welford online algorithm for running mean and variance."""

    def __init__(self, maxlen: int = 200) -> None:
        self._buffer: deque[float] = deque(maxlen=maxlen)
        self._mean = 0.0
        self._M2 = 0.0
        self._n = 0

    def update(self, x: float) -> None:
        self._buffer.append(x)
        self._n += 1
        delta = x - self._mean
        self._mean += delta / self._n
        delta2 = x - self._mean
        self._M2 += delta * delta2

    @property
    def mean(self) -> float:
        return self._mean

    @property
    def std(self) -> float:
        if self._n < 2:
            return 1.0  # Avoid division by zero; treat as high-variance
        return math.sqrt(self._M2 / (self._n - 1))

    def zscore(self, x: float) -> float:
        std = self.std
        # Guard against zero variance when baseline values have no spread
        std_floor = max(std, 0.1)
        return (x - self.mean) / std_floor


# ---------------------------------------------------------------------------
# Feature vector → numpy array
# ---------------------------------------------------------------------------

FEATURE_COLS = [
    "txn_velocity",
    "decline_rate",
    "amount_mean",
    "amount_std",
    "amount_max",
    "unique_cards",
    "unique_ips",
    "bin_concentration",
    "sequential_bin_score",
]


def _fv_to_array(fv: FeatureVector) -> np.ndarray:
    return np.array([getattr(fv, col) for col in FEATURE_COLS], dtype=float)


# ---------------------------------------------------------------------------
# StatisticalDetector
# ---------------------------------------------------------------------------

class StatisticalDetector:
    """
    Combines rolling z-scores (fast, online) with Isolation Forest (batch, trained).

    fit()   → train on train-set feature vectors
    save()  → persist Isolation Forest to disk
    load()  → reload from disk (for inference)
    detect()→ returns AnomalyResult for a given FeatureVector
    """

    def __init__(self) -> None:
        self._velocity_stats = RollingStats()
        self._decline_stats  = RollingStats()
        self._if_model: IsolationForest | None = None

    # ------------------------------------------------------------------
    # Training
    # ------------------------------------------------------------------

    def fit(self, feature_vectors: Sequence[FeatureVector]) -> None:
        """Fit Isolation Forest on train-set feature vectors."""
        if not feature_vectors:
            raise ValueError("Cannot fit on empty feature vector list.")

        X = np.vstack([_fv_to_array(fv) for fv in feature_vectors])
        logger.info(f"[detector] Fitting Isolation Forest on {len(X)} windows...")

        self._if_model = IsolationForest(
            n_estimators=200,
            contamination=IF_CONTAMINATION,
            random_state=42,
            n_jobs=-1,
        )
        self._if_model.fit(X)

        # Warm-up rolling stats on train velocities & decline rates
        for fv in feature_vectors:
            self._velocity_stats.update(fv.txn_velocity)
            self._decline_stats.update(fv.decline_rate)

        logger.info("[detector] Isolation Forest fitted and rolling stats warmed up.")

    def save(self, path: Path = MODEL_PATH) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "wb") as f:
            pickle.dump({
                "model": self._if_model,
                "velocity_stats": self._velocity_stats,
                "decline_stats": self._decline_stats,
            }, f)
        logger.info(f"[detector] Model saved to {path}")

    def load(self, path: Path = MODEL_PATH) -> None:
        if not path.exists():
            raise FileNotFoundError(f"Model file not found: {path}. Run seed + train first.")
        with open(path, "rb") as f:
            data = pickle.load(f)
        self._if_model = data["model"]
        self._velocity_stats = data["velocity_stats"]
        self._decline_stats  = data["decline_stats"]
        logger.info(f"[detector] Model loaded from {path}")

    # ------------------------------------------------------------------
    # Inference
    # ------------------------------------------------------------------

    def detect(self, fv: FeatureVector) -> AnomalyResult:
        """
        Returns an AnomalyResult for a single FeatureVector.
        Works even if Isolation Forest is not loaded (z-score only fallback).
        """
        if fv.txn_count == 0:
            return AnomalyResult(
                window_start=fv.window_start,
                window_end=fv.window_end,
                is_anomaly=False,
                anomaly_score=0.0,
                zscore_velocity=0.0,
                zscore_decline=0.0,
                triggered_features=[],
                feature_vector=fv,
            )

        # Rolling z-scores
        z_vel  = self._velocity_stats.zscore(fv.txn_velocity)
        z_dec  = self._decline_stats.zscore(fv.decline_rate)

        triggered: list[str] = []
        if z_vel > ZSCORE_VELOCITY_THRESHOLD:
            triggered.append(f"velocity_zscore={z_vel:.2f}")
        if z_dec > ZSCORE_DECLINE_THRESHOLD:
            triggered.append(f"decline_zscore={z_dec:.2f}")

        # Deterministic statistical pattern triggers (no LLM, purely arithmetic)
        # 1. Card testing signature: elevated decline rate + micro-amount transactions
        if fv.decline_rate >= 0.35 and fv.txn_count >= 8 and (fv.amount_mean <= 350.0 or fv.decline_rate >= 0.60):
            triggered.append(f"card_testing_signature(dec={fv.decline_rate:.2f},amt={fv.amount_mean:.1f})")

        # 2. BIN attack signature: sequential BINs or high concentration + velocity
        if fv.sequential_bin_score >= 0.20 and fv.txn_count >= 8:
            triggered.append(f"sequential_bin_signature(score={fv.sequential_bin_score:.2f})")
        elif fv.bin_concentration >= 0.40 and fv.txn_velocity >= 8.0 and fv.decline_rate >= 0.30:
            triggered.append(f"bin_concentration_signature(conc={fv.bin_concentration:.2f},vel={fv.txn_velocity:.1f})")

        # Isolation Forest score
        if_score = 0.0
        if self._if_model is not None:
            X = _fv_to_array(fv).reshape(1, -1)
            is_if_anomaly = self._if_model.predict(X)[0] == -1
            decision = float(self._if_model.decision_function(X)[0])
            if_score = max(0.0, min(1.0, 0.5 - decision))
            if is_if_anomaly or if_score > 0.50:
                triggered.append(f"isolation_forest={if_score:.3f}")

        is_anomaly = bool(triggered)

        # Only update baseline with normal traffic to avoid baseline corruption
        if not is_anomaly:
            self._velocity_stats.update(fv.txn_velocity)
            self._decline_stats.update(fv.decline_rate)

        composite_score = max(
            min(abs(z_vel) / 10.0, 1.0),
            min(abs(z_dec) / 10.0, 1.0),
            if_score,
            0.88 if ("card_testing_signature" in str(triggered) or "sequential_bin_signature" in str(triggered)) else 0.0,
        )

        return AnomalyResult(
            window_start=fv.window_start,
            window_end=fv.window_end,
            is_anomaly=is_anomaly,
            anomaly_score=round(composite_score, 4),
            zscore_velocity=round(z_vel, 4),
            zscore_decline=round(z_dec, 4),
            triggered_features=triggered,
            feature_vector=fv,
        )
