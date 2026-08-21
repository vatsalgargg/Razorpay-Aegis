"""
Pydantic schemas for the Razorpay AI Risk Manager pipeline.
All data structures — transactions, feature vectors, anomaly results, alerts — are defined here.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class TxnStatus(str, Enum):
    SUCCESS = "success"
    FAILURE = "failure"
    PENDING = "pending"


class AttackType(str, Enum):
    CARD_TESTING = "card_testing"
    BIN_ATTACK = "bin_attack"
    BENIGN_SPIKE = "benign_spike"
    NONE = "none"


class RecommendedAction(str, Enum):
    FLAG = "flag"
    HOLD_FOR_REVIEW = "hold_for_review"
    NO_ACTION = "no_action"


# ---------------------------------------------------------------------------
# Core transaction model
# ---------------------------------------------------------------------------

class Transaction(BaseModel):
    txn_id: str
    timestamp: datetime
    card_bin: str                      # First 6 digits of card
    card_last4: str                    # Last 4 digits
    amount: float                      # In INR
    currency: str = "INR"
    ip_address: str
    device_id: str
    merchant_id: str
    status: TxnStatus
    # Ground-truth labels (set at generation time, never inferred)
    is_attack: bool = False
    attack_type: AttackType = AttackType.NONE
    attack_window_id: Optional[str] = None  # Groups txns belonging to the same attack window


# ---------------------------------------------------------------------------
# Feature vector (output of feature engineering layer)
# ---------------------------------------------------------------------------

class FeatureVector(BaseModel):
    window_start: datetime
    window_end: datetime
    txn_count: int
    txn_velocity: float                # Transactions per minute
    decline_rate: float                # Failures / total
    amount_mean: float
    amount_std: float
    amount_max: float
    unique_cards: int
    unique_ips: int
    bin_concentration: float           # Fraction of txns from top-1 BIN
    sequential_bin_score: float        # 0–1: how sequential card BINs are
    # Ground-truth for evaluation
    is_attack: bool = False
    attack_type: AttackType = AttackType.NONE


# ---------------------------------------------------------------------------
# Statistical detection output
# ---------------------------------------------------------------------------

class AnomalyResult(BaseModel):
    window_start: datetime
    window_end: datetime
    is_anomaly: bool
    anomaly_score: float               # Composite anomaly score: 0–1 (higher = more anomalous)
    zscore_velocity: float
    zscore_decline: float
    triggered_features: list[str]      # Which features crossed threshold
    feature_vector: FeatureVector


# ---------------------------------------------------------------------------
# LLM / fallback classification output
# ---------------------------------------------------------------------------

class Classification(BaseModel):
    attack_type: AttackType
    confidence: float = Field(ge=0.0, le=1.0)
    explanation: str
    recommended_action: RecommendedAction
    llm_used: bool                     # True = LLM responded; False = fallback heuristic
    llm_provider: Optional[str] = None # e.g. "Groq (120B)", "Gemini 1.5", "Fallback"
    fallback_reason: Optional[str] = None


# ---------------------------------------------------------------------------
# Final alert (written to audit log)
# ---------------------------------------------------------------------------

class Alert(BaseModel):
    alert_id: str
    timestamp: datetime
    anomaly_result: AnomalyResult
    classification: Classification
    # Evaluation metadata
    ground_truth_is_attack: bool = False
    ground_truth_attack_type: AttackType = AttackType.NONE
