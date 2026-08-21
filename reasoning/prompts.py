"""
LLM prompt templates for the reasoning layer.

The system prompt instructs the model to output strict JSON.
The user prompt injects the anomaly's feature snapshot.
"""

from __future__ import annotations

from data.schemas import AnomalyResult

SYSTEM_PROMPT = """You are a payment fraud analyst AI assistant integrated into a real-time risk detection system.

You will receive a structured summary of a suspicious transaction window that has already been flagged by a statistical anomaly detector. Your job is to:
1. Classify the attack type based on the patterns.
2. Explain your reasoning in plain English (1–3 sentences) suitable for a risk analyst.
3. Recommend an action.

You MUST respond with a single valid JSON object following this exact structure:
{
  "attack_type": "card_testing",
  "confidence": 0.95,
  "explanation": "High decline rate with very low average transaction amount suggests card testing.",
  "recommended_action": "hold_for_review"
}

Allowed values:
- attack_type: "card_testing", "bin_attack", "benign_spike", or "none"
- confidence: float between 0.0 and 1.0
- recommended_action: "flag", "hold_for_review", or "no_action"

Rules:
- card_testing: Many small-amount transactions (< INR 50 avg), high decline rate (> 60%), same IP or device.
- bin_attack: Near-sequential card BINs from same prefix, high velocity, moderate-to-high decline rate.
- benign_spike: High velocity but normal amount distribution, low decline rate (e.g., flash sale).
- none: Insufficient evidence to classify despite statistical flag.
- When in doubt between card_testing and bin_attack, examine the sequential_bin_score and amount_mean.
- NEVER recommend blocking — only flag, hold_for_review, or no_action.
- Do not include any text outside the JSON object."""


def build_system_prompt() -> str:
    return SYSTEM_PROMPT


def build_user_prompt(anomaly: AnomalyResult) -> str:
    fv = anomaly.feature_vector
    return f"""ANOMALY WINDOW DETECTED — please classify.

Window: {fv.window_start.isoformat()} -> {fv.window_end.isoformat()}
Transaction count: {fv.txn_count}
Transaction velocity: {fv.txn_velocity:.2f} txns/min
Decline rate: {fv.decline_rate:.1%}
Amount (mean / std / max): INR {fv.amount_mean:.2f} / INR {fv.amount_std:.2f} / INR {fv.amount_max:.2f}
Unique cards: {fv.unique_cards}
Unique IPs: {fv.unique_ips}
BIN concentration (top BIN fraction): {fv.bin_concentration:.1%}
Sequential BIN score (0=random, 1=fully sequential): {fv.sequential_bin_score:.3f}

Statistical anomaly score: {anomaly.anomaly_score:.4f}
Triggered features: {', '.join(anomaly.triggered_features) if anomaly.triggered_features else 'none (soft threshold)'}
Velocity z-score: {anomaly.zscore_velocity:.2f}
Decline rate z-score: {anomaly.zscore_decline:.2f}

Classify this window and explain your reasoning."""
