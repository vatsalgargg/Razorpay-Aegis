"""
Feature engineering layer.

Takes a window of transactions and computes the multivariate feature vector
used by both the statistical detection layer and (summarized) the LLM layer.
"""

from __future__ import annotations

import math
from datetime import datetime
from statistics import mean, stdev
from typing import Sequence

from data.schemas import AttackType, FeatureVector, Transaction, TxnStatus


# ---------------------------------------------------------------------------
# Sequential BIN score
# ---------------------------------------------------------------------------

def _sequential_bin_score(bins: list[str]) -> float:
    """
    Returns a score 0–1 measuring how sequential distinct card BINs are.
    Normal traffic with repeated popular BINs -> 0.0.
    BIN enumeration attack (incrementing BINs: 452301, 452302, ...) -> ~1.0.
    """
    if len(bins) < 5:
        return 0.0
    unique_bins = list(set(bins))
    if len(unique_bins) < 4:
        # Standard traffic with a few popular BINs is not a BIN enumeration attack
        return 0.0
    try:
        ints = sorted(int(b) for b in unique_bins if b.isdigit())
    except ValueError:
        return 0.0
    if len(ints) < 4:
        return 0.0

    diffs = [ints[i + 1] - ints[i] for i in range(len(ints) - 1)]
    # Incremental sequential steps (1 to 3) between distinct BINs
    sequential_diffs = sum(1 for d in diffs if 1 <= d <= 3)
    return sequential_diffs / len(diffs)


# ---------------------------------------------------------------------------
# Main feature computation
# ---------------------------------------------------------------------------

def compute_features(
    window: Sequence[Transaction],
    window_start: datetime,
    window_end: datetime,
) -> FeatureVector:
    """
    Compute all features for a time window of transactions.
    Ground-truth labels are propagated from the window (for evaluation).
    """
    if not window:
        duration_min = max((window_end - window_start).total_seconds() / 60.0, 1e-6)
        return FeatureVector(
            window_start=window_start,
            window_end=window_end,
            txn_count=0,
            txn_velocity=0.0,
            decline_rate=0.0,
            amount_mean=0.0,
            amount_std=0.0,
            amount_max=0.0,
            unique_cards=0,
            unique_ips=0,
            bin_concentration=0.0,
            sequential_bin_score=0.0,
            is_attack=False,
            attack_type=AttackType.NONE,
        )

    txns = list(window)
    duration_min = max((window_end - window_start).total_seconds() / 60.0, 1e-6)

    # Velocity
    txn_velocity = len(txns) / duration_min

    # Decline rate
    failures = sum(1 for t in txns if t.status == TxnStatus.FAILURE)
    decline_rate = failures / len(txns)

    # Amount distribution
    amounts = [t.amount for t in txns]
    amt_mean = mean(amounts)
    amt_std = stdev(amounts) if len(amounts) > 1 else 0.0
    amt_max = max(amounts)

    # Cardinality
    cards = set(f"{t.card_bin}{t.card_last4}" for t in txns)
    ips = set(t.ip_address for t in txns)
    unique_cards = len(cards)
    unique_ips = len(ips)

    # BIN concentration
    bins = [t.card_bin for t in txns]
    bin_counts: dict[str, int] = {}
    for b in bins:
        bin_counts[b] = bin_counts.get(b, 0) + 1
    top_bin_count = max(bin_counts.values())
    bin_concentration = top_bin_count / len(txns)

    # Sequential BIN score
    seq_score = _sequential_bin_score(bins)

    # Ground truth: if ANY txn in window is an attack, window is an attack
    is_attack = any(t.is_attack for t in txns)
    # Majority attack type
    attack_types = [t.attack_type for t in txns if t.is_attack]
    if attack_types:
        from collections import Counter
        majority = Counter(attack_types).most_common(1)[0][0]
        attack_type = majority
    else:
        attack_type = AttackType.NONE

    return FeatureVector(
        window_start=window_start,
        window_end=window_end,
        txn_count=len(txns),
        txn_velocity=round(txn_velocity, 4),
        decline_rate=round(decline_rate, 4),
        amount_mean=round(amt_mean, 2),
        amount_std=round(amt_std, 2),
        amount_max=round(amt_max, 2),
        unique_cards=unique_cards,
        unique_ips=unique_ips,
        bin_concentration=round(bin_concentration, 4),
        sequential_bin_score=round(seq_score, 4),
        is_attack=is_attack,
        attack_type=attack_type,
    )


# ---------------------------------------------------------------------------
# Sliding window builder
# ---------------------------------------------------------------------------

def sliding_windows(
    txns: Sequence[Transaction],
    window_minutes: int = 5,
    step_minutes: int = 1,
) -> list[tuple[datetime, datetime, list[Transaction]]]:
    """
    Returns (window_start, window_end, txns_in_window) tuples
    using a sliding window over the transaction sequence.
    """
    if not txns:
        return []

    sorted_txns = sorted(txns, key=lambda t: t.timestamp)
    start = sorted_txns[0].timestamp
    end = sorted_txns[-1].timestamp

    from datetime import timedelta
    windows = []
    w_start = start

    while w_start <= end:
        w_end = w_start + timedelta(minutes=window_minutes)
        window = [t for t in sorted_txns if w_start <= t.timestamp < w_end]
        windows.append((w_start, w_end, window))
        w_start += timedelta(minutes=step_minutes)

    return windows
