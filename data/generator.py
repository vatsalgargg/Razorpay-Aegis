"""
Synthetic transaction stream generator.

Produces labeled training + held-out test data with injected attack windows.
Ground-truth labels are embedded at generation time — never inferred post-hoc.

Attack patterns:
  card_testing : burst of small-amount txns, high decline rate, same IP/device
  bin_attack   : near-sequential card BINs, high velocity, geographic clustering
"""

from __future__ import annotations

import hashlib
import random
import string
import uuid
from datetime import datetime, timedelta
from typing import Generator

import numpy as np

from data.schemas import AttackType, Transaction, TxnStatus


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

MERCHANT_IDS = [f"MERCH_{i:04d}" for i in range(1, 21)]
NORMAL_BINS = [
    "411111", "424242", "512345", "601100", "370000",
    "378282", "400000", "431274", "471612", "508500",
]
ATTACK_BIN_BASE = "452301"  # BIN used during BIN attacks


def _random_ip(seed: int | None = None) -> str:
    rng = random.Random(seed)
    return f"{rng.randint(1,254)}.{rng.randint(0,255)}.{rng.randint(0,255)}.{rng.randint(1,254)}"


def _random_device(seed: int | None = None) -> str:
    rng = random.Random(seed)
    return "DEV_" + "".join(rng.choices(string.hexdigits[:16], k=8)).upper()


def _sequential_bin(base: str, offset: int) -> str:
    """Return a BIN incremented by offset (always stays 6 digits via modulo wrap)."""
    num = (int(base) + offset) % 1_000_000
    return str(num).zfill(6)


# ---------------------------------------------------------------------------
# Normal traffic generator
# ---------------------------------------------------------------------------

def generate_normal_txns(
    start: datetime,
    duration_minutes: int = 60,
    avg_rate: float = 5.0,   # txns per minute
    decline_rate: float = 0.05,
    rng: random.Random | None = None,
) -> list[Transaction]:
    """Poisson-distributed normal traffic."""
    if rng is None:
        rng = random.Random(42)

    txns: list[Transaction] = []
    t = start
    end = start + timedelta(minutes=duration_minutes)

    while t < end:
        # Poisson inter-arrival: mean = 60/avg_rate seconds
        inter = rng.expovariate(avg_rate / 60.0)
        t += timedelta(seconds=inter)
        if t >= end:
            break

        status = TxnStatus.FAILURE if rng.random() < decline_rate else TxnStatus.SUCCESS
        txns.append(Transaction(
            txn_id=str(uuid.uuid4()),
            timestamp=t,
            card_bin=rng.choice(NORMAL_BINS),
            card_last4=f"{rng.randint(0, 9999):04d}",
            amount=round(rng.lognormvariate(8.5, 1.0), 2),  # ~₹500–₹50 000 range
            ip_address=_random_ip(rng.randint(0, 9999)),
            device_id=_random_device(rng.randint(0, 9999)),
            merchant_id=rng.choice(MERCHANT_IDS),
            status=status,
            is_attack=False,
            attack_type=AttackType.NONE,
        ))

    return txns


# ---------------------------------------------------------------------------
# Card-testing attack generator
# ---------------------------------------------------------------------------

def generate_card_testing_attack(
    start: datetime,
    duration_minutes: int = 2,
    burst_size: int = 35,
    decline_rate: float = 0.75,
    rng: random.Random | None = None,
) -> list[Transaction]:
    """
    Card testing: many small-amount txns, high decline rate,
    same IP + device (attacker probing stolen cards).
    """
    if rng is None:
        rng = random.Random(99)

    window_id = str(uuid.uuid4())
    attack_ip = _random_ip(rng.randint(10000, 99999))
    attack_device = _random_device(rng.randint(10000, 99999))
    attack_bin = rng.choice(NORMAL_BINS)

    txns: list[Transaction] = []
    for i in range(burst_size):
        t = start + timedelta(seconds=rng.uniform(0, duration_minutes * 60))
        status = TxnStatus.FAILURE if rng.random() < decline_rate else TxnStatus.SUCCESS
        txns.append(Transaction(
            txn_id=str(uuid.uuid4()),
            timestamp=t,
            card_bin=attack_bin,
            card_last4=f"{rng.randint(0, 9999):04d}",
            amount=round(rng.uniform(1.0, 10.0), 2),  # ₹1–₹10 (card testing signature)
            ip_address=attack_ip,
            device_id=attack_device,
            merchant_id=rng.choice(MERCHANT_IDS),
            status=status,
            is_attack=True,
            attack_type=AttackType.CARD_TESTING,
            attack_window_id=window_id,
        ))

    return sorted(txns, key=lambda x: x.timestamp)


# ---------------------------------------------------------------------------
# BIN attack generator
# ---------------------------------------------------------------------------

def generate_bin_attack(
    start: datetime,
    duration_minutes: int = 3,
    burst_size: int = 40,
    decline_rate: float = 0.60,
    rng: random.Random | None = None,
) -> list[Transaction]:
    """
    BIN attack: near-sequential card numbers from the same BIN prefix,
    high velocity, coming from a small cluster of IPs.
    """
    if rng is None:
        rng = random.Random(77)

    window_id = str(uuid.uuid4())
    # Small cluster of attacker IPs (1–3 IPs)
    attack_ips = [_random_ip(rng.randint(20000, 29999)) for _ in range(rng.randint(1, 3))]

    txns: list[Transaction] = []
    for i in range(burst_size):
        t = start + timedelta(seconds=rng.uniform(0, duration_minutes * 60))
        bin_offset = i + rng.randint(0, 2)  # Near-sequential, slight jitter
        status = TxnStatus.FAILURE if rng.random() < decline_rate else TxnStatus.SUCCESS
        txns.append(Transaction(
            txn_id=str(uuid.uuid4()),
            timestamp=t,
            card_bin=_sequential_bin(ATTACK_BIN_BASE, bin_offset),
            card_last4=f"{rng.randint(0, 9999):04d}",
            amount=round(rng.lognormvariate(6.5, 0.5), 2),  # More normal amounts
            ip_address=rng.choice(attack_ips),
            device_id=_random_device(rng.randint(20000, 29999)),
            merchant_id=rng.choice(MERCHANT_IDS),
            status=status,
            is_attack=True,
            attack_type=AttackType.BIN_ATTACK,
            attack_window_id=window_id,
        ))

    return sorted(txns, key=lambda x: x.timestamp)


# ---------------------------------------------------------------------------
# Full dataset builder
# ---------------------------------------------------------------------------

def build_dataset(
    total_duration_minutes: int = 480,    # 8 hours of synthetic history
    num_card_testing_attacks: int = 10,
    num_bin_attacks: int = 8,
    seed: int = 42,
) -> dict[str, list[Transaction]]:
    """
    Returns a dict with 'train' and 'test' splits (70/30).
    Attack windows are injected at random times and labeled at generation time.
    """
    rng = random.Random(seed)
    start = datetime(2024, 1, 15, 0, 0, 0)

    # --- Normal traffic ---
    all_txns = generate_normal_txns(
        start=start,
        duration_minutes=total_duration_minutes,
        avg_rate=5.0,
        decline_rate=0.05,
        rng=rng,
    )

    # --- Inject attacks at random times ---
    attack_txns: list[Transaction] = []
    attack_starts: list[datetime] = []

    for i in range(num_card_testing_attacks):
        offset_min = rng.randint(10, total_duration_minutes - 10)
        atk_start = start + timedelta(minutes=offset_min)
        attack_starts.append(atk_start)
        attack_txns.extend(
            generate_card_testing_attack(
                start=atk_start,
                rng=random.Random(seed + i * 100),
            )
        )

    for i in range(num_bin_attacks):
        offset_min = rng.randint(10, total_duration_minutes - 10)
        atk_start = start + timedelta(minutes=offset_min)
        attack_starts.append(atk_start)
        attack_txns.extend(
            generate_bin_attack(
                start=atk_start,
                rng=random.Random(seed + i * 200 + 1000),
            )
        )

    combined = sorted(all_txns + attack_txns, key=lambda x: x.timestamp)

    # --- Train/test split (70/30 by time) ---
    split_idx = int(len(combined) * 0.70)
    # Round split to a clean time boundary
    split_time = combined[split_idx].timestamp

    train = [t for t in combined if t.timestamp < split_time]
    test = [t for t in combined if t.timestamp >= split_time]

    print(f"[generator] Total txns: {len(combined)}")
    print(f"[generator] Train: {len(train)} | Test: {len(test)}")
    print(f"[generator] Attack txns in train: {sum(1 for t in train if t.is_attack)}")
    print(f"[generator] Attack txns in test:  {sum(1 for t in test if t.is_attack)}")

    return {"train": train, "test": test}


# ---------------------------------------------------------------------------
# Stream generator (for live simulation)
# ---------------------------------------------------------------------------

def stream_transactions(
    txns: list[Transaction],
    realtime: bool = False,
    speedup: float = 60.0,   # 1 simulated minute = 1 real second
) -> Generator[Transaction, None, None]:
    """Yields transactions in timestamp order, optionally with time-compressed delays."""
    import time

    prev_ts: datetime | None = None
    for txn in sorted(txns, key=lambda x: x.timestamp):
        if realtime and prev_ts is not None:
            delta = (txn.timestamp - prev_ts).total_seconds() / speedup
            if delta > 0:
                time.sleep(min(delta, 2.0))  # Cap sleep to 2s for demo
        prev_ts = txn.timestamp
        yield txn


if __name__ == "__main__":
    dataset = build_dataset()
    print("Sample train txn:", dataset["train"][0].model_dump_json(indent=2))
