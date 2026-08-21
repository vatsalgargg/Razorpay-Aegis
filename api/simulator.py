"""
Transaction stream simulator.

Replays synthetic test-set data against the running API.
Supports:
  --mode normal        Only normal traffic
  --mode attack        Inject a card-testing attack mid-stream
  --mode bin           Inject a BIN attack mid-stream
  --mode both          Normal traffic with both attack types
  --kill-llm           Set FORCE_LLM_TIMEOUT=true for the server (via env notice)
  --speed FLOAT        Speedup factor (default 60 = 1 min ≈ 1 sec)

Usage:
  python -m api.simulator --mode both
  python -m api.simulator --mode attack --kill-llm
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from datetime import datetime, timedelta
from pathlib import Path

import requests

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from data.generator import (
    generate_bin_attack,
    generate_card_testing_attack,
    generate_normal_txns,
    stream_transactions,
)
from data.schemas import Transaction

BASE_URL = os.getenv("API_URL", "http://localhost:8000")


def _post_txn(txn: Transaction) -> dict:
    try:
        r = requests.post(
            f"{BASE_URL}/ingest",
            json=txn.model_dump(mode="json"),
            timeout=10,
        )
        r.raise_for_status()
        return r.json()
    except Exception as e:
        return {"error": str(e)}


def run_simulation(mode: str, speedup: float, kill_llm: bool) -> None:
    if kill_llm:
        print(
            "\n⚠️  --kill-llm mode: set FORCE_LLM_TIMEOUT=true in your server's .env "
            "and restart it to simulate LLM timeout fallback.\n"
        )

    start = datetime(2024, 3, 1, 10, 0, 0)
    import random

    normal = generate_normal_txns(
        start=start,
        duration_minutes=20,
        avg_rate=5.0,
        rng=random.Random(200),
    )

    attack_txns: list[Transaction] = []
    if mode in ("attack", "both"):
        attack_txns += generate_card_testing_attack(
            start=start + timedelta(minutes=8),
            rng=random.Random(300),
        )
    if mode in ("bin", "both"):
        attack_txns += generate_bin_attack(
            start=start + timedelta(minutes=14),
            rng=random.Random(400),
        )

    all_txns = sorted(normal + attack_txns, key=lambda t: t.timestamp)
    total = len(all_txns)
    attacks = sum(1 for t in all_txns if t.is_attack)

    print(f"[simulator] Mode={mode} | Total txns={total} | Attack txns={attacks}")
    print(f"[simulator] Speedup={speedup}x | API={BASE_URL}")
    print("[simulator] Starting stream... (Ctrl+C to stop)\n")

    prev_ts: datetime | None = None
    for i, txn in enumerate(all_txns, 1):
        if prev_ts is not None:
            delay = (txn.timestamp - prev_ts).total_seconds() / speedup
            if delay > 0:
                time.sleep(min(delay, 0.20))
        prev_ts = txn.timestamp

        result = _post_txn(txn)
        tag = "[ATTACK]" if txn.is_attack else "        "
        alert_tag = ""
        if result.get("is_anomaly"):
            alert = result.get("alert") or {}
            fallback_label = "[FALLBACK]" if not alert.get("llm_used") else "[LLM]"
            alert_tag = (
                f" -> [ALERT: {alert.get('attack_type','?').upper()}] "
                f"(conf={alert.get('confidence',0):.2f}) "
                f"{fallback_label}"
            )

        print(f"[{i:04d}/{total}] {tag} {txn.timestamp.strftime('%H:%M:%S')} "
              f"INR {txn.amount:>8.2f} | score={result.get('anomaly_score',0):.3f}{alert_tag}")

    print("\n[simulator] Stream complete.")
    # Print final metrics
    try:
        m = requests.get(f"{BASE_URL}/metrics", timeout=5).json()
        print(f"\nLive Metrics:")
        print(f"   Alerts total : {m.get('alerts_total')}")
        print(f"   TP           : {m.get('tp')}")
        print(f"   FP           : {m.get('fp')}")
        print(f"   Precision    : {m.get('precision'):.4f}")
        print(f"   FP Cost      : INR {m.get('fp_cost_inr'):.2f}")
    except Exception:
        pass


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Razorpay Risk Manager Stream Simulator")
    parser.add_argument("--mode", choices=["normal", "attack", "bin", "both"], default="both")
    parser.add_argument("--kill-llm", action="store_true", help="Print instructions to force LLM timeout")
    parser.add_argument("--speed", type=float, default=60.0, help="Simulation speedup factor")
    args = parser.parse_args()

    run_simulation(mode=args.mode, speedup=args.speed, kill_llm=args.kill_llm)
