"""
Unit tests for the in-memory Cuckoo Filter (detection/cuckoo.py).

Tests cover:
  - Insert and contains (basic correctness)
  - Delete (true deletion, unlike Bloom filters)
  - TTL expiry (auto-expiry of threat fingerprints)
  - False positive rate (< 1% at typical load)
  - Thread safety (concurrent inserts from multiple threads)
"""

from __future__ import annotations

import time
import threading

import pytest
from detection.cuckoo import CuckooFilter


class TestCuckooFilterBasic:
    def test_insert_and_contains(self):
        cf = CuckooFilter(capacity=1000)
        cf.insert("device-abc")
        assert cf.contains("device-abc") is True

    def test_not_contains_unseen(self):
        cf = CuckooFilter(capacity=1000)
        cf.insert("device-abc")
        # An unseen item should not be in the filter
        # (with extremely high probability for a small filter)
        assert cf.contains("completely-different-item-xyz-999") is False

    def test_delete_removes_item(self):
        cf = CuckooFilter(capacity=1000)
        cf.insert("device-abc")
        assert cf.contains("device-abc") is True
        deleted = cf.delete("device-abc")
        assert deleted is True
        assert cf.contains("device-abc") is False

    def test_delete_returns_false_for_absent(self):
        cf = CuckooFilter(capacity=1000)
        result = cf.delete("never-inserted")
        assert result is False

    def test_count_increments_on_insert(self):
        cf = CuckooFilter(capacity=1000)
        assert cf.count == 0
        cf.insert("a")
        assert cf.count == 1
        cf.insert("b")
        assert cf.count == 2

    def test_count_decrements_on_delete(self):
        cf = CuckooFilter(capacity=1000)
        cf.insert("device-x")
        assert cf.count == 1
        cf.delete("device-x")
        assert cf.count == 0

    def test_multiple_distinct_inserts(self):
        cf = CuckooFilter(capacity=10000)
        items = [f"device-{i}" for i in range(100)]
        for item in items:
            cf.insert(item)
        for item in items:
            assert cf.contains(item), f"{item} not found after insert"

    def test_load_factor_increases(self):
        cf = CuckooFilter(capacity=1000)
        assert cf.load_factor == 0.0
        for i in range(10):
            cf.insert(f"item-{i}")
        assert cf.load_factor > 0.0


class TestCuckooFilterTTL:
    def test_expired_entry_not_found(self):
        cf = CuckooFilter(capacity=1000, default_ttl_s=0.05)  # 50ms TTL
        cf.insert("short-lived")
        assert cf.contains("short-lived") is True
        time.sleep(0.1)  # Wait for expiry
        assert cf.contains("short-lived") is False

    def test_purge_expired_removes_dead_entries(self):
        cf = CuckooFilter(capacity=1000, default_ttl_s=0.05)
        for i in range(5):
            cf.insert(f"expiring-{i}")
        assert cf.count == 5
        time.sleep(0.1)
        removed = cf.purge_expired()
        assert removed == 5
        assert cf.count == 0

    def test_long_ttl_entry_survives(self):
        cf = CuckooFilter(capacity=1000)
        cf.insert("long-lived", ttl_s=900)
        time.sleep(0.1)
        assert cf.contains("long-lived") is True


class TestCuckooFilterFalsePositiveRate:
    def test_false_positive_rate_low(self):
        """FP rate should be < 1% for 1000 items in a 10000 capacity filter."""
        cf = CuckooFilter(capacity=10_000)
        inserted = [f"real-threat-{i}" for i in range(1000)]
        for item in inserted:
            cf.insert(item)
        # Test 1000 items that were NOT inserted
        not_inserted = [f"clean-device-{i}" for i in range(1000)]
        false_positives = sum(1 for item in not_inserted if cf.contains(item))
        fp_rate = false_positives / len(not_inserted)
        assert fp_rate < 0.01, f"FP rate too high: {fp_rate:.2%}"


class TestCuckooFilterThreadSafety:
    def test_concurrent_inserts(self):
        """Multiple threads inserting simultaneously should not cause data corruption."""
        cf     = CuckooFilter(capacity=100_000)
        errors = []

        def insert_batch(thread_id: int):
            try:
                for i in range(50):
                    cf.insert(f"thread-{thread_id}-item-{i}")
            except Exception as e:
                errors.append(str(e))

        threads = [threading.Thread(target=insert_batch, args=(tid,)) for tid in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors, f"Thread errors: {errors}"
        # All 10x50 = 500 items should be present
        for tid in range(10):
            for i in range(50):
                assert cf.contains(f"thread-{tid}-item-{i}"), \
                    f"Missing thread-{tid}-item-{i}"
