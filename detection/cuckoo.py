"""
In-memory Cuckoo Filter for fast threat fingerprint lookups.

Used by the Cross-Merchant Collective Immune System to check incoming
transactions against known attacker fingerprints in < 0.1ms.

Design:
  - O(1) amortized insert, lookup, and DELETE (unlike Bloom filters which cannot delete)
  - Uses two hash positions + fingerprint storage in fixed-size buckets
  - Supports TTL-based automatic expiry of threat fingerprints
  - False positive rate < 0.5% for up to 1,000,000 entries at 4 fingerprints/bucket

Usage:
  cf = CuckooFilter(capacity=1_000_000)
  cf.insert("attacker_fingerprint_a1b2c3")
  assert cf.contains("attacker_fingerprint_a1b2c3")
  cf.delete("attacker_fingerprint_a1b2c3")
"""

from __future__ import annotations

import hashlib
import logging
import threading
import time
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)

BUCKET_SIZE   = 4
MAX_EVICTIONS = 500
DEFAULT_TTL_S = 900  # 15 minutes


@dataclass
class _Entry:
    fingerprint: str
    expires_at: float


class CuckooFilter:
    """Thread-safe in-memory Cuckoo Filter with TTL support."""

    def __init__(
        self,
        capacity: int = 1_000_000,
        bucket_size: int = BUCKET_SIZE,
        default_ttl_s: float = DEFAULT_TTL_S,
    ) -> None:
        self._num_buckets   = max(1, capacity // bucket_size)
        self._bucket_size   = bucket_size
        self._default_ttl_s = default_ttl_s
        self._buckets: list[list[_Entry]] = [[] for _ in range(self._num_buckets)]
        self._lock  = threading.Lock()
        self._count = 0

    def insert(self, item: str, ttl_s: Optional[float] = None) -> bool:
        ttl        = ttl_s if ttl_s is not None else self._default_ttl_s
        fp         = _fingerprint(item)
        i1         = _bucket_index(item, self._num_buckets)
        i2         = _alt_index(i1, fp, self._num_buckets)
        expires_at = time.monotonic() + ttl

        with self._lock:
            self._evict_expired(i1, i2)
            if self._try_insert(i1, fp, expires_at):
                return True
            if self._try_insert(i2, fp, expires_at):
                return True
            return self._kickout_insert(i1, fp, expires_at)

    def contains(self, item: str) -> bool:
        fp  = _fingerprint(item)
        i1  = _bucket_index(item, self._num_buckets)
        i2  = _alt_index(i1, fp, self._num_buckets)
        now = time.monotonic()
        with self._lock:
            for idx in (i1, i2):
                for e in self._buckets[idx]:
                    if e.fingerprint == fp and e.expires_at > now:
                        return True
        return False

    def delete(self, item: str) -> bool:
        fp = _fingerprint(item)
        i1 = _bucket_index(item, self._num_buckets)
        i2 = _alt_index(i1, fp, self._num_buckets)
        with self._lock:
            for idx in (i1, i2):
                bucket = self._buckets[idx]
                for e in bucket:
                    if e.fingerprint == fp:
                        bucket.remove(e)
                        self._count -= 1
                        return True
        return False

    def purge_expired(self) -> int:
        now = time.monotonic()
        removed = 0
        with self._lock:
            for bucket in self._buckets:
                before    = len(bucket)
                bucket[:] = [e for e in bucket if e.expires_at > now]
                removed  += before - len(bucket)
        self._count = max(0, self._count - removed)
        if removed:
            logger.debug(f"[cuckoo] Purged {removed} expired fingerprints.")
        return removed

    @property
    def count(self) -> int:
        return self._count

    @property
    def load_factor(self) -> float:
        total = self._num_buckets * self._bucket_size
        return self._count / total if total > 0 else 0.0

    # internal
    def _try_insert(self, idx: int, fp: str, expires_at: float) -> bool:
        bucket = self._buckets[idx]
        if len(bucket) < self._bucket_size:
            bucket.append(_Entry(fingerprint=fp, expires_at=expires_at))
            self._count += 1
            return True
        return False

    def _evict_expired(self, i1: int, i2: int) -> None:
        now = time.monotonic()
        for idx in (i1, i2):
            bucket    = self._buckets[idx]
            before    = len(bucket)
            bucket[:] = [e for e in bucket if e.expires_at > now]
            self._count -= before - len(bucket)

    def _kickout_insert(self, start_idx: int, fp: str, expires_at: float) -> bool:
        import random
        cur_idx = start_idx
        cur_fp  = fp
        cur_exp = expires_at
        for _ in range(MAX_EVICTIONS):
            bucket   = self._buckets[cur_idx]
            pos      = random.randrange(len(bucket))
            evicted  = bucket[pos]
            bucket[pos] = _Entry(fingerprint=cur_fp, expires_at=cur_exp)
            alt = _alt_index(cur_idx, evicted.fingerprint, self._num_buckets)
            if len(self._buckets[alt]) < self._bucket_size:
                self._buckets[alt].append(evicted)
                self._count += 1
                return True
            cur_idx = alt
            cur_fp  = evicted.fingerprint
            cur_exp = evicted.expires_at
        logger.warning("[cuckoo] Insert failed: filter full.")
        return False


def _fingerprint(item: str) -> str:
    h  = hashlib.sha256(item.encode()).hexdigest()
    fp = h[:4]
    return fp if fp != "0000" else "0001"


def _bucket_index(item: str, num_buckets: int) -> int:
    digest = hashlib.sha256(item.encode()).digest()
    return int.from_bytes(digest[:4], "big") % num_buckets


def _alt_index(primary: int, fp: str, num_buckets: int) -> int:
    fp_hash = int(hashlib.sha256(fp.encode()).digest()[:4].hex(), 16)
    return (primary ^ fp_hash) % num_buckets
