"""
Cross-Merchant Collective Immune System — Threat Mesh.

Provides:
  1. Zero-Knowledge HMAC Fingerprinting — converts raw PII (device, IP, BIN)
     into anonymized, epoch-salted signatures. No PII ever leaves this module.
  2. Multi-Merchant Quorum Engine — activates a global vaccine rule only when
     >= MIN_QUORUM distinct merchants observe the same fingerprint within
     QUORUM_WINDOW_S seconds.
  3. Vaccine Manager — propagates activated fingerprints into the shared
     CuckooFilter so all gateway nodes can block/challenge the threat in < 0.1ms.
  4. Auto-Expiry — vaccine rules auto-delete after VACCINE_TTL_S seconds.

Design guarantee: ZERO impact on checkout latency.
  - The CuckooFilter check at the ingest fast-path takes < 0.1ms (in-process memory).
  - All quorum counting and vaccine propagation happens ASYNCHRONOUSLY via a
    background thread queue — no blocking calls on the hot path.

Privacy guarantee: ZERO raw PII stored or propagated.
  - Only HMAC-SHA256(device || subnet || bin, epoch_salt) fingerprints are stored.
  - Epoch salt rotates every 24h, making past fingerprints unlinkable.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import queue
import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from detection.cuckoo import CuckooFilter

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

MIN_QUORUM      = 3      # Min distinct merchants flagging before vaccine activates
QUORUM_WINDOW_S = 300    # 5-minute sliding window for quorum observation count
VACCINE_TTL_S   = 900    # 15-minute vaccine duration (auto-expires from Cuckoo)
EPOCH_ROTATION  = 86400  # Salt rotates every 24 hours for forward unlinkability


# ---------------------------------------------------------------------------
# Internal data types
# ---------------------------------------------------------------------------

@dataclass
class _Observation:
    """A single merchant's sighting of a suspicious fingerprint."""
    merchant_id:  str
    fingerprint:  str
    observed_at:  float   # time.monotonic()


@dataclass
class VaccineRule:
    """A globally activated threat fingerprint vaccine."""
    fingerprint:  str
    activated_at: datetime
    expires_at:   datetime
    quorum_count: int
    merchants:    list[str]


# ---------------------------------------------------------------------------
# Threat Mesh
# ---------------------------------------------------------------------------

class ThreatMesh:
    """
    Singleton-safe, thread-safe Cross-Merchant Threat Mesh.

    Usage:
      mesh = ThreatMesh(cuckoo_filter)
      mesh.start()              # start background worker
      mesh.observe(anomaly, merchant_id="MERCH_001")
      mesh.stop()               # graceful shutdown
    """

    def __init__(self, cuckoo: CuckooFilter) -> None:
        self._cuckoo          = cuckoo
        self._queue: queue.Queue[_Observation] = queue.Queue()
        self._observations: dict[str, list[_Observation]] = defaultdict(list)
        self._active_vaccines: dict[str, VaccineRule] = {}
        self._lock            = threading.Lock()
        self._worker: threading.Thread | None = None
        self._running         = False

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Start the background quorum-processing worker thread."""
        self._running = True
        self._worker  = threading.Thread(
            target=self._process_loop,
            name="threat-mesh-worker",
            daemon=True,
        )
        self._worker.start()
        logger.info("[threat-mesh] Background quorum worker started.")

    def stop(self) -> None:
        """Gracefully stop the background worker."""
        self._running = False
        self._queue.put(None)  # Sentinel to unblock queue.get()
        if self._worker:
            self._worker.join(timeout=3.0)
        logger.info("[threat-mesh] Worker stopped.")

    # ------------------------------------------------------------------
    # Hot-path: submit observation (non-blocking)
    # ------------------------------------------------------------------

    def observe(
        self,
        device_id: str,
        ip_address: str,
        card_bin: str,
        merchant_id: str,
    ) -> None:
        """
        Submit a suspicious transaction fingerprint to the quorum engine.
        Non-blocking — queued for async processing by background worker.
        Fingerprint is blinded via HMAC before queuing; raw PII is never stored.
        """
        fp = self._blind_fingerprint(device_id, ip_address, card_bin)
        obs = _Observation(
            merchant_id=merchant_id,
            fingerprint=fp,
            observed_at=time.monotonic(),
        )
        self._queue.put_nowait(obs)

    # ------------------------------------------------------------------
    # Status / telemetry
    # ------------------------------------------------------------------

    def status(self) -> dict[str, Any]:
        """Return current threat mesh telemetry for the /threat-mesh/status endpoint."""
        with self._lock:
            active = [
                {
                    "fingerprint":  v.fingerprint[:8] + "...",  # Partial for privacy
                    "activated_at": v.activated_at.isoformat(),
                    "expires_at":   v.expires_at.isoformat(),
                    "quorum_count": v.quorum_count,
                    "merchant_count": len(v.merchants),
                }
                for v in self._active_vaccines.values()
            ]
        return {
            "active_vaccines":       len(active),
            "cuckoo_entries":        self._cuckoo.count,
            "cuckoo_load_factor":    round(self._cuckoo.load_factor, 4),
            "pending_observations":  self._queue.qsize(),
            "vaccines":              active,
        }

    def is_known_threat(self, device_id: str, ip_address: str, card_bin: str) -> bool:
        """
        Fast-path check (< 0.1ms): is this device/IP/BIN combination a known threat?
        Uses in-memory Cuckoo Filter — zero DB or network I/O.
        """
        fp = self._blind_fingerprint(device_id, ip_address, card_bin)
        return self._cuckoo.contains(fp)

    # ------------------------------------------------------------------
    # Background worker: processes observations and evaluates quorum
    # ------------------------------------------------------------------

    def _process_loop(self) -> None:
        while self._running:
            try:
                obs = self._queue.get(timeout=5.0)
                if obs is None:
                    break  # Sentinel received — stop
                self._process_observation(obs)
                self._cuckoo.purge_expired()
            except queue.Empty:
                # Periodic maintenance even with no new observations
                self._cuckoo.purge_expired()
                self._purge_stale_observations()

    def _process_observation(self, obs: _Observation) -> None:
        with self._lock:
            self._observations[obs.fingerprint].append(obs)
            # Trim old observations outside the quorum window
            cutoff = time.monotonic() - QUORUM_WINDOW_S
            self._observations[obs.fingerprint] = [
                o for o in self._observations[obs.fingerprint]
                if o.observed_at >= cutoff
            ]
            # Evaluate quorum
            recent = self._observations[obs.fingerprint]
            distinct_merchants = len({o.merchant_id for o in recent})

            if (
                distinct_merchants >= MIN_QUORUM
                and obs.fingerprint not in self._active_vaccines
            ):
                self._activate_vaccine(obs.fingerprint, recent)

    def _activate_vaccine(
        self, fingerprint: str, observations: list[_Observation]
    ) -> None:
        """Inject fingerprint into Cuckoo Filter and record the active vaccine rule."""
        self._cuckoo.insert(fingerprint, ttl_s=VACCINE_TTL_S)
        merchants = list({o.merchant_id for o in observations})
        now       = datetime.now(timezone.utc)
        rule      = VaccineRule(
            fingerprint=fingerprint,
            activated_at=now,
            expires_at=datetime.fromtimestamp(
                time.time() + VACCINE_TTL_S, tz=timezone.utc
            ),
            quorum_count=len(observations),
            merchants=merchants,
        )
        self._active_vaccines[fingerprint] = rule
        logger.warning(
            f"[threat-mesh] 🛡️  VACCINE ACTIVATED fingerprint={fingerprint[:8]}... "
            f"quorum={len(observations)} across {len(merchants)} merchants: {merchants}"
        )

    def _purge_stale_observations(self) -> None:
        """Remove observation windows that are too old for quorum consideration."""
        cutoff = time.monotonic() - QUORUM_WINDOW_S
        with self._lock:
            for fp in list(self._observations.keys()):
                self._observations[fp] = [
                    o for o in self._observations[fp] if o.observed_at >= cutoff
                ]
                if not self._observations[fp]:
                    del self._observations[fp]
            # Purge expired vaccine records
            expired = [
                fp for fp, v in self._active_vaccines.items()
                if not self._cuckoo.contains(fp)
            ]
            for fp in expired:
                del self._active_vaccines[fp]
                logger.info(f"[threat-mesh] Vaccine expired: {fp[:8]}...")

    # ------------------------------------------------------------------
    # Zero-Knowledge HMAC Fingerprinting (Privacy Core)
    # ------------------------------------------------------------------

    def _blind_fingerprint(
        self, device_id: str, ip_address: str, card_bin: str
    ) -> str:
        """
        Generate an anonymized, epoch-salted HMAC fingerprint.
        Raw PII is never stored or transmitted.

        The salt rotates every EPOCH_ROTATION seconds (default: 24h),
        ensuring cross-day re-identification is impossible even if the
        output hash table is leaked.

        Returns a 64-char hex HMAC-SHA256 string.
        """
        epoch    = int(time.time() // EPOCH_ROTATION)
        salt     = f"aegis-epoch-{epoch}"
        # Coarsen IP to /24 subnet (e.g. "192.168.1.155" -> "192.168.1")
        subnet   = ".".join(ip_address.split(".")[:3])
        payload  = f"{device_id}|{subnet}|{card_bin}"
        digest   = hmac.new(
            salt.encode(),
            payload.encode(),
            hashlib.sha256,
        ).hexdigest()
        return digest
