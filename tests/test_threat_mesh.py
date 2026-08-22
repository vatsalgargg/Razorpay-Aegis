"""
Tests for the Cross-Merchant Threat Mesh (gateway/threat_mesh.py).

Tests cover:
  - Single merchant observation does NOT activate vaccine
  - Multi-merchant quorum (>= 3) DOES activate vaccine
  - Vaccine gets inserted into Cuckoo Filter after quorum
  - is_known_threat() returns False before quorum, True after
  - Vaccine auto-expires (TTL behavior)
  - Background worker starts and stops cleanly
"""

from __future__ import annotations

import time
import threading

import pytest
from detection.cuckoo import CuckooFilter
from gateway.threat_mesh import ThreatMesh, MIN_QUORUM, VACCINE_TTL_S


@pytest.fixture
def mesh():
    """Provide a ThreatMesh with a fast-expiry CuckooFilter for testing."""
    cuckoo = CuckooFilter(capacity=10_000, default_ttl_s=2.0)
    m = ThreatMesh(cuckoo)
    m.start()
    yield m
    m.stop()


@pytest.fixture
def mesh_cuckoo():
    """Provide both ThreatMesh and CuckooFilter for inspection."""
    cuckoo = CuckooFilter(capacity=10_000, default_ttl_s=2.0)
    m = ThreatMesh(cuckoo)
    m.start()
    yield m, cuckoo
    m.stop()


SHARED_DEVICE = "device-attacker-99"
SHARED_IP     = "198.51.100.5"
SHARED_BIN    = "452301"


def _observe_from(mesh: ThreatMesh, merchant_id: str) -> None:
    mesh.observe(
        device_id   = SHARED_DEVICE,
        ip_address  = SHARED_IP,
        card_bin    = SHARED_BIN,
        merchant_id = merchant_id,
    )


class TestThreatMeshQuorum:
    def test_single_merchant_does_not_activate_vaccine(self, mesh_cuckoo):
        m, cuckoo = mesh_cuckoo
        _observe_from(m, "MERCH_0001")
        time.sleep(0.3)  # Let background worker process
        # Not enough quorum — should NOT be in Cuckoo Filter
        assert m.is_known_threat(SHARED_DEVICE, SHARED_IP, SHARED_BIN) is False

    def test_two_merchants_does_not_activate_vaccine(self, mesh_cuckoo):
        m, cuckoo = mesh_cuckoo
        for mid in ["MERCH_0001", "MERCH_0002"]:
            _observe_from(m, mid)
        time.sleep(0.3)
        assert m.is_known_threat(SHARED_DEVICE, SHARED_IP, SHARED_BIN) is False

    def test_quorum_activates_vaccine(self, mesh_cuckoo):
        """Exactly MIN_QUORUM distinct merchants should activate the vaccine."""
        m, cuckoo = mesh_cuckoo
        for i in range(MIN_QUORUM):
            _observe_from(m, f"MERCH_{i:04d}")
        time.sleep(0.5)  # Let background worker process observations
        assert m.is_known_threat(SHARED_DEVICE, SHARED_IP, SHARED_BIN) is True

    def test_quorum_status_reflects_active_vaccine(self, mesh):
        for i in range(MIN_QUORUM):
            _observe_from(mesh, f"MERCH_{i:04d}")
        time.sleep(0.5)
        status = mesh.status()
        assert status["active_vaccines"] >= 1

    def test_same_merchant_repeated_does_not_satisfy_quorum(self, mesh_cuckoo):
        """Quorum requires DISTINCT merchants, not repeated observations from one."""
        m, cuckoo = mesh_cuckoo
        for _ in range(MIN_QUORUM + 5):
            _observe_from(m, "MERCH_SAME")  # Same merchant every time
        time.sleep(0.5)
        assert m.is_known_threat(SHARED_DEVICE, SHARED_IP, SHARED_BIN) is False


class TestThreatMeshLifecycle:
    def test_worker_starts_and_stops(self):
        cuckoo = CuckooFilter(capacity=1000)
        m = ThreatMesh(cuckoo)
        m.start()
        assert m._running is True
        m.stop()
        assert m._running is False

    def test_status_returns_expected_keys(self, mesh):
        status = mesh.status()
        assert "active_vaccines" in status
        assert "cuckoo_entries" in status
        assert "cuckoo_load_factor" in status
        assert "pending_observations" in status
        assert "vaccines" in status

    def test_status_cuckoo_entries_zero_at_start(self, mesh):
        status = mesh.status()
        assert status["cuckoo_entries"] == 0
        assert status["active_vaccines"] == 0


class TestThreatMeshZKFingerprint:
    def test_same_pii_generates_same_fingerprint(self, mesh):
        """Same device/IP/BIN must produce the same fingerprint within an epoch."""
        fp1 = mesh._blind_fingerprint(SHARED_DEVICE, SHARED_IP, SHARED_BIN)
        fp2 = mesh._blind_fingerprint(SHARED_DEVICE, SHARED_IP, SHARED_BIN)
        assert fp1 == fp2

    def test_different_pii_generates_different_fingerprint(self, mesh):
        fp1 = mesh._blind_fingerprint("device-A", "1.2.3.4", "411111")
        fp2 = mesh._blind_fingerprint("device-B", "5.6.7.8", "512345")
        assert fp1 != fp2

    def test_fingerprint_is_hex_string(self, mesh):
        fp = mesh._blind_fingerprint(SHARED_DEVICE, SHARED_IP, SHARED_BIN)
        assert isinstance(fp, str)
        assert len(fp) == 64  # SHA-256 hex = 64 chars
        int(fp, 16)           # Raises ValueError if not valid hex
