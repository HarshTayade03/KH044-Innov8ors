"""
tests/conftest.py — Pytest configuration and fixtures.
"""

import socket
import ipaddress
from pathlib import Path

import pytest
from src.app.config import settings
from src.app.database import init_db
from src.app.services import embedding
from src.app.services.threat_intel import threat_intel_service


@pytest.fixture(autouse=True)
def setup_database(tmp_path, monkeypatch):
    """Isolate persistent state and prohibit accidental model/feed downloads."""
    monkeypatch.setattr(settings, "database_path", str(tmp_path / "test.db"))
    monkeypatch.setattr(settings, "kev_live", False)
    monkeypatch.setattr(settings, "epss_live", False)
    root = Path(__file__).resolve().parents[1]
    monkeypatch.setattr(settings, "kev_data_path", str(root / "data/cisa_kev_mock.json"))
    monkeypatch.setattr(settings, "epss_data_path", str(root / "data/epss_mock.json"))
    monkeypatch.setattr(embedding, "_model", embedding.FallbackEmbedder())
    monkeypatch.setattr(threat_intel_service, "_kev_mock_cache", None)
    monkeypatch.setattr(threat_intel_service, "_epss_mock_cache", None)

    def guarded_connect(original):
        def connect(sock, address):
            # Windows asyncio implements socketpair via literal loopback TCP.
            if isinstance(address, tuple):
                try:
                    if ipaddress.ip_address(address[0]).is_loopback:
                        return original(sock, address)
                except ValueError:
                    pass
            raise AssertionError("Unit tests must not open external network connections")
        return connect

    monkeypatch.setattr(socket.socket, "connect", guarded_connect(socket.socket.connect))
    monkeypatch.setattr(socket.socket, "connect_ex", guarded_connect(socket.socket.connect_ex))
    init_db()


@pytest.fixture
def finding_factory():
    from src.app.services.normalizer import normalizer_service

    def create(**overrides):
        record = {"name": "SQL Injection", "host": "app.example.test", "path": "/login",
                  "parameter": "username", "severity": "High", "cwe_ids": ["CWE-89"]}
        record.update(overrides)
        return normalizer_service.normalize_record(record, "burp", "batch-test")

    return create
