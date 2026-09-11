"""
tests/conftest.py — Pytest configuration and fixtures.
"""

import pytest
from src.app.database import init_db

@pytest.fixture(autouse=True, scope="session")
def setup_database():
    """Ensure database tables are initialized before running tests."""
    init_db()
