"""Shared pytest fixtures for the CTF PCAP Generator test suite."""

import pytest

from ctf_pcaps.web import create_app


@pytest.fixture()
def app():
    """Create a Flask application configured for testing."""
    app = create_app({"TESTING": True})
    yield app


@pytest.fixture()
def client(app):
    """Create a Flask test client."""
    return app.test_client()
