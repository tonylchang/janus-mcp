from __future__ import annotations

import pytest

from janus_mcp.config import Settings
from janus_mcp.redaction import RedactionStats
from support import FakeKube, make_audit, make_settings


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture
def settings(tmp_path) -> Settings:
    return make_settings(tmp_path)


@pytest.fixture
def fake_kube() -> FakeKube:
    return FakeKube()


@pytest.fixture
def stats() -> RedactionStats:
    return RedactionStats()


@pytest.fixture
def server(settings, fake_kube):
    from janus_mcp.server import build_server

    return build_server(settings, fake_kube, make_audit(settings))
