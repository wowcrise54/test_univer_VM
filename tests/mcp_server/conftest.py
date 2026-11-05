from __future__ import annotations

import pytest

from mcp_server.principal import current_principal
from tests.mcp_server.fakes import TEST_PRINCIPAL


@pytest.fixture(autouse=True)
def token_principal():
    """Tools always run for a token principal; the HTTP guard sets it in production."""
    marker = current_principal.set(TEST_PRINCIPAL)
    try:
        yield TEST_PRINCIPAL
    finally:
        current_principal.reset(marker)
