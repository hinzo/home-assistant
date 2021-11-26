"""Test configuration for http."""
import pytest


@pytest.fixture
def aiohttp_client(loop, aiohttp_client, socket_enabled):
    """Return aiohttp_client and allow opening sockets."""
    return aiohttp_client
