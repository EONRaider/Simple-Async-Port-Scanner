import asyncio
from collections.abc import AsyncIterator

import pytest_asyncio


@pytest_asyncio.fixture
async def open_port() -> AsyncIterator[int]:
    """An ephemeral TCP port on 127.0.0.1 with a listener accepting
    (and immediately dropping) connections, so a connect attempt
    against it always succeeds."""
    server = await asyncio.start_server(
        lambda reader, writer: writer.close(), "127.0.0.1", 0
    )
    port = server.sockets[0].getsockname()[1]
    async with server:
        yield port


@pytest_asyncio.fixture
async def closed_port() -> int:
    """An ephemeral TCP port on 127.0.0.1 that is bound and then
    immediately released, so a connect attempt against it reliably
    raises ConnectionRefusedError."""
    server = await asyncio.start_server(
        lambda reader, writer: None, "127.0.0.1", 0
    )
    port = server.sockets[0].getsockname()[1]
    server.close()
    await server.wait_closed()
    return port
