import socket
from unittest.mock import AsyncMock, patch

from async_port_scanner.core import AsyncTCPScanner


async def test_open_port_is_reported_open(open_port):
    scanner = AsyncTCPScanner(
        targets=("127.0.0.1",), ports=(open_port,), timeout=2.0
    )
    await scanner._run()
    state, _service, reason = scanner.results["127.0.0.1"][open_port]
    assert state == "open"
    assert reason == "SYN/ACK"


async def test_closed_port_is_reported_closed(closed_port):
    scanner = AsyncTCPScanner(
        targets=("127.0.0.1",), ports=(closed_port,), timeout=2.0
    )
    await scanner._run()
    state, _service, reason = scanner.results["127.0.0.1"][closed_port]
    assert state == "closed"
    assert reason == "Connection refused"


async def test_multi_target_multi_port_covers_cartesian_product(
    open_port, closed_port
):
    targets = ("127.0.0.1", "localhost")
    ports = (open_port, closed_port)
    scanner = AsyncTCPScanner(targets=targets, ports=ports, timeout=2.0)
    await scanner._run()

    assert set(scanner.results) == set(targets)
    for target in targets:
        assert set(scanner.results[target]) == set(ports)
        assert scanner.results[target][open_port][0] == "open"
        assert scanner.results[target][closed_port][0] == "closed"


async def test_connection_refused_is_reported_deterministically():
    """Supplements test_closed_port_is_reported_closed, which relies on
    a released-but-not-yet-reused ephemeral port: mocks the refusal
    directly so this assertion can't flake on port reuse timing."""
    scanner = AsyncTCPScanner(
        targets=("127.0.0.1",), ports=(9998,), timeout=1.0
    )
    with patch(
        "async_port_scanner.core.asyncio.open_connection",
        new=AsyncMock(side_effect=ConnectionRefusedError),
    ):
        await scanner._run()

    state, _service, reason = scanner.results["127.0.0.1"][9998]
    assert state == "closed"
    assert reason == "Connection refused"


async def test_timeout_is_reported_with_no_response_reason():
    scanner = AsyncTCPScanner(
        targets=("example.invalid",), ports=(9999,), timeout=1.0
    )
    with patch(
        "async_port_scanner.core.asyncio.open_connection",
        new=AsyncMock(side_effect=TimeoutError),
    ):
        await scanner._run()

    state, _service, reason = scanner.results["example.invalid"][9999]
    assert state == "closed"
    assert reason == "No response"


async def test_dns_failure_is_reported_as_network_error_not_keyerror():
    """socket.gaierror is an OSError subclass whose class name isn't
    one of the three literal strings the original reason-lookup dict
    was keyed on -- regression test for the resulting KeyError."""
    scanner = AsyncTCPScanner(
        targets=("nonexistent.invalid",), ports=(80,), timeout=1.0
    )
    with patch(
        "async_port_scanner.core.asyncio.open_connection",
        new=AsyncMock(side_effect=socket.gaierror),
    ):
        await scanner._run()  # must not raise KeyError

    state, _service, reason = scanner.results["nonexistent.invalid"][80]
    assert state == "closed"
    assert reason == "Network error"


async def test_total_time_is_recorded(open_port):
    scanner = AsyncTCPScanner(
        targets=("127.0.0.1",), ports=(open_port,), timeout=2.0
    )
    await scanner._run()
    assert scanner.total_time > 0


async def test_notify_all_calls_registered_observers():
    scanner = AsyncTCPScanner(targets=(), ports=(), timeout=1.0)

    class _RecordingObserver:
        def __init__(self, subject):
            subject.register(self)
            self.updated = False

        async def update(self):
            self.updated = True

    observer = _RecordingObserver(scanner)
    await scanner._run()
    assert observer.updated is True
