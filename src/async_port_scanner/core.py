#!/usr/bin/env python3
# https://github.com/EONRaider/Simple-Async-Port-Scanner

from __future__ import annotations

__author__ = "EONRaider @ keybase.io/eonraider"

import asyncio
import socket
from collections import defaultdict
from collections.abc import Collection, Iterator
from contextlib import contextmanager
from time import perf_counter
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .output import Output


class AsyncTCPScanner:
    """Perform asynchronous TCP-connect scans on collections of target
    hosts and ports."""

    def __init__(
        self,
        targets: Collection[str],
        ports: Collection[int],
        timeout: float,
    ):
        """
        Args:
            targets (Collection[str]): A collection of strings
                containing a sequence of IP addresses and/or domain
                names.
            ports (Collection[int]): A collection of integers containing
                a sequence of valid port numbers as defined by
                IETF RFC 6335.
            timeout (float): Time to wait for a response from a target
                before closing a connection to it. Setting this to too
                short an interval may prevent the scanner from waiting
                the time necessary to receive a valid response from a
                valid server, generating a false-negative by identifying
                a result as a timeout too soon. Recommended setting to
                a minimum of 10 seconds.
        """
        self.targets = targets
        self.ports = ports
        self.timeout = timeout
        self.results: defaultdict[str, dict[int, tuple[str, str, str]]] = (
            defaultdict(dict)
        )
        self.total_time = 0.0
        self._observers: list[Output] = []

    @contextmanager
    def _timer(self) -> Iterator[None]:
        """Measure the total time taken by the scan operation."""
        start_time: float = perf_counter()
        yield
        self.total_time = perf_counter() - start_time

    def register(self, observer: Output) -> None:
        """Register a class that implements the interface of
        Output as an observer."""
        self._observers.append(observer)

    async def _notify_all(self) -> None:
        """Notify all registered observers that the scan results are
        ready to be pulled and processed."""
        async with asyncio.TaskGroup() as tg:
            for observer in self._observers:
                tg.create_task(observer.update())

    async def _scan_target_port(self, address: str, port: int) -> None:
        """Execute a TCP handshake on a target port and add the result
        to a JSON data structure of the form:
        {
            'example.com': {
                22: ('closed', 'ssh', 'Connection refused'),
                80: ('open', 'http', 'SYN/ACK')
            }
        }
        """
        try:
            await asyncio.wait_for(
                asyncio.open_connection(address, port), timeout=self.timeout
            )
            port_state, reason = "open", "SYN/ACK"
        except (ConnectionRefusedError, TimeoutError, OSError) as exc:
            port_state = "closed"
            if isinstance(exc, ConnectionRefusedError):
                reason = "Connection refused"
            elif isinstance(exc, TimeoutError):
                reason = "No response"
            else:
                reason = "Network error"
        try:
            service = socket.getservbyport(port)
        except OSError:
            service = "unknown"
        self.results[address].update({port: (port_state, service, reason)})

    async def _run(self) -> None:
        with self._timer():
            async with asyncio.TaskGroup() as tg:
                for port in self.ports:
                    for target in self.targets:
                        tg.create_task(self._scan_target_port(target, port))
        await self._notify_all()

    def execute(self) -> None:
        asyncio.run(self._run())
