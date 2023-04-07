#!/usr/bin/env python3
# https://github.com/EONRaider/Simple-Async-Port-Scanner

__author__ = "EONRaider @ keybase.io/eonraider"

import asyncio
import socket
from collections import defaultdict
from contextlib import contextmanager
from time import perf_counter
from typing import Collection


class AsyncTCPScanner:
    """Perform asynchronous TCP-connect scans on collections of target
    hosts and ports."""

    def __init__(self,
                 targets: Collection[str],
                 ports: Collection[int],
                 timeout: float):
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
        self.results = defaultdict(dict)
        self.total_time = float()
        self._loop = asyncio.get_event_loop()
        self._observers = list()

    @property
    def _scan_tasks(self):
        """Set up a scan coroutine for each pair of target address and
        port."""
        return [self._scan_target_port(target, port) for port in self.ports
                for target in self.targets]

    @contextmanager
    def _timer(self):
        """Measure the total time taken by the scan operation."""
        start_time: float = perf_counter()
        yield
        self.total_time = perf_counter() - start_time

    def register(self, observer):
        """Register a class that implements the interface of
        Output as an observer."""
        self._observers.append(observer)

    async def _notify_all(self):
        """Notify all registered observers that the scan results are
        ready to be pulled and processed."""
        [asyncio.create_task(observer.update()) for observer in self._observers]

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
                asyncio.open_connection(address, port),
                timeout=self.timeout
            )
            port_state, reason = 'open', 'SYN/ACK'
        except (ConnectionRefusedError, asyncio.TimeoutError, OSError) as e:
            reasons = {
                'ConnectionRefusedError': 'Connection refused',
                'TimeoutError': 'No response',
                'OSError': 'Network error'
            }
            port_state, reason = 'closed', reasons[e.__class__.__name__]
        try:
            service = socket.getservbyport(port)
        except OSError:
            service = 'unknown'
        self.results[address].update({port: (port_state, service, reason)})

    def execute(self):
        with self._timer():
            self._loop.run_until_complete(asyncio.wait(self._scan_tasks))
        self._loop.run_until_complete(self._notify_all())
