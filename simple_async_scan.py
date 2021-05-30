#!/usr/bin/env python3
# https://github.com/EONRaider/Simple-Async-Port-Scanner

__author__ = 'EONRaider @ keybase.io/eonraider'

import abc
import asyncio
import socket
from collections import defaultdict
from contextlib import contextmanager
from time import ctime, perf_counter, time
from typing import Collection, Iterator


class AsyncTCPScanner(object):
    """Perform asynchronous TCP-connect scans on collections of target
    hosts and ports."""

    def __init__(self,
                 target_addresses: Collection[str],
                 ports: Collection[int],
                 timeout: float):
        """
        Args:
            target_addresses (Collection[str]): A collection of strings
                containing a sequence of IP addresses and/or domain
                names.
            ports (Collection[int]): A collection of integers containing
                a sequence of valid port numbers as defined by
                IETF RFC 6335.
            timeout (float): Time to wait for a response from a target
                before closing a connection to it. Setting this to too
                short an interval may generate false-negatives by
                identifying a result as a timeout too soon (instead of
                just waiting the necessary time to receive a valid
                response from a live server).
        """

        self.target_addresses = target_addresses
        self.ports = ports
        self.timeout = timeout
        self.results = defaultdict(dict)
        self.total_time = float()
        self.__loop = asyncio.get_event_loop()
        self.__observers = list()

    @property
    def _scan_tasks(self):
        """Set up a scan coroutine for each pair of target address and
        port."""
        return [self._scan_target_port(address, port) for port in self.ports
                for address in self.target_addresses]

    @contextmanager
    def _timer(self):
        start_time: float = perf_counter()
        yield
        self.total_time = perf_counter() - start_time

    def register(self, observer):
        """Register a derived class of OutputMethod as an observer"""
        self.__observers.append(observer)

    async def _notify_all(self):
        """Notify all registered observers that the scan results are
        ready to be pulled and processed."""
        for observer in self.__observers:
            asyncio.create_task(observer.update())

    async def _scan_target_port(self, address: str, port: int) -> None:
        """
        Execute a TCP handshake on a target port and add the result to
        a JSON data structure of the form:
        {
            'example.com': {
                22: ('closed', 'ssh', 'No response'),
                80: ('open', 'http', 'SYN/ACK')
            }
        }
        """

        try:
            await asyncio.wait_for(
                asyncio.open_connection(address, port, loop=self.loop),
                timeout=3.0)
            port_state, reason = 'open', 'syn/ack'
        except (ConnectionRefusedError, asyncio.TimeoutError, OSError):
            port_state, reason = 'closed', 'timeout'
        try:
            service = socket.getservbyport(port)
        except OSError:
            service = 'unknown'
        self.results[address].update({port: (port_state, service, reason)})


    @classmethod
    def from_csv_strings(cls, target_addresses: str, ports: str,
                         *args, **kwargs):
        """
        Create a new instance of AsyncTCPScanner by parsing strings of
        comma-separated IP addresses/domain names and port numbers and
        transforming them into sets.

        Args:
            target_addresses (str): A string containing a sequence of IP
                addresses and/or domain names.
            ports (str): A string containing a sequence of valid port
                numbers as defined by IETF RFC 6335.
        """

        def _parse_ports(port_seq) -> Iterator[int]:
            """
            Yield an iterator with integers extracted from a string
            consisting of mixed port numbers and/or ranged intervals.
            Ex: From '20-25,53,80,111' to (20,21,22,23,24,25,53,80,111)
            """
            for port in port_seq.split(','):
                try:
                    port = int(port)
                    if not 0 < port < 65536:
                        raise SystemExit(f'Error: Invalid port number {port}.')
                    yield port
                except ValueError:
                    start, end = (int(port) for port in port.split('-'))
                    yield from range(start, end + 1)

        return cls(target_addresses=set(target_addresses.split(',')),
                   ports=set(_parse_ports(ports)),
                   *args, **kwargs)


class OutputMethod(abc.ABC):
    """Interface for the implementation of all classes responsible for
    further processing and/or output of the information gathered by
    the AsyncTCPScanner class."""

    def __init__(self, subject):
        subject.register(self)

    @abc.abstractmethod
    async def update(self, *args, **kwargs):
        pass


class ScanToScreen(OutputMethod):
    def __init__(self, subject):
        super().__init__(subject)
        self.scan = subject

    async def update(self):
        all_targets: str = ' | '.join(self.scan.target_addresses)
        num_ports: int = len(self.scan.ports) * len(self.scan.target_addresses)
        output: str = '    {: ^8}{: ^12}{: ^12}{: ^12}'

        print(f'Starting Async Port Scanner at {ctime(time())}')
        print(f'Scan report for {all_targets}')

        for address in self.scan.results.keys():
            print(f'\n[>] Results for {address}:')
            print(output.format('PORT', 'STATE', 'SERVICE', 'REASON'))
            for port, port_info in sorted(self.scan.results[address].items()):
                if self.scan.open_only is True and port_info[0] == 'closed':
                    continue
                print(output.format(port, *port_info))

        print(f"\nAsync TCP Connect scan of {num_ports} ports for "
              f"{all_targets} completed in {self.scan.total_time:.3f} seconds")

        await asyncio.sleep(0)


if __name__ == '__main__':
    import argparse

    usage = ('Usage examples:\n'
             '1. python3 simple_async_scan.py google.com -p 80,443\n'
             '2. python3 simple_async_scan.py '
             '45.33.32.156,demo.testfire.net,18.192.172.30 '
             '-p 20-25,53,80,111,135,139,443,3306,5900')

    parser = argparse.ArgumentParser(
        description='Simple asynchronous TCP Connect port scanner',
        epilog=usage,
        formatter_class=argparse.RawTextHelpFormatter)

    parser.add_argument('targets', type=str, metavar='ADDRESSES',
                        help="A comma-separated sequence of IP addresses "
                             "and/or domain names to scan, e.g., "
                             "'45.33.32.156,65.61.137.117,"
                             "testphp.vulnweb.com'.")
    parser.add_argument('-p', '--ports', type=str, required=True,
                        help="A comma-separated sequence of port numbers "
                             "and/or port ranges to scan on each target "
                             "specified, e.g., '20-25,53,80,443'.")
    parser.add_argument('--open', action='store_true',
                        help='Only show open ports in the scan results.')
    cli_args = parser.parse_args()

    parsed_addrs, parsed_ports = parse_csv_strings(addresses=cli_args.targets,
                                                   ports=cli_args.ports)
    scanner = AsyncTCPScanner(target_addresses=parsed_addrs,
                              ports=parsed_ports,
                              show_open_only=cli_args.open)
    to_screen = ScanToScreen(scanner)
    scanner.execute()
