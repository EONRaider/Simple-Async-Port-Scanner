#!/usr/bin/env python3
# https://github.com/EONRaider/Simple-Async-Port-Scanner

__author__ = 'EONRaider @ keybase.io/eonraider'

import abc
import asyncio
import socket
from collections import defaultdict
from time import time, ctime
from typing import Iterator, List, Sequence, Tuple


class AsyncTCPScanner(object):
    def __init__(self, target_addresses: Sequence[str], ports: Sequence[int], *,
                 show_open_only: bool = False):
        self.target_addresses = target_addresses
        self.ports = ports
        self.start_time: float = 0
        self.end_time: float = 0
        self.json_report = defaultdict(dict)
        self.__observers = list()
        self.open_only: bool = show_open_only

    @property
    def total_time(self):
        return self.end_time - self.start_time

    def register(self, observer):
        """Register a derived class of OutputMethod as an observer"""
        self.__observers.append(observer)

    def __notify_all(self):
        """Send the scan results to all registered observers"""
        for observer in self.__observers:
            observer.update()

    def execute(self):
        self.start_time = time()
        scan_results: List[tuple] = asyncio.run(self.__scan_targets())
        self.end_time = time()
        self.__process_results(scan_results)
        self.__notify_all()

    def __process_results(self, scan_results: list):
        """Create a JSON report with the scan results so that their
        processing can be done with data organized by target address."""

        """
        This method converts a 'scan_results' data structure like...
        [('g.cn', 22, 'closed', 'ssh'), ('g.cn', 80, 'open', 'http')]
        ... into a more convenient, similar to JSON, dictionary...
        {'g.cn': {22: ('open', 'ssh'), 80: ('open', 'http')}}
        """
        for info in scan_results:
            self.json_report[info[0]].update({info[1]: (info[2], info[3])})

    async def __scan_targets(self) -> tuple:
        loop = asyncio.get_event_loop()
        scans = (asyncio.create_task(self.__tcp_connection(loop, address, port))
                 for port in self.ports for address in self.target_addresses)
        results = await asyncio.gather(*scans)
        return results

    @staticmethod
    async def __tcp_connection(loop: asyncio.AbstractEventLoop,
                               target_address: str,
                               port: int) -> Tuple[str, int, str, str]:
        try:
            await asyncio.wait_for(
                asyncio.open_connection(target_address, port, loop=loop),
                timeout=3.0)
            port_state = 'open'
        except (ConnectionRefusedError, asyncio.TimeoutError, OSError):
            port_state = 'closed'
        try:
            service_name = socket.getservbyport(port)
        except OSError:
            service_name = 'unknown'
        return target_address, port, port_state, service_name

    @classmethod
    def from_csv_string(cls, addresses: str, ports: str):
        """
        Parse strings of comma-separated IP addresses/domain names and
        port numbers and transform them into sequences that are used to
        instantiate new AsyncTCPScanner objects. Recommended for use
        with the Standard Library 'argparse' module or CSV files.

        Args:
            addresses (str): A string containing a sequence of IP
                addresses and/or domain names.
            ports (str): A string containing a sequence of port numbers.

        Returns:
            An instance of type AsyncTCPScan.
        """

        def parse_ports(port_seq) -> Iterator[int]:
            """
            Yield an iterator with integers extracted from a string
            consisting of mixed port numbers and/or ranged intervals.
            Ex: From '20-25,53,80,111' to (20,21,22,23,24,25,53,80,111)
            """
            for port in port_seq.split(','):
                try:
                    yield int(port)
                except ValueError:
                    start, end = (int(port) for port in port.split('-'))
                    yield from range(start, end + 1)

        target_sequence = tuple(addresses.split(','))
        port_sequence = tuple(parse_ports(ports))

        return cls(target_addresses=target_sequence, ports=port_sequence)


class OutputMethod(abc.ABC):
    """Interface for the implementation of all classes responsible for
    further processing and/or output of the information gathered by
    the AsyncTCPScanner class."""

    def __init__(self, subject):
        subject.register(self)

    @abc.abstractmethod
    def update(self, *args, **kwargs):
        pass


class ScanToScreen(OutputMethod):
    def __init__(self, subject):
        super().__init__(subject)
        self.scan = subject

    def update(self):
        all_targets: str = ' | '.join(self.scan.target_addresses)
        num_ports: int = len(self.scan.ports) * len(self.scan.target_addresses)
        elapsed_time: float = self.scan.end_time - self.scan.start_time
        output: str = '    {: ^8}{: ^12}{: ^12}'

        print(f'Starting Async Port Scanner at {ctime(self.scan.start_time)}')
        print(f'Scan report for {all_targets}')

        for address in self.scan.json_report.keys():
            print(f'\n[>] Results for {address}:')
            print(output.format('PORT', 'STATE', 'SERVICE'))
            for port_num, port_info in self.scan.json_report[address].items():
                if self.scan.open_only is True and port_info[0] == 'closed':
                    continue
                print(output.format(port_num, port_info[0], port_info[1]))

        print(f"\nAsync TCP Connect scan of {num_ports} ports for "
              f"{all_targets} completed in {elapsed_time:.3f} seconds")


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

    scanner = AsyncTCPScanner.from_csv_string(addresses=cli_args.targets,
                                              ports=cli_args.ports)
    scanner.open_only = cli_args.open
    to_screen = ScanToScreen(scanner)
    scanner.execute()
