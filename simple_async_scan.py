#!/usr/bin/env python3
# https://github.com/EONRaider/Simple-Async-Port-Scanner

__author__ = 'EONRaider @ keybase.io/eonraider'

import abc
import asyncio
import socket
from collections import defaultdict
from time import time, ctime
from typing import Iterator, Sequence, Tuple


class AsyncTCPScanner(object):
    def __init__(self, target_addresses: Sequence[str], ports: Sequence[int],
                 show_open_only: bool = False):
        self.target_addresses = target_addresses
        self.ports = ports
        self.start_time: float = 0
        self.end_time: float = 0
        self.json_report = defaultdict(dict)
        self.__observers = list()
        self.show_open_only = show_open_only

    def register(self, observer):
        """Register a derived class of OutputMethod as an observer"""
        self.__observers.append(observer)

    def __notify_all(self):
        """Send the scan results to all registered observers"""
        for observer in self.__observers:
            observer.update()

    def execute(self):
        self.start_time = time()
        scan_results = asyncio.run(self.__scan_targets())
        self.end_time = time()
        self.__make_json_report(scan_results)
        self.__notify_all()

    def __make_json_report(self, scan_results):
        for info in scan_results:
            self.json_report[info[0]].update({info[1]: (info[2], info[3])})

    async def __scan_targets(self) -> tuple:
        loop = asyncio.get_event_loop()
        scans = (asyncio.create_task(self.__tcp_connection(loop, address, port))
                 for port in self.ports for address in self.target_addresses)
        return await asyncio.gather(*scans)

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
        output_template: str = '{}{: ^8}{: ^12}{: ^12}'
        allowed_states = ('open',) if self.scan.show_open_only is True \
            else ('open', 'closed')
        i = ' ' * 4  # Basic indentation level

        print(f'Starting Async Port Scanner at {ctime(self.scan.start_time)}')
        print(f'Scan report for {all_targets}')

        for address in self.scan.json_report.keys():
            print(f'\n[>] Results for {address}:')
            print(output_template.format(i, 'PORT', 'STATE', 'SERVICE'))
            for port_num, port_info in self.scan.json_report[address].items():
                if port_info[0] in allowed_states:
                    print(output_template.format(i, port_num, port_info[0],
                                                 port_info[1]))

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

    parser.add_argument('targets', type=str, metavar='IP_ADDRESSES',
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
    args = parser.parse_args()

    scanner = AsyncTCPScanner.from_csv_string(addresses=args.targets,
                                              ports=args.ports)
    scanner.show_open_only = args.open
    to_screen = ScanToScreen(scanner)
    scanner.execute()
