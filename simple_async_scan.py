#!/usr/bin/env python3
# https://github.com/EONRaider/Simple-Async-Scanner

__author__ = 'EONRaider @ keybase.io/eonraider'

import asyncio
import contextlib
import time
from typing import Iterable, Iterator, Tuple, NoReturn


async def tcp_connect(loop: asyncio.AbstractEventLoop,
                      ip_address: str,
                      port: int) -> Tuple[str, int, str]:
    with contextlib.suppress(ConnectionRefusedError, asyncio.TimeoutError,
                             OSError):
        port_state = 'closed'
        await asyncio.wait_for(
            asyncio.open_connection(ip_address, port, loop=loop), timeout=3.0)
        port_state = 'open'
    return ip_address, port, port_state


async def scanner(target_addresses: Iterable, ports: Iterable) -> NoReturn:
    start_time = time.time()
    loop = asyncio.get_event_loop()
    scans = (asyncio.create_task(tcp_connect(loop, address, port))
             for port in ports for address in target_addresses)

    scan_results = await asyncio.gather(*scans)

    elapsed_time = time.time() - start_time
    print('[>>>] TCP Connect scan for {0} completed in {1:.3f} seconds'.format(
        ' '.join(target_addresses), elapsed_time))
    print(*('{0: >7} {1}:{2} --> {3}'.format(
        '[+]', *result) for result in scan_results), sep='\n')


if __name__ == '__main__':
    import argparse


    def parse_ports(ports) -> Iterator[int]:
        """
        Yields an iterator with integers extracted from a string
        consisting of mixed port numbers and/or ranged intervals.
        Ex: From '20-25,53,80,111' to (21,22,25,26,27,28,29,30,53,80)
        """
        for port in ports.split(','):
            try:
                yield int(port)
            except ValueError:
                start, end = (int(port) for port in port.split('-'))
                yield from range(start, end + 1)


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
    args = parser.parse_args()

    target_sequence: list = args.targets.split(',')
    port_sequence = parse_ports(args.ports)

    asyncio.run(scanner(target_addresses=target_sequence, ports=port_sequence))
