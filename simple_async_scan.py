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
    scans = (asyncio.create_task(tcp_connect(loop, ip_address, port_number))
             for port_number in ports for ip_address in targets)

    scan_results = await asyncio.gather(*scans)

    elapsed_time = time.time() - start_time
    print('[>>>] TCP Connect scan for {0} completed in {1} seconds'.format(
        ' '.join(targets), elapsed_time))
    print(*('{0: >7} {1}:{2} --> {3}'.format(
        '[+]', *result) for result in scan_results), sep='\n')


if __name__ == '__main__':
    import argparse

    usage_example = ('Usage example:\n'
                     'python3 simple_async_scan.py '
                     '45.33.32.156 65.61.137.117 18.192.172.30'
                     '-p 21 22 25 80 111 135 139 443 3306 5900')

    parser = argparse.ArgumentParser(
        description='Simple asynchronous TCP Connect port scanner',
        epilog=usage_example,
        formatter_class=argparse.RawTextHelpFormatter)

    parser.add_argument('targets', nargs='+', type=str, metavar='IP_ADDRESSES',
                        help="A space-separated list of IP addresses to scan, "
                             "e.g., '45.33.32.156 65.61.137.117'.")
    parser.add_argument('-p', '--ports', nargs='+', type=int, required=True,
                        help="A space-separated list of ports to scan on each "
                             "specified target, e.g., '21 22 80 443'.")
    args = parser.parse_args()

    asyncio.run(scanner(**vars(args)))
