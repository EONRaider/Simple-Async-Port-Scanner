#!/usr/bin/env python3
# https://github.com/EONRaider/Simple-Async-Port-Scanner

__author__ = "EONRaider @ keybase.io/eonraider"

import argparse
from collections.abc import Generator, Sequence
from typing import Any

from . import __version__
from .core import AsyncTCPScanner
from .output import OutputToScreen


def parse_ports(port_seq: str) -> Generator[int, Any, None]:
    """Yield an iterator with integers extracted from a string
    consisting of mixed port numbers and/or ranged intervals.
    Ex: From '20-25,53,80,111' to (20,21,22,23,24,25,53,80,111)
    """
    for port in port_seq.split(","):
        try:
            port_num = int(port)
            if not 0 < port_num < 65536:
                raise SystemExit(f"Error: Invalid port number {port_num}.")
            yield port_num
        except ValueError:
            start, end = (int(p) for p in port.split("-"))
            if not (0 < start <= end < 65536):
                raise SystemExit(f"Error: Invalid port range {port}.") from None
            yield from range(start, end + 1)


def process_cli_args(
    targets: str, ports: str, **kwargs: Any
) -> AsyncTCPScanner:
    """Create a new instance of AsyncTCPScanner by parsing strings of
    comma-separated IP addresses/domain names and port numbers
    from the CLI and transforming them into proper initialization
    arguments.

    Args:
        targets (str): A string containing a sequence of IP
            addresses and/or domain names.
        ports (str): A string containing a sequence of valid port
            numbers as defined by IETF RFC 6335.
    """
    return AsyncTCPScanner(
        targets=tuple(targets.split(",")),
        ports=tuple(parse_ports(ports)),
        **kwargs,
    )


def build_arg_parser() -> argparse.ArgumentParser:
    usage = (
        "Usage examples:\n"
        "1. async-port-scanner google.com -p 80,443\n"
        "2. async-port-scanner "
        "45.33.32.156,demo.testfire.net,18.192.172.30 "
        "-p 20-25,53,80,111,135,139,443,3306,5900"
    )

    parser = argparse.ArgumentParser(
        prog="async-port-scanner",
        description="Simple asynchronous TCP Connect port scanner",
        epilog=usage,
        formatter_class=argparse.RawTextHelpFormatter,
    )

    parser.add_argument(
        "targets",
        type=str,
        metavar="ADDRESSES",
        help="A comma-separated sequence of IP addresses "
        "and/or domain names to scan, e.g., "
        "'45.33.32.156,65.61.137.117,"
        "testphp.vulnweb.com'.",
    )
    parser.add_argument(
        "-p",
        "--ports",
        type=str,
        required=True,
        help="A comma-separated sequence of port numbers "
        "and/or port ranges to scan on each target "
        "specified, e.g., '20-25,53,80,443'.",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        help="Time to wait for a response from a target before "
        "closing a connection (defaults to 10.0 seconds).",
    )
    parser.add_argument(
        "--open",
        action="store_true",
        help="Only show open ports in scan results.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> None:
    cli_args = build_arg_parser().parse_args(argv)

    scanner = process_cli_args(
        targets=cli_args.targets,
        ports=cli_args.ports,
        timeout=cli_args.timeout,
    )

    OutputToScreen(subject=scanner, show_open_only=cli_args.open)
    scanner.execute()


if __name__ == "__main__":
    main()
