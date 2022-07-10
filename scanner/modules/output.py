#!/usr/bin/env python3
# https://github.com/EONRaider/Simple-Async-Port-Scanner

__author__ = "EONRaider @ keybase.io/eonraider"

import asyncio
from abc import ABC, abstractmethod
from time import ctime, time


class Output(ABC):
    """
    Interface for the implementation of all classes responsible for
    further processing and/or output of the information gathered by
    the AsyncTCPScanner class.
    """

    def __init__(self, subject):
        subject.register(self)

    @abstractmethod
    async def update(self, *args, **kwargs) -> None:
        pass


class OutputToScreen(Output):
    def __init__(self, subject, show_open_only: bool = False):
        super().__init__(subject)
        self.scan = subject
        self.open_only = show_open_only

    async def update(self) -> None:
        all_targets: str = ' | '.join(self.scan.targets)
        num_ports: int = len(self.scan.ports) * len(self.scan.targets)
        output: str = '    {: ^8}{: ^12}{: ^12}{: ^12}'

        print(f'Starting Async Port Scanner at {ctime(time())}')
        print(f'Scan report for {all_targets}')

        for address in self.scan.results.keys():
            print(f'\n[>] Results for {address}:')
            print(output.format('PORT', 'STATE', 'SERVICE', 'REASON'))
            for port, port_info in sorted(self.scan.results[address].items()):
                if self.open_only is True and port_info[0] == 'closed':
                    continue
                print(output.format(port, *port_info))

        print(f"\nAsync TCP Connect scan of {num_ports} ports for "
              f"{all_targets} completed in {self.scan.total_time:.2f} seconds")

        await asyncio.sleep(0)
