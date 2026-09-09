# Python 3 Asynchronous TCP/IP Connect Port Scanner

[![PyPI](https://img.shields.io/pypi/v/async-port-scanner?style=for-the-badge)](https://pypi.org/project/async-port-scanner/)
[![Python Version](https://img.shields.io/pypi/pyversions/async-port-scanner?style=for-the-badge&logo=python)](https://pypi.org/project/async-port-scanner/)
[![CI](https://img.shields.io/github/actions/workflow/status/EONRaider/Simple-Async-Port-Scanner/ci.yml?style=for-the-badge&label=CI)](https://github.com/EONRaider/Simple-Async-Port-Scanner/actions/workflows/ci.yml)
[![License](https://img.shields.io/github/license/EONRaider/Simple-Async-Port-Scanner?style=for-the-badge)](https://github.com/EONRaider/Simple-Async-Port-Scanner/blob/master/LICENSE)

[![Reddit](https://img.shields.io/badge/Reddit-EON__Raider-FF4500?style=flat-square&logo=reddit)](https://www.reddit.com/user/EON_Raider)
[![Discord](https://img.shields.io/badge/Discord-EONRaider-7289DA?style=flat-square&logo=discord)](https://discord.gg/KVjWBptv)

A simple TCP Connect port scanner developed in Python 3. This application leverages
the use of Python's Standard Library `asyncio` framework to execute a
number of TCP connections to an arbitrary number ports on target IP
addresses, taking a maximum time equal to the connection `timeout`
setting (defaults to 10 seconds) to return all results.

This application maintains no dependencies on third-party modules.

## Demo
![scanner_demo](https://user-images.githubusercontent.com/15611424/178142566-6bba065f-ca8d-43a8-a845-19bf650162f1.gif)

## Installation

Install from PyPI, ideally with [pipx](https://pipx.pypa.io/) so the `async-port-scanner`
command is available globally in its own isolated environment:

```
user@host:~$ pipx install async-port-scanner
```

Or with `pip`:

```
user@host:~$ pip install async-port-scanner
```

### For development

```
user@host:~$ git clone https://github.com/EONRaider/Simple-Async-Port-Scanner.git
user@host:~$ cd Simple-Async-Port-Scanner
user@host:~/Simple-Async-Port-Scanner$ uv sync
user@host:~/Simple-Async-Port-Scanner$ uv run async-port-scanner example.com -p 80,443
```

## Usage
```
usage: async-port-scanner [-h] -p PORTS [--timeout TIMEOUT] [--open]
                          [--version]
                          ADDRESSES

Simple asynchronous TCP Connect port scanner

positional arguments:
  ADDRESSES             A comma-separated sequence of IP addresses and/or domain names to scan, e.g., '45.33.32.156,65.61.137.117,testphp.vulnweb.com'.

options:
  -h, --help            show this help message and exit
  -p PORTS, --ports PORTS
                        A comma-separated sequence of port numbers and/or port ranges to scan on each target specified, e.g., '20-25,53,80,443'.
  --timeout TIMEOUT     Time to wait for a response from a target before closing a connection (defaults to 10.0 seconds).
  --open                Only show open ports in scan results.
  --version             show program's version number and exit

Usage examples:
1. async-port-scanner google.com -p 80,443
2. async-port-scanner 45.33.32.156,demo.testfire.net,18.192.172.30 -p 20-25,53,80,111,135,139,443,3306,5900
```

`async-port-scanner` is also runnable as a module with `python -m async_port_scanner`.

## Application Performance
Due to the nature of Python's `asyncio` framework results such as the 
ones shown below are possible: the first 1000 TCP/IP ports of 
[scanme.nmap.org](http://scanme.nmap.org) are scanned in **1.68 seconds**:
```
eonraider@havoc:~$ async-port-scanner scanme.nmap.org -p 1-1000 --open
Starting Async Port Scanner at Sat Jan 30 13:41:25 2021
Scan report for scanme.nmap.org

[>] Results for scanme.nmap.org:
      PORT     STATE      SERVICE      REASON   
       22       open        ssh       SYN/ACK   
       80       open        http      SYN/ACK   

Async TCP Connect scan of 1000 ports for scanme.nmap.org completed in 1.68 seconds
```

**ADVISORY:** For the sake of simplicity this application does not
implement a maximum number of workers responsible for making each
connection, instead spawning a new worker for every target socket
(i.e. combination of target address and TCP port) until the process is
complete. What this means in
practice is that performing a scan of a significant number of ports on
a single host will consequently trigger a great number of requests being
sent almost simultaneously, potentially causing an involuntary situation
analogous to that of a *SYN-flood Denial-of-Service attack* on hosts not
able to handle the sudden spike in the number of requests they have to
handle. For this particular reason, and in addition to the
[Legal Disclaimer](#legal-disclaimer) section below, **all users are
advised by the developers to use caution when scanning live hosts.**

## Legal Disclaimer

The use of code contained in this repository, either in part or in its totality,
for engaging targets without prior mutual consent is illegal. **It is
the end user's responsibility to obey all applicable local, state and 
federal laws.**

Developers assume **no liability** and are not
responsible for misuses or damages caused by any code contained
in this repository in any event that, accidentally or otherwise, it comes to
be utilized by a threat agent or unauthorized entity as a means to compromise
the security, privacy, confidentiality, integrity, and/or availability of
systems and their associated resources by leveraging the exploitation of known
or unknown vulnerabilities present in said systems, including, but not limited
to, the implementation of security controls, human- or electronically-enabled.

The use of this code is **only** endorsed by the developers in those
circumstances directly related to **educational environments** or
**authorized penetration testing engagements** whose declared purpose is that
of finding and mitigating vulnerabilities in systems, limiting their exposure
to compromises and exploits employed by malicious agents as defined in their
respective threat models.
