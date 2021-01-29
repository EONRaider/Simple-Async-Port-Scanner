# Python 3 Asynchronous TCP Connect Port Scanner

![Python Version](https://img.shields.io/badge/python-3.x-blue?style=for-the-badge&logo=python)
![OS](https://img.shields.io/badge/OS-GNU%2FLinux-red?style=for-the-badge&logo=linux)
[![CodeFactor Grade](https://img.shields.io/codefactor/grade/github/eonraider/simple-async-scanner?style=for-the-badge)](https://www.codefactor.io/repository/github/eonraider/simple-async-scanner)
[![License](https://img.shields.io/github/license/EONRaider/Packet-Sniffer?style=for-the-badge)](https://github.com/EONRaider/Packet-Sniffer/blob/master/LICENSE)

[![Reddit](https://img.shields.io/reddit/user-karma/combined/eonraider?style=flat-square&logo=reddit)](https://www.reddit.com/user/eonraider)
[![GitHub](https://img.shields.io/github/followers/eonraider?label=GitHub&logo=github&style=flat-square)](https://github.com/EONRaider)
[![Twitter](https://img.shields.io/twitter/follow/eon_raider?style=flat-square&logo=twitter)](https://twitter.com/intent/follow?screen_name=eon_raider)

A simple pure-Python TCP Connect port scanner. This application leverages
the use of Python's Standard Library `asyncio` framework to execute a
number of TCP connections to an arbitrary number ports on target IP
addresses, taking a maximum time equal to the connection `timeout`
setting (defaults to 3 seconds) to return all results.

This application maintains no dependencies on third-party modules and can be
run by any Python v3.7+ interpreter.

## Installation

### GNU / Linux

Simply clone this repository with `git clone` and execute the
`simple_async_scan.py` file as described in the following
[Usage](#usage) section.

```
user@host:~/DIR$ git clone https://github.com/EONRaider/Simple-Async-Scan.git
```

## Usage

```
Simple asynchronous TCP Connect port scanner

positional arguments:
  IP_ADDRESSES          A comma-separated sequence of IP addresses and/or domain names to scan, e.g., '45.33.32.156,65.61.137.117,testphp.vulnweb.com'.

optional arguments:
  -h, --help            show this help message and exit
  -p PORTS, --ports PORTS
                        A comma-separated sequence of port numbers and/or port ranges to scan on each target specified, e.g., '20-25,53,80,443'.

Usage examples:
1. python3 simple_async_scan.py google.com -p 80,443
2. python3 simple_async_scan.py 45.33.32.156,demo.testfire.net,18.192.172.30 -p 20-25,53,80,111,135,139,443,3306,5900
```

## Running the Application

<table>
<tbody>
  <tr>
    <td>Objective</td>
    <td>Scan ports on a series of domains and IP addresses</td>
  </tr>
  <tr>
    <td>Execution</td>
    <td><b>python3 simple_async_scan.py 45.33.32.156,demo.testfire.net -p 20-25,53,80,111</b></td>
  </tr>
  <tr>
    <td>Outcome</td>
    <td>Refer to sample output below</td>
  </tr>
</tbody>
</table>

- Sample output:

```
[>>>] TCP Connect scan for 45.33.32.156 demo.testfire.net completed in 3.0040507316589355 seconds
    [+] 45.33.32.156:20 --> closed
    [+] demo.testfire.net:20 --> closed
    [+] 45.33.32.156:21 --> closed
    [+] demo.testfire.net:21 --> closed
    [+] 45.33.32.156:22 --> open
    [+] demo.testfire.net:22 --> closed
    [+] 45.33.32.156:23 --> closed
    [+] demo.testfire.net:23 --> closed
    [+] 45.33.32.156:24 --> closed
    [+] demo.testfire.net:24 --> closed
    [+] 45.33.32.156:25 --> closed
    [+] demo.testfire.net:25 --> closed
    [+] 45.33.32.156:53 --> closed
    [+] demo.testfire.net:53 --> closed
    [+] 45.33.32.156:80 --> open
    [+] demo.testfire.net:80 --> open
    [+] 45.33.32.156:111 --> closed
    [+] demo.testfire.net:111 --> closed
```

## Legal Disclaimer

The use of code contained in this repository, either in part or in its totality,
for engaging targets without prior mutual consent is illegal. **It is
the end user's responsibility to obey all applicable local, state,
and federal laws.**

Developers assume **no liability** and are not
responsible for misuses or damages caused by any code contained
in this repository in any event that, accidentally or otherwise, it comes to
be utilized by a threat agent or unauthorized entity as a means to compromise
the security, privacy, confidentiality, integrity, and|or availability of
systems and their associated resources by leveraging the exploitation of known
or unknown vulnerabilities present in said systems, including, but not limited
to the implementation of security controls, human- or electronically-enabled.

The use of this code is **only** endorsed by the developers in those
circumstances directly related to **educational environments** or
**authorized penetration testing engagements** whose declared purpose is that
of finding and mitigating vulnerabilities in systems, limiting their exposure
to compromises and exploits employed by malicious agents as defined in their
respective threat models.
