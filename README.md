# Python 3 Asynchronous TCP/IP Connect Port Scanner

![Python Version](https://img.shields.io/badge/python-3.7+-blue?style=for-the-badge&logo=python)
![OS](https://img.shields.io/badge/OS-GNU%2FLinux-red?style=for-the-badge&logo=linux)
[![CodeFactor Grade](https://img.shields.io/codefactor/grade/github/eonraider/simple-async-port-scanner?style=for-the-badge)](https://www.codefactor.io/repository/github/eonraider/simple-async-port-scanner)
[![License](https://img.shields.io/github/license/EONRaider/Packet-Sniffer?style=for-the-badge)](https://github.com/EONRaider/Packet-Sniffer/blob/master/LICENSE)

[![Reddit](https://img.shields.io/badge/Reddit-EONRaider-FF4500?style=flat-square&logo=reddit)](https://www.reddit.com/user/eonraider)
[![Discord](https://img.shields.io/badge/Discord-EONRaider-7289DA?style=flat-square&logo=discord)](https://discord.gg/KVjWBptv)
[![Twitter](https://img.shields.io/badge/Twitter-eon__raider-38A1F3?style=flat-square&logo=twitter)](https://twitter.com/intent/follow?screen_name=eon_raider)

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
user@host:~/DIR$ git clone https://github.com/EONRaider/Simple-Async-Port-Scanner.git
```

## Usage

```
usage: simple_async_scan.py [-h] -p PORTS [--open] ADDRESSES

Simple asynchronous TCP Connect port scanner

positional arguments:
  ADDRESSES             A comma-separated sequence of IP addresses and/or domain names to scan, e.g., '45.33.32.156,65.61.137.117,testphp.vulnweb.com'.

optional arguments:
  -h, --help            show this help message and exit
  -p PORTS, --ports PORTS
                        A comma-separated sequence of port numbers and/or port ranges to scan on each target specified, e.g., '20-25,53,80,443'.
  --open                Only show open ports in the scan results.

Usage examples:
1. python3 simple_async_scan.py google.com -p 80,443
2. python3 simple_async_scan.py 45.33.32.156,demo.testfire.net,18.192.172.30 -p 20-25,53,80,111,135,139,443,3306,5900
```

## Application Performance
Due to the nature of Python's `asyncio` framework results such as the 
ones shown below are possible: the first 1000 TCP/IP ports of 
[scanme.nmap.org](http://scanme.nmap.org) are scanned in **1.685 seconds**:

```
eonraider@havoc:~$ python3 simple_async_scan.py scanme.nmap.org -p 1-1000 --open
Starting Async Port Scanner at Sat Jan 30 13:41:25 2021
Scan report for scanme.nmap.org

[>] Results for scanme.nmap.org:
      PORT     STATE      SERVICE   
       22       open        ssh     
       80       open        http    

Async TCP Connect scan of 1000 ports for scanme.nmap.org completed in 1.685 seconds
```

Compared to the same procedure using `nmap` (set to skip host discovery
with -Pn and highest timing template with -T5), taking 19.79 seconds:

```
eonraider@havoc:~$ nmap scanme.nmap.org -Pn -T5 -sT -p 1-1000
Starting Nmap 7.80 ( https://nmap.org ) at 2021-01-31 18:49 -03
Warning: 45.33.32.156 giving up on port because retransmission cap hit (2).
Nmap scan report for scanme.nmap.org (45.33.32.156)
Host is up (0.23s latency).
Other addresses for scanme.nmap.org (not scanned): 2600:3c01::f03c:91ff:fe18:bb2f
Not shown: 970 closed ports, 28 filtered ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 19.79 seconds
```

*Different tests have shown the present application can be from 10 to 20
times faster than `nmap` when performing simple TCP Connect scans.*

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
eonraider@havoc:~$ python3 simple_async_scan.py 45.33.32.156,demo.testfire.net -p 20-25,53,80,111
Starting Async Port Scanner at Sat Jan 30 13:39:20 2021
Scan report for 45.33.32.156 | demo.testfire.net

[>] Results for 45.33.32.156:
      PORT     STATE      SERVICE   
       20      closed     ftp-data  
       21      closed       ftp     
       22       open        ssh     
       23      closed      telnet   
       24      closed     unknown   
       25      closed       smtp    
       53      closed      domain   
       80       open        http    
      111      closed      sunrpc   

[>] Results for demo.testfire.net:
      PORT     STATE      SERVICE   
       20      closed     ftp-data  
       21      closed       ftp     
       22      closed       ssh     
       23      closed      telnet   
       24      closed     unknown   
       25      closed       smtp    
       53      closed      domain   
       80       open        http    
      111      closed      sunrpc   

Async TCP Connect scan of 18 ports for 45.33.32.156 | demo.testfire.net completed in 3.005 seconds
```

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
