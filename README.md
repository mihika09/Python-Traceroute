# Python-Traceroute
Implementation of traceroute in Python 3.x using raw sockets.

Note that ICMP messages can only be sent from processes running as root (in Windows, you must run this script as 'Administrator').

Derived from Python's pyping library.

## Usage

### Use as a cli tool:

Python-Traceroute: sudo python traceroute.py google.com  

```
traceroute to google.com (172.217.26.206), 64 hops max, 55 byte packets
 1  192.168.0.1 (192.168.0.1) 2.067ms 1.666 ms 1.631 ms 
 2  blr-walton-core01.static.youbroadband.in (203.187.252.65) 12.784ms 9.951 ms 10.469 ms 
 3  * * * 
 4  33-244-187-203.static.youbroadband.in (203.187.244.33) 14.187ms 13.794 ms 12.858 ms 
 5  108.170.253.97 (108.170.253.97) 17.465ms 12.987 ms 12.511 ms 
 6  74.125.253.69 (74.125.253.69) 14.126ms 13.408 ms 15.907 ms 
 7  maa03s23-in-f206.1e100.net (172.217.26.206) 18.303ms 17.773 ms 15.810 ms  
```

Python-Traceroute: sudo python traceroute.py google.com -c 1  

```
traceroute to google.com (172.217.31.206), 64 hops max, 55 byte packets
 1  192.168.0.1 (192.168.0.1) 2.667ms 
 2  blr-walton-core01.static.youbroadband.in (203.187.252.65) 13.707ms 
 3  * 
 4  33-244-187-203.static.youbroadband.in (203.187.244.33) 22.558ms 
 5  108.170.253.113 (108.170.253.113) 15.897ms 
 6  74.125.253.13 (74.125.253.13) 14.415ms 
 7  maa03s28-in-f14.1e100.net (172.217.31.206) 12.154ms 
``` 
 
  
#### For positional/optional arguments:
Python-Ping: sudo python traceroute.py --help  


### Use as a Python library

Copy the repository and then import the file  

import sys  
sys.path.insert(0, './Python-Traceroute')  
from traceroute import traceroute
traceroute("google.com") 

```
traceroute to google.com (172.217.26.206), 64 hops max, 55 byte packets
 1  192.168.0.1 (192.168.0.1) 2.067ms 1.666 ms 1.631 ms 
 2  blr-walton-core01.static.youbroadband.in (203.187.252.65) 12.784ms 9.951 ms 10.469 ms 
 3  * * * 
 4  33-244-187-203.static.youbroadband.in (203.187.244.33) 14.187ms 13.794 ms 12.858 ms 
 5  108.170.253.97 (108.170.253.97) 17.465ms 12.987 ms 12.511 ms 
 6  74.125.253.69 (74.125.253.69) 14.126ms 13.408 ms 15.907 ms 
 7  maa03s23-in-f206.1e100.net (172.217.26.206) 18.303ms 17.773 ms 15.810 ms  
```

#### Optional Arguments:  
traceroute("google.com", count=number of packets to be sent for each hop, packet_size=packet_size in bytes, timeout=timeout in ms, max_hops = maximum hops)  
