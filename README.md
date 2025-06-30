# network_scanner.py
Gemini generated script to do a network scan capturing ARP, IP, Host OS (guess), open common ports, hostname and OUI manufacturer lookup

Requires sudo/root/admin access to run.

Python3 dependencies - pip install scapy python-nmap requests netifaces

python-nmap requires that nmap be installed locally on the system as well.

The local network should be automatically detected, but if not specify with -n/--network
