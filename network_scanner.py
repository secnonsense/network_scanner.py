import argparse
import ipaddress
import sys
import time
import requests
import nmap
import netifaces
from scapy.all import ARP, Ether, srp, conf
import logging
import os

# Suppress Scapy IPv6 warning if not needed
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

def get_local_network_info():
    """
    Detects the local IP address and default gateway to infer the network.
    Returns (ip_address, netmask, gateway_ip) or (None, None, None) if not found.
    """
    try:
        gws = netifaces.gateways()
        default_gateway_interface = gws['default'][netifaces.AF_INET][1]
        
        # Get interface addresses
        addresses = netifaces.ifaddresses(default_gateway_interface)
        
        if netifaces.AF_INET in addresses:
            ipv4_info = addresses[netifaces.AF_INET][0]
            ip_address = ipv4_info['addr']
            netmask = ipv4_info['netmask']
            gateway_ip = gws['default'][netifaces.AF_INET][0]
            
            # Convert netmask to CIDR prefix
            try:
                # ip_network expects str for netmask argument
                network = ipaddress.ip_network(f"{ip_address}/{netmask}", strict=False)
                return str(network.network_address), str(network.netmask), gateway_ip, str(network.prefixlen)
            except ipaddress.NetmaskValueError:
                print(f"Warning: Could not determine CIDR for {ip_address}/{netmask}. Please specify network manually.")
                return ip_address, netmask, gateway_ip, None # Return netmask as is if CIDR conversion fails
            
    except Exception as e:
        print(f"Error detecting local network info: {e}. Please specify the network manually using -n.")
        return None, None, None, None

def get_oui_manufacturer(mac_address):
    """
    Looks up the manufacturer of a MAC address's OUI using macvendors.com.
    """
    if not mac_address:
        return "Unknown"
    
    # Ensure MAC address is in the correct format (XX:XX:XX:XX:XX:XX)
    mac_address = mac_address.replace('-', ':').upper()

    api_url = f"https://api.macvendors.com/{mac_address}"
    try:
        response = requests.get(api_url, timeout=5)
        response.raise_for_status()  # Raise an HTTPError for bad responses (4xx or 5xx)
        return response.text.strip()
    except requests.exceptions.RequestException as e:
        # print(f"Warning: Could not retrieve OUI manufacturer for {mac_address}: {e}")
        return "Not Found / Unknown"

def arp_scan(network_cidr):
    """
    Performs an ARP scan on the given network CIDR to discover active hosts.
    Returns a dictionary of {ip_address: mac_address}.
    """
    print(f"\n[+] Performing ARP scan on {network_cidr} to discover active hosts...")
    
    # Set Scapy's verbosity
    conf.verb = 0 
    
    ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=network_cidr), timeout=2, inter=0.1)
    
    active_hosts = {}
    for sent, received in ans:
        ip = received.psrc
        mac = received.hwsrc
        active_hosts[ip] = mac
    
    print(f"[+] Discovered {len(active_hosts)} active hosts via ARP.")
    return active_hosts

def nmap_scan_host(ip_address):
    """
    Performs a more in-depth Nmap scan on a single host for open ports and OS detection.
    Returns a dictionary with 'ports', 'os', 'hostname'.
    """
    print(f"    [->] Scanning {ip_address} with Nmap for ports and OS...")
    nm = nmap.PortScanner()
    
    try:
        # -T4: faster execution
        # -O: OS detection
        # -sS: SYN scan (requires root)
        # -p 1-1024: scan common ports
        # If running as non-root, use -sT (TCP connect scan) instead of -sS
        # For a more comprehensive port scan, use -p- (all ports) but it will be much slower
        nm.scan(ip_address, arguments='-T4 -O -sS -p 1-1024') 
        
        host_info = {}
        if ip_address in nm.all_hosts():
            host_data = nm[ip_address]
            
            # Hostname
            hostname = host_data['hostnames'][0]['name'] if host_data['hostnames'] else 'N/A'
            host_info['hostname'] = hostname if hostname else 'N/A'

            # Open Ports
            open_ports = []
            if 'tcp' in host_data:
                for port, data in host_data['tcp'].items():
                    if data['state'] == 'open':
                        service = data.get('name', 'unknown')
                        product = data.get('product', '')
                        version = data.get('version', '')
                        extra = f" ({product} {version})".strip() if product or version else ""
                        open_ports.append(f"{port}/{data['state']} ({service}{extra})")
            host_info['ports'] = open_ports if open_ports else "No common ports open"

            # OS Guess
            os_guess = "N/A"
            if 'osmatch' in host_data and host_data['osmatch']:
                os_guess = host_data['osmatch'][0]['name']
            elif 'osclass' in host_data and host_data['osclass']:
                os_guess = host_data['osclass'][0]['osfamily'] + " " + host_data['osclass'][0]['osgen']
            host_info['os'] = os_guess
            
            return host_info
            
    except nmap.PortScannerError as e:
        print(f"        [!] Nmap scan error for {ip_address}: {e}. Ensure nmap is installed and accessible, and you have sufficient permissions (e.g., run with sudo).")
    except Exception as e:
        print(f"        [!] An unexpected error occurred during Nmap scan for {ip_address}: {e}")
    
    return {'hostname': 'N/A', 'ports': 'N/A', 'os': 'N/A'}

def main():
    parser = argparse.ArgumentParser(description="Scan local network for hosts, ports, MACs, OS, and OUI manufacturers.")
    parser.add_argument('-n', '--network', type=str, 
                        help="Specify the network to scan (e.g., 192.168.1.0/24). If not provided, will attempt to auto-detect.")
    
    args = parser.parse_args()

    network_to_scan = args.network
    if not network_to_scan:
        print("[*] Attempting to auto-detect local network...")
        ip, netmask, gateway, prefixlen = get_local_network_info()
        if ip and netmask and prefixlen:
            network_to_scan = f"{ip}/{prefixlen}"
            print(f"[*] Detected network: {network_to_scan}")
            print(f"[*] Gateway: {gateway}")
        else:
            print("[!] Could not auto-detect network. Please specify it using the -n argument (e.g., 192.168.1.0/24).")
            sys.exit(1)
    else:
        try:
            # Validate user-provided network
            ipaddress.ip_network(network_to_scan, strict=False)
        except ValueError:
            print(f"[!] Invalid network format: {network_to_scan}. Please use CIDR notation (e.g., 192.168.1.0/24).")
            sys.exit(1)

    print(f"\n--- Starting Network Scan on {network_to_scan} ---")
    
    # Step 1: ARP Scan for initial host discovery and MACs
    active_hosts_macs = arp_scan(network_to_scan)
    
    if not active_hosts_macs:
        print("[!] No active hosts found on the network via ARP. Exiting.")
        sys.exit(0)

    print("\n--- Performing Detailed Scans (Ports, OS, OUI) ---")
    scanned_results = {}
    
    for ip_address, mac_address in active_hosts_macs.items():
        print(f"\n[+] Processing host: {ip_address} (MAC: {mac_address})")
        
        # Step 2: Nmap Scan for ports and OS
        nmap_data = nmap_scan_host(ip_address)
        
        # Step 3: OUI Lookup
        oui_manufacturer = get_oui_manufacturer(mac_address)
        
        scanned_results[ip_address] = {
            'mac_address': mac_address,
            'oui_manufacturer': oui_manufacturer,
            'hostname': nmap_data.get('hostname', 'N/A'),
            'open_ports': nmap_data.get('ports', 'N/A'),
            'os_guess': nmap_data.get('os', 'N/A')
        }
        time.sleep(0.1) # Small delay to be polite to APIs/network

    print("\n--- Scan Results ---")
    print(scanned_results)
    quit()
    if not scanned_results:
        print("No detailed information found for any host.")
        return

    for ip, data in scanned_results.items():
        print(f"\n-----------------------------------------------------")
        print(f"  IP Address:     {ip}")
        print(f"  MAC Address:    {data['mac_address']}")
        print(f"  Manufacturer:   {data['oui_manufacturer']}")
        print(f"  Hostname:       {data['hostname']}")
        print(f"  OS Guess:       {data['os_guess']}")
        print(f"  Open Ports:")
        if isinstance(data['open_ports'], list):
            if data['open_ports']:
                for port_info in data['open_ports']:
                    print(f"    - {port_info}")
            else:
                print(f"    No common ports (1-1024) open.")
        else:
            print(f"    {data['open_ports']}")
        print(f"-----------------------------------------------------")

    print("\n--- Scan Complete ---")

if __name__ == "__main__":
    if sys.platform != "win32":
        # Check for root privileges on Linux/macOS
        if os.geteuid() != 0:
            print("This script requires root privileges to run (for Scapy and Nmap raw sockets). Please run with 'sudo'.")
            sys.exit(1)
    
   
    main()
