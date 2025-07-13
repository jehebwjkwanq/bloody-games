import ipaddress
from scapy.all import ARP, Ether, srp
import socket
import threading
import subprocess
from colorama import Fore, Back, Style, init

# Initialize colorama for Termux compatibility
init(autoreset=True)

# Blood-red ASCII art
ASCII_ART = f"""{Fore.RED}
 
██████╗ ███████╗ █████╗ ██████╗ ███████╗
██╔══██╗██╔════╝██╔══██╗██╔══██╗██╔════╝
██║  ██║█████╗  ███████║██║  ██║███████╗
██║  ██║██╔══╝  ██╔══██║██║  ██║╚════██║
██████╔╝███████╗██║  ██║██████╔╝███████║
╚═════╝ ╚══════╝╚═╝  ╚═╝╚═════╝ ╚══════╝
{Style.RESET_ALL}
"""

def arp_scan(network):
    """Scan network using ARP protocol to find active devices"""
    arp = ARP(pdst=str(network))
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp
    
    # Send packet and capture responses
    result = srp(packet, timeout=2, verbose=0)[0]
    
    # Parse results
    clients = []
    for sent, received in result:
        clients.append({"ip": received.psrc, "mac": received.hwsrc})
    return clients

def scan_ports(ip):
    """Scan common ports on a target IP address"""
    open_ports = []
    common_ports = [20, 21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 8080]
    
    def port_scan(port):
        try:
            with socket.create_connection((ip, port), timeout=0.5):
                open_ports.append(port)
        except:
            pass
    
    # Create and start threads for each port
    threads = []
    for port in common_ports:
        t = threading.Thread(target=port_scan, args=(port,))
        t.start()
        threads.append(t)
    
    # Wait for all threads to complete
    for t in threads:
        t.join()
    
    return open_ports

def main():
    print(ASCII_ART)
    
    target_ip = input(f"{Fore.RED}Enter IP or network to scan (e.g., 192.168.1.0/24): {Style.RESET_ALL}")
    
    try:
        # Parse input as network or single IP
        if '/' in target_ip:
            network = ipaddress.ip_network(target_ip, strict=False)
        else:
            ip = ipaddress.ip_address(target_ip)
            network = ipaddress.ip_network(f"{ip}/24", strict=False)
    except ValueError:
        print(f"{Fore.RED}Invalid IP/network format. Please try again.{Style.RESET_ALL}")
        return

    print(f"\n{Fore.RED}[+] Scanning network: {network}{Style.RESET_ALL}\n")
    
    # Perform ARP scan
    devices = arp_scan(network)
    
    if not devices:
        print(f"{Fore.RED}No devices found on the network.{Style.RESET_ALL}")
        return

    print(f"{Fore.RED}[+] Devices found on the network:{Style.RESET_ALL}")
    for device in devices:
        ip = device['ip']
        print(f"{Fore.RED}IP: {ip} | MAC: {device['mac']}{Style.RESET_ALL}")
        open_ports = scan_ports(ip)
        if open_ports:
            print(f"{Fore.RED}  Open ports: {', '.join(map(str, open_ports))}{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}  No open ports found in the scanned range.{Style.RESET_ALL}")

if __name__ == "__main__":
    main()