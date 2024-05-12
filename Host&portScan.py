import socket
import logging
from scapy.all import ARP, Ether, srp

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)  # Suppress scapy IPv6 warning


def scan_network(ip_range):
    print("Scanning network...")
    arp_request = ARP(pdst=ip_range)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = srp(arp_request_broadcast, timeout=5, verbose=False)[0]

    live_hosts = []
    for element in answered_list:
        live_host = {
            "ip": element[1].psrc,
            "mac": element[1].hwsrc,
            "name": socket.gethostbyaddr(element[1].psrc)[0]  # Get device name
        }
        live_hosts.append(live_host)
    print("Network scan completed.")
    return live_hosts


def scan_ports(ip):
    print(f"Scanning ports on {ip}...")
    open_ports = []
    try:
        for port in range(1, 1250):
            print(f"Scanning port {port} on {ip}...")
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.05)
                result = s.connect_ex((ip, port))
                if result == 0:
                    print(f"Port {port} on {ip} is open.")
                    open_ports.append(port)
                else:
                    print(f"Port {port} on {ip} is closed.")
    except socket.error as e:
        print(f"Error: {e}")
    print(f"Port scan on {ip} completed.")
    return open_ports


if __name__ == "__main__":
    target = input("Enter IP address or network range (e.g., 192.168.1.1 or 192.168.1.0/24): ")

    if "/" in target:  # Check if it's a network range
        live_hosts = scan_network(target)
        print("Live hosts in the network:")
        for host in live_hosts:
            print(f"Name: {host['name']}, IP: {host['ip']}, MAC: {host['mac']}")
    else:
        open_ports = scan_ports(target)
        if open_ports:
            print(f"Open ports on {target}: {open_ports}")
        else:
            print(f"No open ports found on {target}.")
