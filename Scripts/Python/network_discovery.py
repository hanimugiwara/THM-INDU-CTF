#!/usr/bin/env python3
"""
Network Discovery Tool - Comprehensive Network Mapping
Authored by: Hex

Advanced network discovery and service enumeration tool designed for
rapid reconnaissance and comprehensive network mapping.

Usage:
    python3 network_discovery.py --target 192.168.1.0/24
    python3 network_discovery.py --target 10.10.0.1-254 --threads 100
    python3 network_discovery.py --target targets.txt --service-scan --output results.json
"""

import argparse
import ipaddress
import json
import socket
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests

class NetworkDiscovery:
    def __init__(self, timeout=3, threads=50, stealth=False):
        self.timeout = timeout
        self.threads = threads
        self.stealth = stealth
        self.results = {}
        self.lock = threading.Lock()
        
        # Common service ports
        self.common_ports = [
            21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 993, 995,
            1723, 3306, 3389, 5432, 5900, 8080, 8443, 502, 102, 20000,
            47808, 44818, 161, 162, 514, 623, 1433, 1521, 2049, 6379
        ]
        
        # Industrial protocol ports
        self.ics_ports = [
            102,    # S7 Protocol
            502,    # Modbus TCP
            20000,  # DNP3
            44818,  # EtherNet/IP
            47808,  # BACnet
            4840,   # OPC UA
            1962,   # PCWorx
            9600,   # T3000 Building Automation
            789,    # RedLion
            2455,   # WAGO
            1911,   # Niagara Fox
            5007,   # Omron FINS
            8080,   # HTTP (often used for HMI)
            8443    # HTTPS (often used for HMI)
        ]
    
    def parse_targets(self, target_input):
        """Parse various target input formats"""
        targets = []
        
        try:
            # Check if it's a file
            try:
                with open(target_input, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            targets.extend(self.parse_ip_range(line))
                return targets
            except FileNotFoundError:
                pass
            
            # Parse as IP range
            return self.parse_ip_range(target_input)
            
        except Exception as e:
            print(f"[-] Error parsing targets: {e}")
            return []
    
    def parse_ip_range(self, ip_range):
        """Parse IP range in various formats"""
        ips = []
        
        try:
            if '/' in ip_range:
                # CIDR notation
                network = ipaddress.ip_network(ip_range, strict=False)
                ips = [str(ip) for ip in network.hosts()]
            elif '-' in ip_range:
                # Range notation (e.g., 192.168.1.1-254)
                start_ip, end_part = ip_range.split('-', 1)
                start = ipaddress.ip_address(start_ip)
                
                if '.' in end_part:
                    # Full IP range
                    end = ipaddress.ip_address(end_part)
                    current = start
                    while current <= end:
                        ips.append(str(current))
                        current += 1
                else:
                    # Last octet range
                    base_ip = '.'.join(start_ip.split('.')[:-1])
                    start_last = int(start_ip.split('.')[-1])
                    end_last = int(end_part)
                    
                    for i in range(start_last, end_last + 1):
                        ips.append(f"{base_ip}.{i}")
            else:
                # Single IP
                ips = [str(ipaddress.ip_address(ip_range))]
                
        except Exception as e:
            print(f"[-] Error parsing IP range {ip_range}: {e}")
            return []
        
        return ips
    
    def ping_host(self, ip):
        """Check if host is alive using ping"""
        try:
            if sys.platform.startswith('win'):
                cmd = ['ping', '-n', '1', '-w', '1000', ip]
            else:
                cmd = ['ping', '-c', '1', '-W', '1', ip]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            return result.returncode == 0
        except:
            return False
    
    def scan_port(self, ip, port):
        """Scan single port on target"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((ip, port))
            sock.close()
            
            if result == 0:
                return port
            return None
        except:
            return None
    
    def banner_grab(self, ip, port):
        """Grab service banner"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((ip, port))
            
            # Send HTTP request for web services
            if port in [80, 8080, 8000, 3000]:
                sock.send(b"GET / HTTP/1.1\r\nHost: " + ip.encode() + b"\r\n\r\n")
            elif port in [443, 8443]:
                # Skip HTTPS banner grabbing for now
                sock.close()
                return self.http_banner_grab(ip, port, https=True)
            else:
                # For other services, just try to receive data
                pass
            
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()
            
            return banner[:200] if banner else None
            
        except:
            return None
    
    def http_banner_grab(self, ip, port, https=False):
        """Grab HTTP/HTTPS banner and title"""
        try:
            protocol = 'https' if https else 'http'
            url = f"{protocol}://{ip}:{port}"
            
            response = requests.get(url, timeout=self.timeout, verify=False)
            
            banner_info = {
                'status_code': response.status_code,
                'server': response.headers.get('Server', 'Unknown'),
                'title': self.extract_title(response.text),
                'content_length': len(response.content)
            }
            
            return banner_info
            
        except:
            return None
    
    def extract_title(self, html):
        """Extract title from HTML content"""
        import re
        match = re.search(r'<title[^>]*>([^<]+)</title>', html, re.IGNORECASE)
        return match.group(1).strip() if match else None
    
    def identify_service(self, port, banner=None):
        """Identify service based on port and banner"""
        service_map = {
            21: 'FTP',
            22: 'SSH',
            23: 'Telnet',
            25: 'SMTP',
            53: 'DNS',
            80: 'HTTP',
            110: 'POP3',
            135: 'RPC',
            139: 'NetBIOS',
            143: 'IMAP',
            443: 'HTTPS',
            993: 'IMAPS',
            995: 'POP3S',
            1723: 'PPTP',
            3306: 'MySQL',
            3389: 'RDP',
            5432: 'PostgreSQL',
            5900: 'VNC',
            8080: 'HTTP-Alt',
            8443: 'HTTPS-Alt',
            # Industrial protocols
            102: 'S7',
            502: 'Modbus',
            20000: 'DNP3',
            44818: 'EtherNet/IP',
            47808: 'BACnet',
            4840: 'OPC-UA',
            161: 'SNMP',
            162: 'SNMP-Trap'
        }
        
        service = service_map.get(port, f'Unknown-{port}')
        
        # Refine based on banner
        if banner and isinstance(banner, str):
            banner_lower = banner.lower()
            if 'ssh' in banner_lower:
                service = 'SSH'
            elif 'ftp' in banner_lower:
                service = 'FTP'
            elif 'http' in banner_lower:
                service = 'HTTP'
            elif 'smtp' in banner_lower:
                service = 'SMTP'
            elif 'mysql' in banner_lower:
                service = 'MySQL'
        
        return service
    
    def scan_host(self, ip, port_list=None):
        """Comprehensive scan of single host"""
        if port_list is None:
            port_list = self.common_ports + self.ics_ports
        
        host_info = {
            'ip': ip,
            'alive': False,
            'ports': {},
            'os_guess': None,
            'scan_time': time.strftime('%Y-%m-%d %H:%M:%S')
        }
        
        # Check if host is alive
        if not self.ping_host(ip):
            return host_info
        
        host_info['alive'] = True
        print(f"[+] Host {ip} is alive, scanning ports...")
        
        # Scan ports
        open_ports = []
        for port in port_list:
            if self.scan_port(ip, port):
                open_ports.append(port)
        
        if not open_ports:
            return host_info
        
        print(f"  [+] Found {len(open_ports)} open ports: {open_ports}")
        
        # Banner grabbing and service identification
        for port in open_ports:
            banner = self.banner_grab(ip, port)
            service = self.identify_service(port, banner)
            
            host_info['ports'][port] = {
                'service': service,
                'banner': banner,
                'state': 'open'
            }
            
            if self.stealth:
                time.sleep(0.1)  # Small delay between banner grabs
        
        # Simple OS fingerprinting based on open ports
        host_info['os_guess'] = self.guess_os(open_ports)
        
        with self.lock:
            self.results[ip] = host_info
        
        return host_info
    
    def guess_os(self, open_ports):
        """Simple OS guessing based on open ports"""
        if 3389 in open_ports:  # RDP
            return "Windows"
        elif 22 in open_ports and 135 not in open_ports:  # SSH but no RPC
            return "Linux/Unix"
        elif any(port in open_ports for port in [102, 502, 20000]):  # Industrial protocols
            return "Industrial Device/PLC"
        elif 161 in open_ports:  # SNMP
            return "Network Device"
        else:
            return "Unknown"
    
    def scan_network(self, targets, port_list=None, service_scan=False):
        """Scan multiple targets"""
        if not targets:
            print("[-] No targets to scan")
            return
        
        print(f"[*] Starting network scan of {len(targets)} targets")
        print(f"[*] Using {self.threads} threads with {self.timeout}s timeout")
        
        if service_scan:
            print(f"[*] Service scanning enabled")
        
        start_time = time.time()
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            if service_scan:
                # Full service scan
                futures = {executor.submit(self.scan_host, ip, port_list): ip for ip in targets}
            else:
                # Quick alive check only
                futures = {executor.submit(self.ping_host, ip): ip for ip in targets}
            
            completed = 0
            alive_hosts = 0
            
            for future in as_completed(futures):
                completed += 1
                ip = futures[future]
                
                try:
                    if service_scan:
                        result = future.result()
                        if result['alive']:
                            alive_hosts += 1
                    else:
                        if future.result():
                            alive_hosts += 1
                            print(f"[+] Host {ip} is alive")
                            self.results[ip] = {
                                'ip': ip,
                                'alive': True,
                                'ports': {},
                                'scan_time': time.strftime('%Y-%m-%d %H:%M:%S')
                            }
                
                except Exception as e:
                    print(f"[-] Error scanning {ip}: {e}")
                
                if completed % 50 == 0:
                    print(f"[*] Progress: {completed}/{len(targets)} hosts scanned")
        
        end_time = time.time()
        
        print(f"\n[*] Scan completed in {end_time - start_time:.2f} seconds")
        print(f"[*] Found {alive_hosts} alive hosts out of {len(targets)} scanned")
    
    def detect_industrial_systems(self):
        """Analyze results for industrial control systems"""
        ics_hosts = []
        
        for ip, host_info in self.results.items():
            if not host_info['alive']:
                continue
            
            ics_indicators = []
            
            for port, port_info in host_info['ports'].items():
                service = port_info['service']
                
                if service in ['Modbus', 'S7', 'DNP3', 'EtherNet/IP', 'BACnet', 'OPC-UA']:
                    ics_indicators.append(service)
                elif port in self.ics_ports:
                    ics_indicators.append(f"Port-{port}")
                
                # Check banners for industrial keywords
                banner = port_info.get('banner')
                if banner and isinstance(banner, dict):
                    title = banner.get('title', '')
                    if any(keyword in title.lower() for keyword in ['scada', 'hmi', 'plc', 'industrial', 'control']):
                        ics_indicators.append(f"HMI-{title}")
            
            if ics_indicators:
                ics_hosts.append({
                    'ip': ip,
                    'indicators': ics_indicators,
                    'open_ports': list(host_info['ports'].keys())
                })
        
        return ics_hosts
    
    def generate_report(self, output_file=None):
        """Generate comprehensive scan report"""
        # Analyze for industrial systems
        ics_systems = self.detect_industrial_systems()
        
        report = {
            'scan_summary': {
                'total_targets': len(self.results),
                'alive_hosts': len([h for h in self.results.values() if h['alive']]),
                'total_open_ports': sum(len(h['ports']) for h in self.results.values()),
                'ics_systems_found': len(ics_systems),
                'scan_timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
            },
            'hosts': self.results,
            'industrial_systems': ics_systems,
            'service_summary': self.generate_service_summary()
        }
        
        if output_file:
            with open(output_file, 'w') as f:
                json.dump(report, f, indent=2)
            print(f"[+] Report saved to {output_file}")
        
        return report
    
    def generate_service_summary(self):
        """Generate summary of discovered services"""
        service_count = {}
        
        for host_info in self.results.values():
            for port_info in host_info['ports'].values():
                service = port_info['service']
                service_count[service] = service_count.get(service, 0) + 1
        
        return dict(sorted(service_count.items(), key=lambda x: x[1], reverse=True))
    
    def print_summary(self):
        """Print scan results summary"""
        print("\n" + "="*60)
        print("NETWORK DISCOVERY - SCAN SUMMARY")
        print("="*60)
        
        alive_hosts = [h for h in self.results.values() if h['alive']]
        total_ports = sum(len(h['ports']) for h in alive_hosts)
        
        print(f"Total Hosts Scanned: {len(self.results)}")
        print(f"Alive Hosts: {len(alive_hosts)}")
        print(f"Total Open Ports: {total_ports}")
        
        # Service summary
        service_summary = self.generate_service_summary()
        if service_summary:
            print(f"\nTop Services Found:")
            for service, count in list(service_summary.items())[:10]:
                print(f"  {service}: {count}")
        
        # Industrial systems
        ics_systems = self.detect_industrial_systems()
        if ics_systems:
            print(f"\n[!] INDUSTRIAL CONTROL SYSTEMS DETECTED:")
            for ics in ics_systems:
                print(f"  {ics['ip']}: {', '.join(ics['indicators'])}")
        
        # Detailed host information
        print(f"\nDetailed Host Information:")
        for ip, host_info in sorted(self.results.items()):
            if host_info['alive'] and host_info['ports']:
                print(f"\n{ip} ({host_info.get('os_guess', 'Unknown OS')}):")
                for port, port_info in sorted(host_info['ports'].items()):
                    banner_info = ""
                    if port_info['banner']:
                        if isinstance(port_info['banner'], dict):
                            title = port_info['banner'].get('title')
                            server = port_info['banner'].get('server')
                            if title:
                                banner_info = f" - {title}"
                            elif server:
                                banner_info = f" - {server}"
                        else:
                            banner_info = f" - {port_info['banner'][:50]}"
                    
                    print(f"  {port}/{port_info['service']}{banner_info}")
        
        print("="*60)

def main():
    parser = argparse.ArgumentParser(description='Network Discovery - Comprehensive network mapping')
    parser.add_argument('--target', '-t', required=True, help='Target IP/range/file')
    parser.add_argument('--ports', help='Comma-separated list of ports to scan')
    parser.add_argument('--threads', type=int, default=50, help='Number of threads')
    parser.add_argument('--timeout', type=int, default=3, help='Socket timeout')
    parser.add_argument('--service-scan', action='store_true', help='Enable service detection')
    parser.add_argument('--stealth', action='store_true', help='Enable stealth mode')
    parser.add_argument('--output', '-o', help='Output file (JSON format)')
    parser.add_argument('--quick', action='store_true', help='Quick scan (ping only)')
    
    args = parser.parse_args()
    
    # Parse port list
    port_list = None
    if args.ports:
        try:
            port_list = [int(p.strip()) for p in args.ports.split(',')]
        except ValueError:
            print("[-] Invalid port list format")
            sys.exit(1)
    
    # Create discovery instance
    discovery = NetworkDiscovery(args.timeout, args.threads, args.stealth)
    
    # Parse targets
    targets = discovery.parse_targets(args.target)
    if not targets:
        print("[-] No valid targets found")
        sys.exit(1)
    
    # Perform scan
    if args.quick:
        discovery.scan_network(targets, service_scan=False)
    else:
        discovery.scan_network(targets, port_list, args.service_scan)
    
    # Generate and display results
    discovery.print_summary()
    
    if args.output:
        discovery.generate_report(args.output)

if __name__ == "__main__":
    main()