#!/usr/bin/env python3
"""
Multi-Device Modbus Network Scanner
Authored by: Hex

This script performs comprehensive Modbus network scanning to identify active devices,
extract device information, and hunt for flags in register data. Designed for CTF
competitions where speed and thoroughness are critical.

Usage:
    python3 modbus_network_scanner.py <IP_RANGE>
    python3 modbus_network_scanner.py 192.168.1.0/24
    python3 modbus_network_scanner.py 10.10.0.1-50
"""

import sys
import ipaddress
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pymodbus.client import ModbusTcpClient
from pymodbus.exceptions import ConnectionException, ModbusIOException

class ModbusScanner:
    def __init__(self, timeout=3, max_workers=20):
        self.timeout = timeout
        self.max_workers = max_workers
        self.results = []
        self.lock = threading.Lock()
        
    def scan_device(self, ip):
        """Scan a single IP for Modbus devices"""
        try:
            client = ModbusTcpClient(str(ip), port=502, timeout=self.timeout)
            
            if not client.connect():
                return None
                
            device_info = {
                'ip': str(ip),
                'port': 502,
                'accessible': True,
                'unit_ids': [],
                'registers': {},
                'coils': {},
                'flags': []
            }
            
            # Test multiple unit IDs (common range 1-247)
            for unit_id in [1, 2, 3, 4, 5, 10, 247]:
                try:
                    # Try to read holding registers
                    response = client.read_holding_registers(0, 10, slave=unit_id)
                    if not response.isError():
                        device_info['unit_ids'].append(unit_id)
                        device_info['registers'][unit_id] = response.registers
                        
                        # Hunt for flags in registers
                        flag_data = self.hunt_flags_in_registers(response.registers)
                        if flag_data:
                            device_info['flags'].extend(flag_data)
                            
                    # Try to read coils
                    coil_response = client.read_coils(0, 10, slave=unit_id)
                    if not coil_response.isError():
                        device_info['coils'][unit_id] = coil_response.bits
                        
                except (ModbusIOException, ConnectionException):
                    continue
                    
            client.close()
            
            if device_info['unit_ids']:
                with self.lock:
                    self.results.append(device_info)
                print(f"[+] Modbus device found: {ip} (Unit IDs: {device_info['unit_ids']})")
                
                # Print any flags found
                for flag in device_info['flags']:
                    print(f"    [FLAG] {flag}")
                    
            return device_info
            
        except Exception as e:
            return None
    
    def hunt_flags_in_registers(self, registers):
        """Hunt for CTF flags in register data"""
        flags = []
        
        # Convert registers to bytes and look for ASCII patterns
        byte_data = b''
        for reg in registers:
            # Each register is 16 bits, convert to 2 bytes
            byte_data += reg.to_bytes(2, byteorder='big')
            
        try:
            # Try to decode as ASCII
            ascii_data = byte_data.decode('ascii', errors='ignore')
            
            # Look for THM{} flag pattern
            import re
            flag_pattern = r'THM\{[^}]+\}'
            matches = re.findall(flag_pattern, ascii_data)
            flags.extend(matches)
            
            # Look for other common flag patterns
            generic_patterns = [
                r'flag\{[^}]+\}',
                r'FLAG\{[^}]+\}',
                r'ctf\{[^}]+\}',
                r'CTF\{[^}]+\}'
            ]
            
            for pattern in generic_patterns:
                matches = re.findall(pattern, ascii_data, re.IGNORECASE)
                flags.extend(matches)
                
        except:
            pass
            
        return flags
    
    def scan_range(self, ip_range):
        """Scan a range of IP addresses"""
        print(f"[*] Starting Modbus scan of {ip_range}")
        print(f"[*] Using {self.max_workers} threads with {self.timeout}s timeout")
        
        # Parse IP range
        ips = self.parse_ip_range(ip_range)
        
        if not ips:
            print("[-] Invalid IP range format")
            return
            
        print(f"[*] Scanning {len(ips)} addresses...")
        
        # Use ThreadPoolExecutor for concurrent scanning
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_ip = {executor.submit(self.scan_device, ip): ip for ip in ips}
            
            completed = 0
            for future in as_completed(future_to_ip):
                completed += 1
                if completed % 50 == 0:
                    print(f"[*] Progress: {completed}/{len(ips)} addresses scanned")
                    
        print(f"\n[*] Scan complete. Found {len(self.results)} Modbus devices")
        self.print_summary()
    
    def parse_ip_range(self, ip_range):
        """Parse various IP range formats"""
        ips = []
        
        try:
            if '/' in ip_range:
                # CIDR notation (e.g., 192.168.1.0/24)
                network = ipaddress.ip_network(ip_range, strict=False)
                ips = list(network.hosts())
            elif '-' in ip_range:
                # Range notation (e.g., 192.168.1.1-50)
                start_ip, end_part = ip_range.split('-')
                start = ipaddress.ip_address(start_ip)
                
                # Extract the last octet range
                base_ip = '.'.join(start_ip.split('.')[:-1])
                start_last = int(start_ip.split('.')[-1])
                end_last = int(end_part)
                
                for i in range(start_last, end_last + 1):
                    ips.append(ipaddress.ip_address(f"{base_ip}.{i}"))
            else:
                # Single IP
                ips = [ipaddress.ip_address(ip_range)]
                
        except Exception as e:
            print(f"[-] Error parsing IP range: {e}")
            return []
            
        return ips
    
    def print_summary(self):
        """Print scan results summary"""
        if not self.results:
            print("[-] No Modbus devices found")
            return
            
        print("\n" + "="*60)
        print("MODBUS SCAN RESULTS")
        print("="*60)
        
        total_flags = 0
        for device in self.results:
            print(f"\nDevice: {device['ip']}:502")
            print(f"  Unit IDs: {device['unit_ids']}")
            
            if device['flags']:
                print(f"  FLAGS FOUND:")
                for flag in device['flags']:
                    print(f"    {flag}")
                    total_flags += 1
            
            # Show register data
            for unit_id, registers in device['registers'].items():
                print(f"  Unit {unit_id} Registers (0-9): {registers}")
                
        print(f"\n[+] Total devices found: {len(self.results)}")
        print(f"[+] Total flags found: {total_flags}")
        
    def deep_register_scan(self, ip, unit_id=1, start_reg=0, count=1000):
        """Perform deep scan of specific device registers"""
        print(f"[*] Deep scanning {ip} Unit {unit_id} registers {start_reg}-{start_reg+count-1}")
        
        try:
            client = ModbusTcpClient(ip, port=502, timeout=self.timeout)
            if not client.connect():
                print(f"[-] Could not connect to {ip}")
                return
                
            # Scan in chunks to avoid overwhelming the device
            chunk_size = 100
            all_flags = []
            
            for start in range(start_reg, start_reg + count, chunk_size):
                try:
                    response = client.read_holding_registers(start, min(chunk_size, count - (start - start_reg)), slave=unit_id)
                    if not response.isError():
                        flags = self.hunt_flags_in_registers(response.registers)
                        if flags:
                            all_flags.extend(flags)
                            print(f"  [FLAG] Found at registers {start}-{start+len(response.registers)-1}: {flags}")
                            
                except Exception as e:
                    continue
                    
            client.close()
            
            if all_flags:
                print(f"[+] Deep scan complete. Found {len(all_flags)} flags total")
            else:
                print("[-] Deep scan complete. No flags found")
                
        except Exception as e:
            print(f"[-] Deep scan error: {e}")

def main():
    if len(sys.argv) != 2:
        print("Usage: python3 modbus_network_scanner.py <IP_RANGE>")
        print("Examples:")
        print("  python3 modbus_network_scanner.py 192.168.1.0/24")
        print("  python3 modbus_network_scanner.py 10.10.0.1-50")
        print("  python3 modbus_network_scanner.py 192.168.1.100")
        sys.exit(1)
        
    ip_range = sys.argv[1]
    scanner = ModbusScanner(timeout=3, max_workers=20)
    
    start_time = time.time()
    scanner.scan_range(ip_range)
    end_time = time.time()
    
    print(f"\n[*] Scan completed in {end_time - start_time:.2f} seconds")
    
    # If devices were found, offer deep scan option
    if scanner.results:
        print("\n[*] For deep register scanning of a specific device, use:")
        for device in scanner.results[:3]:  # Show first 3 devices
            print(f"  scanner.deep_register_scan('{device['ip']}', unit_id={device['unit_ids'][0]})")

if __name__ == "__main__":
    main()