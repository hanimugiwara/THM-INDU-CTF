#!/usr/bin/env python3
"""
Modbus Register Hunter - Deep Register Scanning & Flag Extraction
Authored by: Hex

Advanced Modbus register scanning tool designed for comprehensive flag hunting
and sensitive data extraction from industrial control systems.

Usage:
    python3 modbus_register_hunter.py --target 192.168.1.100
    python3 modbus_register_hunter.py --target 192.168.1.100 --unit-id 1 --start 0 --count 10000
    python3 modbus_register_hunter.py --target 192.168.1.100 --deep-scan --output results.json
"""

import argparse
import json
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pymodbus.client import ModbusTcpClient
from pymodbus.exceptions import ConnectionException, ModbusIOException

class ModbusRegisterHunter:
    def __init__(self, target, port=502, timeout=3, unit_id=1):
        self.target = target
        self.port = port
        self.timeout = timeout
        self.unit_id = unit_id
        self.client = None
        self.flags_found = []
        self.sensitive_data = []
        
    def connect(self):
        """Establish connection to Modbus device"""
        try:
            self.client = ModbusTcpClient(self.target, port=self.port, timeout=self.timeout)
            if self.client.connect():
                print(f"[+] Connected to Modbus device at {self.target}:{self.port}")
                return True
            else:
                print(f"[-] Failed to connect to {self.target}:{self.port}")
                return False
        except Exception as e:
            print(f"[-] Connection error: {e}")
            return False
    
    def disconnect(self):
        """Close connection to Modbus device"""
        if self.client:
            self.client.close()
            print(f"[*] Disconnected from {self.target}")
    
    def read_registers(self, start_address, count, register_type='holding'):
        """Read registers from Modbus device"""
        try:
            if register_type == 'holding':
                response = self.client.read_holding_registers(start_address, count, slave=self.unit_id)
            elif register_type == 'input':
                response = self.client.read_input_registers(start_address, count, slave=self.unit_id)
            elif register_type == 'coils':
                response = self.client.read_coils(start_address, count, slave=self.unit_id)
            elif register_type == 'discrete':
                response = self.client.read_discrete_inputs(start_address, count, slave=self.unit_id)
            else:
                return None
                
            if response.isError():
                return None
            
            return response
        except Exception as e:
            return None
    
    def registers_to_ascii(self, registers):
        """Convert register values to ASCII string"""
        try:
            ascii_chars = []
            for reg in registers:
                # Each register is 16 bits, split into 2 bytes
                high_byte = (reg >> 8) & 0xFF
                low_byte = reg & 0xFF
                
                # Convert to ASCII if printable
                if 32 <= high_byte <= 126:
                    ascii_chars.append(chr(high_byte))
                else:
                    ascii_chars.append('.')
                    
                if 32 <= low_byte <= 126:
                    ascii_chars.append(chr(low_byte))
                else:
                    ascii_chars.append('.')
            
            return ''.join(ascii_chars)
        except:
            return ""
    
    def hunt_flags(self, ascii_data, start_address):
        """Hunt for CTF flags and sensitive data in ASCII data"""
        flags = []
        
        # Common flag patterns
        flag_patterns = [
            r'THM\{[^}]+\}',
            r'FLAG\{[^}]+\}',
            r'flag\{[^}]+\}',
            r'CTF\{[^}]+\}',
            r'ctf\{[^}]+\}',
            r'[A-Z0-9]{20,}',  # Long alphanumeric strings
            r'[a-f0-9]{32}',   # MD5 hashes
            r'[a-f0-9]{40}',   # SHA1 hashes
        ]
        
        for pattern in flag_patterns:
            matches = re.findall(pattern, ascii_data, re.IGNORECASE)
            for match in matches:
                if len(match.strip()) > 5:  # Filter out short meaningless matches
                    flags.append({
                        'value': match,
                        'pattern': pattern,
                        'start_address': start_address,
                        'type': 'flag' if any(x in match.lower() for x in ['thm', 'flag', 'ctf']) else 'sensitive'
                    })
        
        # Look for common sensitive keywords
        sensitive_keywords = [
            'password', 'passwd', 'secret', 'key', 'token', 'admin',
            'root', 'user', 'login', 'auth', 'credential', 'api'
        ]
        
        for keyword in sensitive_keywords:
            if keyword in ascii_data.lower():
                # Extract surrounding context
                start_pos = ascii_data.lower().find(keyword)
                context = ascii_data[max(0, start_pos-20):start_pos+50]
                flags.append({
                    'value': context.strip(),
                    'pattern': f'keyword:{keyword}',
                    'start_address': start_address,
                    'type': 'sensitive'
                })
        
        return flags
    
    def scan_register_range(self, start_address, count, register_type='holding', chunk_size=100):
        """Scan a range of registers for flags and sensitive data"""
        print(f"[*] Scanning {register_type} registers {start_address}-{start_address+count-1}")
        
        found_data = []
        
        for offset in range(0, count, chunk_size):
            current_start = start_address + offset
            current_count = min(chunk_size, count - offset)
            
            response = self.read_registers(current_start, current_count, register_type)
            
            if response:
                if register_type in ['holding', 'input']:
                    ascii_data = self.registers_to_ascii(response.registers)
                    flags = self.hunt_flags(ascii_data, current_start)
                    
                    if flags:
                        found_data.extend(flags)
                        print(f"  [+] Found {len(flags)} items at registers {current_start}-{current_start+current_count-1}")
                        for flag in flags:
                            if flag['type'] == 'flag':
                                print(f"    [FLAG] {flag['value']}")
                            else:
                                print(f"    [SENSITIVE] {flag['value'][:50]}...")
                
                elif register_type in ['coils', 'discrete']:
                    # For binary data, look for patterns
                    bit_pattern = ''.join(['1' if bit else '0' for bit in response.bits[:current_count]])
                    if '1' in bit_pattern:
                        found_data.append({
                            'value': bit_pattern,
                            'pattern': 'binary_data',
                            'start_address': current_start,
                            'type': 'binary'
                        })
                        print(f"  [+] Active bits found at {current_start}: {bit_pattern}")
            
            # Small delay to avoid overwhelming the device
            time.sleep(0.1)
        
        return found_data
    
    def comprehensive_scan(self, max_registers=10000):
        """Perform comprehensive scan of all register types"""
        print(f"[*] Starting comprehensive scan of unit {self.unit_id}")
        
        all_findings = []
        
        register_types = [
            ('holding', 0, max_registers),
            ('input', 0, max_registers // 2),
            ('coils', 0, max_registers // 4),
            ('discrete', 0, max_registers // 4)
        ]
        
        for reg_type, start, count in register_types:
            try:
                findings = self.scan_register_range(start, count, reg_type)
                all_findings.extend(findings)
                
                # Update class variables
                for finding in findings:
                    if finding['type'] == 'flag':
                        self.flags_found.append(finding)
                    else:
                        self.sensitive_data.append(finding)
                        
            except KeyboardInterrupt:
                print("\n[!] Scan interrupted by user")
                break
            except Exception as e:
                print(f"[-] Error scanning {reg_type} registers: {e}")
                continue
        
        return all_findings
    
    def targeted_scan(self, addresses, register_type='holding'):
        """Scan specific register addresses"""
        print(f"[*] Targeted scan of {len(addresses)} {register_type} registers")
        
        findings = []
        
        for address in addresses:
            response = self.read_registers(address, 1, register_type)
            if response:
                if register_type in ['holding', 'input']:
                    ascii_data = self.registers_to_ascii(response.registers)
                    flags = self.hunt_flags(ascii_data, address)
                    findings.extend(flags)
                    
                    if flags:
                        print(f"  [+] Register {address}: {ascii_data.strip()}")
                
                time.sleep(0.05)  # Short delay between reads
        
        return findings
    
    def device_fingerprint(self):
        """Attempt to fingerprint the Modbus device"""
        print(f"[*] Fingerprinting device {self.target}")
        
        fingerprint_data = {
            'target': self.target,
            'port': self.port,
            'unit_id': self.unit_id,
            'device_info': {},
            'supported_functions': []
        }
        
        # Test common function codes
        function_codes = [1, 2, 3, 4, 5, 6, 15, 16, 23]
        
        for func_code in function_codes:
            try:
                if func_code in [1, 2]:  # Read coils/discrete inputs
                    response = self.client.read_coils(0, 1, slave=self.unit_id) if func_code == 1 else self.client.read_discrete_inputs(0, 1, slave=self.unit_id)
                elif func_code in [3, 4]:  # Read holding/input registers
                    response = self.client.read_holding_registers(0, 1, slave=self.unit_id) if func_code == 3 else self.client.read_input_registers(0, 1, slave=self.unit_id)
                else:
                    continue  # Skip write functions for safety
                
                if not response.isError():
                    fingerprint_data['supported_functions'].append(func_code)
                    
            except:
                continue
        
        print(f"  [+] Supported function codes: {fingerprint_data['supported_functions']}")
        return fingerprint_data
    
    def generate_report(self, output_file=None):
        """Generate comprehensive report of findings"""
        report = {
            'target': self.target,
            'port': self.port,
            'unit_id': self.unit_id,
            'scan_timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'flags_found': self.flags_found,
            'sensitive_data': self.sensitive_data,
            'total_flags': len(self.flags_found),
            'total_sensitive': len(self.sensitive_data)
        }
        
        if output_file:
            with open(output_file, 'w') as f:
                json.dump(report, f, indent=2)
            print(f"[+] Report saved to {output_file}")
        
        return report
    
    def print_summary(self):
        """Print summary of scan results"""
        print("\n" + "="*60)
        print("MODBUS REGISTER HUNTER - SCAN SUMMARY")
        print("="*60)
        print(f"Target: {self.target}:{self.port} (Unit ID: {self.unit_id})")
        print(f"Flags Found: {len(self.flags_found)}")
        print(f"Sensitive Data: {len(self.sensitive_data)}")
        
        if self.flags_found:
            print(f"\n[+] FLAGS DISCOVERED:")
            for i, flag in enumerate(self.flags_found, 1):
                print(f"  {i}. {flag['value']} (Address: {flag['start_address']})")
        
        if self.sensitive_data:
            print(f"\n[+] SENSITIVE DATA:")
            for i, data in enumerate(self.sensitive_data[:10], 1):  # Show first 10
                preview = data['value'][:100] + "..." if len(data['value']) > 100 else data['value']
                print(f"  {i}. {preview} (Address: {data['start_address']})")
        
        print("="*60)

def main():
    parser = argparse.ArgumentParser(description='Modbus Register Hunter - Deep register scanning and flag extraction')
    parser.add_argument('--target', '-t', required=True, help='Target IP address')
    parser.add_argument('--port', '-p', type=int, default=502, help='Target port (default: 502)')
    parser.add_argument('--unit-id', '-u', type=int, default=1, help='Modbus unit ID (default: 1)')
    parser.add_argument('--timeout', type=int, default=3, help='Connection timeout (default: 3)')
    parser.add_argument('--start', '-s', type=int, default=0, help='Start register address (default: 0)')
    parser.add_argument('--count', '-c', type=int, default=1000, help='Number of registers to scan (default: 1000)')
    parser.add_argument('--register-type', choices=['holding', 'input', 'coils', 'discrete'], default='holding', help='Register type to scan')
    parser.add_argument('--deep-scan', action='store_true', help='Perform comprehensive scan of all register types')
    parser.add_argument('--fingerprint', action='store_true', help='Fingerprint device capabilities')
    parser.add_argument('--output', '-o', help='Output file for results (JSON format)')
    parser.add_argument('--addresses', nargs='+', type=int, help='Specific register addresses to scan')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    # Create hunter instance
    hunter = ModbusRegisterHunter(args.target, args.port, args.timeout, args.unit_id)
    
    # Connect to device
    if not hunter.connect():
        sys.exit(1)
    
    try:
        # Fingerprint device if requested
        if args.fingerprint:
            hunter.device_fingerprint()
        
        # Perform scanning
        if args.deep_scan:
            print(f"[*] Starting deep scan (up to {args.count * 4} registers)")
            hunter.comprehensive_scan(args.count)
        elif args.addresses:
            print(f"[*] Scanning specific addresses: {args.addresses}")
            hunter.targeted_scan(args.addresses, args.register_type)
        else:
            print(f"[*] Scanning {args.register_type} registers {args.start}-{args.start+args.count-1}")
            hunter.scan_register_range(args.start, args.count, args.register_type)
        
        # Generate and display results
        hunter.print_summary()
        
        if args.output:
            hunter.generate_report(args.output)
        
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
    except Exception as e:
        print(f"[-] Scan error: {e}")
    finally:
        hunter.disconnect()

if __name__ == "__main__":
    main()