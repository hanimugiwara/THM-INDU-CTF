# Python Arsenal for Industrial Operations

**Authored by: Hex**
**Version: 2.0 - Complete Automation Toolkit**
**Classification:** Operational Use Only
**Last Updated:** [TIMESTAMP]

---

## Executive Overview

Python is our primary weapon for custom protocol manipulation, automation, and rapid exploitation development. This directory contains a comprehensive collection of production-ready Python scripts specifically designed for industrial control system penetration testing and CTF operations.

**Mission Critical**: These scripts are battle-tested and optimized for speed, stealth, and effectiveness in industrial environments. Each script can be executed standalone or integrated into larger attack frameworks.

---

## Table of Contents

1. [Environment Setup & Dependencies](#environment-setup--dependencies)
2. [Script Categories & Usage](#script-categories--usage)
3. [Quick Reference Guide](#quick-reference-guide)
4. [Industrial Protocol Scripts](#industrial-protocol-scripts)
5. [Web Application Scripts](#web-application-scripts)
6. [Network Automation Scripts](#network-automation-scripts)
7. [Exploitation Frameworks](#exploitation-frameworks)
8. [Utility & Helper Scripts](#utility--helper-scripts)
9. [Execution Guidelines](#execution-guidelines)
10. [Troubleshooting & Debugging](#troubleshooting--debugging)

---

## Environment Setup & Dependencies

### Python Environment Requirements

**Recommended Python Version:** 3.8+ (3.9+ preferred for async features)

### Essential Libraries Installation

```bash
# Core penetration testing libraries
pip install requests urllib3 pwntools scapy

# Industrial protocol libraries
pip install pymodbus pysnmp snap7 python-can

# Web application testing
pip install selenium beautifulsoup4 paramiko

# Cryptography and encoding
pip install cryptography pycryptodome base58

# Network and protocol analysis
pip install netaddr python-nmap impacket

# Database interaction
pip install pymongo mysql-connector-python psycopg2-binary

# Additional utilities
pip install colorama termcolor rich click typer

# Complete installation command
pip install -r requirements.txt
```

### Quick Environment Setup Script

```bash
#!/bin/bash
# Run this script to set up the complete Python environment
echo "[+] Setting up Python environment for industrial operations..."

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install all required packages
pip install --upgrade pip
pip install -r requirements.txt

# Verify critical imports
python3 -c "import pymodbus, requests, scapy, pwntools; print('[+] All critical libraries installed successfully')"

echo "[+] Environment setup complete. Activate with: source venv/bin/activate"
```

---

## Script Categories & Usage

### Industrial Control Systems (ICS) Scripts

| Script | Purpose | Target Protocols | Difficulty |
|:---|:---|:---|:---|
| [`modbus_network_scanner.py`](modbus_network_scanner.py) | Network-wide Modbus device discovery | Modbus TCP | Easy |
| [`modbus_register_hunter.py`](modbus_register_hunter.py) | Deep register scanning & flag extraction | Modbus TCP | Medium |
| [`s7_communication_tool.py`](s7_communication_tool.py) | Siemens S7 PLC interaction | S7 Protocol | Advanced |
| [`dnp3_analyzer.py`](dnp3_analyzer.py) | DNP3 protocol analysis | DNP3 | Advanced |
| [`bacnet_discovery.py`](bacnet_discovery.py) | BACnet device enumeration | BACnet/IP | Medium |
| [`ics_protocol_fuzzer.py`](ics_protocol_fuzzer.py) | Multi-protocol fuzzing framework | Multiple ICS | Expert |

### Web Application Exploitation Scripts

| Script | Purpose | Target Technology | Difficulty |
|:---|:---|:---|:---|
| [`web_login_bruteforcer.py`](web_login_bruteforcer.py) | Intelligent login brute forcing | HTTP/HTTPS | Easy |
| [`sql_injection_tester.py`](sql_injection_tester.py) | Automated SQL injection testing | Web Applications | Medium |
| [`directory_traversal_scanner.py`](directory_traversal_scanner.py) | Path traversal vulnerability scanner | File Systems | Medium |
| [`file_upload_bypass.py`](file_upload_bypass.py) | File upload restriction bypass | Web Forms | Medium |
| [`web_shell_generator.py`](web_shell_generator.py) | Custom web shell generation | Multiple Languages | Advanced |
| [`api_security_scanner.py`](api_security_scanner.py) | REST API vulnerability assessment | APIs | Advanced |

### Network Automation Scripts

| Script | Purpose | Target Systems | Difficulty |
|:---|:---|:---|:---|
| [`network_discovery.py`](network_discovery.py) | Comprehensive network mapping | TCP/UDP Services | Easy |
| [`service_enumerator.py`](service_enumerator.py) | Deep service fingerprinting | Multiple Protocols | Medium |
| [`credential_harvester.py`](credential_harvester.py) | Multi-protocol credential extraction | Various Services | Advanced |
| [`network_pivot_setup.py`](network_pivot_setup.py) | Automated pivot establishment | SSH/SOCKS | Advanced |
| [`traffic_interceptor.py`](traffic_interceptor.py) | Network traffic interception | Ethernet/WiFi | Expert |

### Exploitation Frameworks

| Script | Purpose | Capabilities | Difficulty |
|:---|:---|:---|:---|
| [`rapid_exploit_framework.py`](rapid_exploit_framework.py) | All-in-one exploitation platform | Multi-vector attacks | Expert |
| [`persistence_manager.py`](persistence_manager.py) | Cross-platform persistence | Linux/Windows | Advanced |
| [`lateral_movement_toolkit.py`](lateral_movement_toolkit.py) | Automated lateral movement | Network Propagation | Expert |
| [`evidence_collector.py`](evidence_collector.py) | Digital forensics automation | File/Memory Analysis | Advanced |

---

## Quick Reference Guide

### Common Execution Patterns

```bash
# Network scanning and discovery
python3 modbus_network_scanner.py 192.168.1.0/24
python3 network_discovery.py --target 10.10.0.0/16 --threads 50

# Web application testing
python3 web_login_bruteforcer.py --url http://target.com/login --wordlist /usr/share/wordlists/rockyou.txt
python3 sql_injection_tester.py --url http://target.com/search --parameter q

# Industrial protocol interaction
python3 modbus_register_hunter.py --target 192.168.1.100 --unit-id 1 --registers 0-1000
python3 s7_communication_tool.py --target 192.168.1.101 --read-memory

# Automation and frameworks
python3 rapid_exploit_framework.py --config operations.json --target-list targets.txt
```

### Essential Command-Line Arguments

Most scripts support these common arguments:
- `--target` / `-t`: Target IP address or hostname
- `--port` / `-p`: Target port (protocol-specific defaults)
- `--timeout`: Connection timeout in seconds
- `--threads`: Number of concurrent threads
- `--output` / `-o`: Output file for results
- `--verbose` / `-v`: Verbose logging
- `--stealth`: Stealth mode with timing delays
- `--config`: Configuration file path

### Environment Variables

```bash
# Set default target for quick testing
export DEFAULT_TARGET="192.168.1.100"

# Default wordlist locations
export WORDLIST_DIR="/usr/share/wordlists"

# Output directory for results
export RESULTS_DIR="./results"

# Stealth mode timing
export STEALTH_DELAY="0.5"
```

---

## Industrial Protocol Scripts

### Modbus TCP Scripts

**Primary Scripts:**
- **`modbus_network_scanner.py`**: Fast network-wide discovery of Modbus devices
- **`modbus_register_hunter.py`**: Deep scanning for flags and sensitive data
- **`modbus_write_tool.py`**: Controlled register/coil manipulation
- **`modbus_function_fuzzer.py`**: Function code and register fuzzing

**Usage Examples:**
```bash
# Quick network scan
python3 modbus_network_scanner.py 192.168.1.0/24

# Deep register hunting on specific device
python3 modbus_register_hunter.py --target 192.168.1.100 --unit-id 1 --start 0 --count 10000

# Write to specific registers (use with caution!)
python3 modbus_write_tool.py --target 192.168.1.100 --register 40001 --value 1234

# Fuzz device responses
python3 modbus_function_fuzzer.py --target 192.168.1.100 --functions 1,2,3,4,5,6
```

### Siemens S7 Scripts

**Primary Scripts:**
- **`s7_communication_tool.py`**: Comprehensive S7 PLC interaction
- **`s7_memory_reader.py`**: Memory dump and analysis
- **`s7_ladder_logic_extractor.py`**: Program logic extraction

### DNP3 & Other Protocols

**Primary Scripts:**
- **`dnp3_analyzer.py`**: DNP3 protocol analysis and manipulation
- **`bacnet_discovery.py`**: BACnet device discovery and enumeration
- **`ethernet_ip_scanner.py`**: EtherNet/IP (Allen-Bradley) communication

---

## Web Application Scripts

### Authentication Testing

**`web_login_bruteforcer.py`** - Advanced login brute forcing with:
- Smart rate limiting and anti-detection
- Multiple authentication methods (Form, Basic, JWT)
- Session handling and CSRF token extraction
- Success/failure detection using multiple methods

**`multi_factor_bypass.py`** - MFA bypass techniques:
- Session fixation attacks
- OTP prediction and timing attacks
- Backup code enumeration

### Injection Testing

**`sql_injection_tester.py`** - Comprehensive SQLi testing:
- Error-based, blind, and time-based detection
- Database fingerprinting
- Automated data extraction
- WAF evasion techniques

**`command_injection_scanner.py`** - OS command injection:
- Multiple payload vectors
- Output-based and blind detection
- Shell establishment automation

### File Upload Exploitation

**`file_upload_bypass.py`** - Upload restriction bypass:
- Extension and MIME type manipulation
- Magic byte insertion
- Polyglot file generation
- Web shell deployment automation

---

## Network Automation Scripts

### Discovery and Enumeration

**`network_discovery.py`** - Intelligent network mapping:
- Multi-threaded port scanning
- Service fingerprinting
- OS detection
- Network topology mapping

**`service_enumerator.py`** - Deep service analysis:
- Banner grabbing and version detection
- Vulnerability correlation
- Configuration extraction
- Credential hunting

### Credential Operations

**`credential_harvester.py`** - Multi-vector credential extraction:
- Network protocol authentication testing
- Memory dump analysis
- Configuration file parsing
- Hash extraction and cracking coordination

---

## Exploitation Frameworks

### Rapid Exploit Framework

**`rapid_exploit_framework.py`** - Complete attack automation:
- Target discovery and enumeration
- Vulnerability assessment
- Exploitation and post-exploitation
- Reporting and evidence collection

**Configuration Example:**
```json
{
    "targets": ["192.168.1.0/24"],
    "protocols": ["modbus", "http", "ssh", "snmp"],
    "exploits": ["web_sqli", "modbus_register_read", "ssh_bruteforce"],
    "post_exploitation": ["credential_dump", "network_pivot"],
    "stealth_mode": true,
    "reporting": {
        "format": "json",
        "output": "results.json"
    }
}
```

### Persistence and Lateral Movement

**`persistence_manager.py`** - Cross-platform persistence:
- Service installation and registry modification
- Scheduled task creation
- File system hiding techniques
- Network callback establishment

**`lateral_movement_toolkit.py`** - Automated propagation:
- Credential reuse testing
- SMB and SSH lateral movement
- Domain enumeration and exploitation
- Kerberoasting and ticket manipulation

---

## Utility & Helper Scripts

### Data Processing

**`data_analyzer.py`** - Intelligence analysis:
- Log file parsing and correlation
- Network traffic analysis
- Password pattern identification
- Flag extraction and validation

### Communication and Reporting

**`report_generator.py`** - Professional reporting:
- Multiple output formats (HTML, PDF, JSON)
- Screenshot integration
- Timeline generation
- Executive summary creation

**`team_communicator.py`** - Team coordination:
- Slack/Discord integration
- Real-time status updates
- Alert notifications
- Progress tracking

---

## Execution Guidelines

### Pre-Execution Checklist

1. **Environment Verification**
   ```bash
   # Check Python version
   python3 --version
   
   # Verify required libraries
   python3 -c "import pymodbus, requests, scapy; print('OK')"
   
   # Check network connectivity
   ping -c 1 [TARGET_IP]
   ```

2. **Target Validation**
   ```bash
   # Confirm target IP range
   nmap -sn [TARGET_RANGE]
   
   # Verify permissions and scope
   echo "Authorized target: [TARGET]" >> operation_log.txt
   ```

3. **Tool Configuration**
   ```bash
   # Set environment variables
   export DEFAULT_TARGET="192.168.1.100"
   export STEALTH_MODE="true"
   
   # Create output directory
   mkdir -p results/$(date +%Y%m%d_%H%M%S)
   ```

### Execution Best Practices

1. **Start with Passive Reconnaissance**
   ```bash
   python3 network_discovery.py --passive --target [RANGE]
   ```

2. **Proceed with Active Scanning**
   ```bash
   python3 modbus_network_scanner.py [RANGE] --stealth
   ```

3. **Target Specific Systems**
   ```bash
   python3 modbus_register_hunter.py --target [IP] --deep-scan
   ```

4. **Document Everything**
   ```bash
   python3 report_generator.py --input results/ --output operation_report.html
   ```

### Error Handling and Recovery

Most scripts include comprehensive error handling:
- **Connection timeouts**: Automatic retry with exponential backoff
- **Protocol errors**: Graceful degradation and alternative methods
- **Rate limiting**: Adaptive timing and stealth mode activation
- **System errors**: Detailed logging and recovery suggestions

### Logging and Output

All scripts support multiple logging levels:
- **DEBUG**: Detailed protocol interaction
- **INFO**: General operation progress
- **WARNING**: Potential issues or anomalies
- **ERROR**: Critical failures requiring attention
- **CRITICAL**: System-level failures

---

## Troubleshooting & Debugging

### Common Issues and Solutions

**1. Connection Timeouts**
```bash
# Increase timeout values
python3 script.py --timeout 10

# Use stealth mode for sensitive targets
python3 script.py --stealth --delay 2
```

**2. Protocol Errors**
```bash
# Enable debug logging
python3 script.py --verbose --debug

# Try alternative protocol versions
python3 modbus_scanner.py --protocol-version 2
```

**3. Permission Denied**
```bash
# Run with elevated privileges if needed
sudo python3 script.py

# Check firewall rules
sudo iptables -L
```

**4. Library Import Errors**
```bash
# Reinstall requirements
pip install --force-reinstall -r requirements.txt

# Check virtual environment
which python3
```

### Debug Mode Activation

```bash
# Enable comprehensive debugging
export PYTHON_DEBUG=1
export MODBUS_DEBUG=1

# Run script with maximum verbosity
python3 script.py --debug --verbose --trace
```

### Performance Optimization

```bash
# Adjust thread count for performance
python3 script.py --threads 100

# Use memory-efficient mode for large scans
python3 script.py --memory-efficient

# Enable result caching
python3 script.py --cache-results
```

---

## Security Considerations

### Operational Security

1. **Network Footprint**: All scripts support stealth modes with randomized timing
2. **Log Cleaning**: Built-in log sanitization and cleanup routines
3. **Encryption**: Sensitive data is encrypted during transmission and storage
4. **Authentication**: Support for various authentication methods and bypass techniques

### Legal and Ethical Usage

⚠️ **CRITICAL REMINDER**: These tools are designed for authorized penetration testing and CTF competitions only. Ensure proper authorization before use.

### Safety Mechanisms

- **Dry-run modes**: Test operations without making changes
- **Backup creation**: Automatic backup of critical configurations
- **Rollback capabilities**: Ability to reverse changes when possible
- **Emergency stop**: Immediate termination of all operations

---

**🎯 OPERATIONAL EXCELLENCE REMINDER 🎯**

These Python scripts represent the cutting edge of industrial penetration testing automation. Use them wisely, test thoroughly, and maintain operational security at all times.

**Speed. Precision. Success.**

---
*End of Python Arsenal Documentation v2.0*

