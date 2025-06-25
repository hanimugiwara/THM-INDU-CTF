# Kali Linux Setup Guide for Industrial CTF Competitions

## Table of Contents
1. [Prerequisites and System Requirements](#prerequisites-and-system-requirements)
2. [Installation Priority Overview](#installation-priority-overview)
3. [Critical Priority Installation](#critical-priority-installation)
4. [High Priority Installation](#high-priority-installation)
5. [Medium Priority Installation](#medium-priority-installation)
6. [Low Priority Installation](#low-priority-installation)
7. [Industrial Control Systems Specific Tools](#industrial-control-systems-specific-tools)
8. [Verification Steps](#verification-steps)
9. [Troubleshooting](#troubleshooting)
10. [Post-Installation Configuration](#post-installation-configuration)

---

## Prerequisites and System Requirements

### System Specifications
- **Operating System**: Kali Linux (latest version recommended)
- **Python Version**: 3.8+ (Python 3.9+ recommended)
- **RAM**: Minimum 4GB, 8GB+ recommended
- **Storage**: At least 20GB free space
- **Network**: Internet connection for downloads
- **Privileges**: Root access for packet capture and raw socket operations

### Pre-Installation Checklist
- [ ] Kali Linux fully updated
- [ ] Root access available
- [ ] Internet connectivity verified
- [ ] At least 20GB free disk space

---

## Installation Priority Overview

### Critical Priority
Essential tools needed immediately for basic CTF operations:
- Python 3.8+ environment and virtual environment support
- Core networking tools (nmap, basic network discovery)
- Essential Python packages (requests, urllib3, scapy)
- Git for repository management

### High Priority
Advanced tools for comprehensive penetration testing:
- Web application testing tools
- Network analysis and packet capture
- Metasploit Framework
- Advanced Python libraries for exploitation

### Medium Priority
Specialized tools for industrial systems and password attacks:
- Industrial Control Systems tools
- Password cracking utilities
- Custom security repositories
- Protocol-specific tools

### Low Priority
Optional tools and GUI applications:
- Development environments
- GUI-based tools (if not running headless)
- Additional convenience utilities

---

## Critical Priority Installation

### 1. System Update and Core Dependencies

```bash
# Update system packages
sudo apt update && sudo apt upgrade -y

# Install essential development tools
sudo apt install -y build-essential git curl wget
```

### 2. Python Environment Setup

```bash
# Verify Python version (should be 3.8+)
python3 --version

# Install pip if not present
sudo apt install -y python3-pip python3-venv

# Create dedicated virtual environment for CTF tools
python3 -m venv ~/ctf-env
source ~/ctf-env/bin/activate

# Upgrade pip in virtual environment
pip install --upgrade pip setuptools wheel
```

### 3. Core Python Packages

```bash
# Activate virtual environment
source ~/ctf-env/bin/activate

# Install critical Python packages
pip install requests>=2.25.0
pip install urllib3>=1.26.0
pip install scapy
pip install click
pip install colorama
pip install termcolor
```

**What these do:**
- `requests`: HTTP library for web interactions
- `urllib3`: HTTP client with connection pooling
- `scapy`: Packet manipulation and network discovery
- `click/colorama/termcolor`: CLI tools and colored output

### 4. Essential Network Tools

```bash
# Core network discovery and scanning
sudo apt install -y nmap
sudo apt install -y netcat
sudo apt install -y socat

# Basic network utilities
sudo apt install -y net-tools
sudo apt install -y iproute2
```

**Verification Commands:**
```bash
nmap --version
nc -h
python3 -c "import scapy; print('Scapy installed successfully')"
```

---

## High Priority Installation

### 1. Advanced Python Libraries

```bash
# Activate virtual environment
source ~/ctf-env/bin/activate

# Exploitation and penetration testing
pip install pwntools
pip install paramiko
pip install beautifulsoup4
pip install selenium

# Cryptography libraries
pip install cryptography
pip install pycryptodome

# Network analysis
pip install netaddr
pip install python-nmap
pip install impacket
```

**What these do:**
- `pwntools`: Exploitation framework for CTFs
- `paramiko`: SSH client/server library
- `beautifulsoup4`: HTML/XML parsing
- `selenium`: Web browser automation
- `cryptography/pycryptodome`: Cryptographic operations
- `impacket`: Network protocol implementations

### 2. Web Application Testing Tools

```bash
# Directory and file discovery
sudo apt install -y gobuster
sudo apt install -y dirb
sudo apt install -y nikto

# SQL injection testing
sudo apt install -y sqlmap

# Web proxy tools
sudo apt install -y proxychains
```

**What these do:**
- `gobuster`: Fast directory/file brute-forcer
- `dirb`: Web content scanner
- `nikto`: Web server scanner
- `sqlmap`: Automatic SQL injection tool
- `proxychains`: Proxy chains for anonymous connections

### 3. Network Analysis Tools

```bash
# Packet capture and analysis
sudo apt install -y wireshark
sudo apt install -y tshark
sudo apt install -y tcpdump

# Network scanning
sudo apt install -y masscan
sudo apt install -y arp-scan
sudo apt install -y unicornscan

# Network manipulation
sudo apt install -y ettercap-text-only
```

### 4. Metasploit Framework

```bash
# Install Metasploit (usually pre-installed on Kali)
sudo apt install -y metasploit-framework

# Initialize Metasploit database
sudo msfdb init
```

**Verification:**
```bash
msfconsole -q -x "version; exit"
```

---

## Medium Priority Installation

### 1. Database Connectors

```bash
# Activate virtual environment
source ~/ctf-env/bin/activate

# Database connectivity
pip install pymongo
pip install mysql-connector-python
pip install psycopg2-binary
```

### 2. Password Cracking Tools

```bash
# Hash cracking
sudo apt install -y john
sudo apt install -y hashcat

# Network authentication attacks
sudo apt install -y hydra
sudo apt install -y medusa
```

**What these do:**
- `john`: Password cracker (John the Ripper)
- `hashcat`: Advanced password recovery
- `hydra`: Network logon cracker
- `medusa`: Parallel password cracker

### 3. Additional CLI Frameworks

```bash
# Activate virtual environment
source ~/ctf-env/bin/activate

# Advanced CLI tools
pip install typer
pip install rich
```

### 4. Exploit Database Tools

```bash
# Exploit database
sudo apt install -y exploitdb

# Update exploit database
sudo searchsploit -u
```

---

## Low Priority Installation

### 1. Development Tools

```bash
# Additional development libraries
sudo apt install -y libmodbus-dev
sudo apt install -y libs7-dev

# Version control enhancements
sudo apt install -y git-extras
```

### 2. GUI Tools (if not headless)

```bash
# GUI network analysis (if X11 available)
sudo apt install -y wireshark-qt

# GUI text editors
sudo apt install -y gedit
```

---

## Industrial Control Systems Specific Tools

### 1. Industrial Python Libraries

```bash
# Activate virtual environment
source ~/ctf-env/bin/activate

# Modbus protocol support
pip install "pymodbus>=3.0.0,<4.0.0"

# Additional industrial protocols
pip install python-snap7
pip install python-can
pip install pysnmp
```

**What these do:**
- `pymodbus`: Modbus TCP/RTU client/server library
- `python-snap7`: Siemens S7 protocol support
- `python-can`: Controller Area Network support
- `pysnmp`: SNMP library for network management

### 2. Modbus CLI Tool

```bash
# Install modbus-cli for Modbus TCP interaction
pip install modbus-cli
```

**Test Modbus connectivity:**
```bash
# Example: Scan for Modbus devices (replace with target IP)
# modbus-cli --host 192.168.1.100 --port 502 read-coils 0 10
```

### 3. Specialized ICS Security Tools

```bash
# Create directory for custom tools
mkdir -p ~/ics-tools
cd ~/ics-tools

# Clone plcscan - PLC network scanner
git clone https://github.com/meeas/plcscan.git

# Clone icsmap - ICS discovery tool
git clone https://github.com/dark-lbp/icsmap.git

# Clone Industrial Security Framework (ISF)
git clone https://github.com/dark-lbp/isf.git

# Clone Redpoint - Digital Bond's ICS enumeration tools
git clone https://github.com/digitalbond/Redpoint.git

# Clone Aegis - DNP3 fuzzer
git clone https://github.com/Pigmalion69/aegis.git
```

### 4. Install Custom ICS Tools

```bash
# Install plcscan
cd ~/ics-tools/plcscan
sudo python3 setup.py install

# Make tools executable
chmod +x ~/ics-tools/*/bin/* 2>/dev/null || true

# Add tools to PATH (add to ~/.bashrc for persistence)
export PATH="$PATH:~/ics-tools/plcscan/bin"
export PATH="$PATH:~/ics-tools/icsmap"
export PATH="$PATH:~/ics-tools/isf"
```

**Protocol Port Reference:**
- **Port 502**: Modbus TCP
- **Port 102**: Siemens S7
- **Port 20000**: DNP3
- **Port 44818**: EtherNet/IP
- **Port 47808**: BACnet

---

## Verification Steps

### 1. Python Environment Verification

```bash
# Activate virtual environment
source ~/ctf-env/bin/activate

# Test core packages
python3 -c "
import requests, urllib3, scapy, pwntools
import paramiko, beautifulsoup4
import cryptography, netaddr
import pymodbus
print('All critical Python packages imported successfully!')
"
```

### 2. Network Tools Verification

```bash
# Test network scanning
nmap -sn 127.0.0.1
echo "Nmap test: $?"

# Test packet capture capabilities (requires root)
sudo timeout 2 tcpdump -i lo > /dev/null 2>&1
echo "Packet capture test: $?"

# Test web tools
gobuster --help > /dev/null 2>&1
echo "Gobuster test: $?"
```

### 3. ICS Tools Verification

```bash
# Test Modbus tools
python3 -c "from pymodbus.client.sync import ModbusTcpClient; print('Modbus client available')"

# Test custom tools (if installed)
which plcscan > /dev/null 2>&1 && echo "plcscan available" || echo "plcscan not found"
```

### 4. Complete System Check

```bash
# Create verification script
cat << 'EOF' > ~/ctf_verify.py
#!/usr/bin/env python3
import sys
import subprocess
import importlib

def check_package(package):
    try:
        importlib.import_module(package)
        return True
    except ImportError:
        return False

def check_command(command):
    try:
        subprocess.run([command, '--help'], capture_output=True, check=True)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False

# Python packages to check
packages = [
    'requests', 'urllib3', 'scapy', 'pwntools', 'paramiko',
    'cryptography', 'netaddr', 'pymodbus', 'click', 'colorama'
]

# System commands to check
commands = [
    'nmap', 'gobuster', 'sqlmap', 'hydra', 'john',
    'wireshark', 'metasploit', 'tcpdump'
]

print("=== CTF Environment Verification ===")
print("\nPython Packages:")
for pkg in packages:
    status = "✓" if check_package(pkg) else "✗"
    print(f"  {status} {pkg}")

print("\nSystem Commands:")
for cmd in commands:
    status = "✓" if check_command(cmd) else "✗"
    print(f"  {status} {cmd}")

print("\n=== Verification Complete ===")
EOF

# Run verification
python3 ~/ctf_verify.py
```

---

## Troubleshooting

### Common Issues and Solutions

#### 1. Python Package Installation Failures

**Issue**: `pip install` fails with permission errors
```bash
# Solution: Ensure virtual environment is active
source ~/ctf-env/bin/activate
# Verify you're in virtual environment
which python3
```

**Issue**: Package version conflicts
```bash
# Solution: Use specific versions
pip install "pymodbus>=3.0.0,<4.0.0"
# Or upgrade existing packages
pip install --upgrade package_name
```

#### 2. Network Tool Permission Issues

**Issue**: `tcpdump` or `wireshark` permission denied
```bash
# Solution: Add user to wireshark group
sudo usermod -a -G wireshark $USER
# Logout and login again, or use newgrp
newgrp wireshark
```

#### 3. Metasploit Database Issues

**Issue**: Metasploit database connection fails
```bash
# Solution: Reinitialize database
sudo msfdb delete
sudo msfdb init
sudo msfdb start
```

#### 4. ICS Tools Installation Problems

**Issue**: Custom tools not found in PATH
```bash
# Solution: Add to shell profile
echo 'export PATH="$PATH:~/ics-tools/plcscan/bin"' >> ~/.bashrc
source ~/.bashrc
```

#### 5. Memory Issues During Large Scans

**Issue**: System runs out of memory during scans
```bash
# Solution: Limit concurrent connections
nmap -T2 --max-parallelism 10 target_range
masscan --rate 1000 target_range
```

---

## Post-Installation Configuration

### 1. Environment Persistence

Add to `~/.bashrc` for automatic virtual environment activation:
```bash
# CTF Environment Auto-activation
echo 'alias ctf-env="source ~/ctf-env/bin/activate"' >> ~/.bashrc
echo 'alias ctf-start="source ~/ctf-env/bin/activate && cd ~/ctf-workspace"' >> ~/.bashrc
```

### 2. Create CTF Workspace

```bash
# Create organized workspace
mkdir -p ~/ctf-workspace/{recon,exploits,tools,reports}
cd ~/ctf-workspace

# Create quick reference
cat << 'EOF' > ~/ctf-workspace/quick_ref.md
# CTF Quick Reference

## Network Discovery
- nmap -sn <network>          # Ping sweep
- nmap -sV -sC <target>       # Version and script scan
- masscan -p1-65535 <target> # Fast port scan

## Web Testing
- gobuster dir -u <url> -w <wordlist>
- nikto -h <target>
- sqlmap -u <url> --batch

## Modbus Testing
- python3 -c "from pymodbus.client.sync import ModbusTcpClient; client = ModbusTcpClient('<target>')"
- modbus-cli --host <target> --port 502 read-coils 0 10

## Password Attacks
- hydra -l admin -P passwords.txt <target> http-get-form
- john --wordlist=<wordlist> <hashfile>
EOF
```

### 3. Network Interface Configuration

```bash
# Create script for monitor mode setup (for wireless testing)
cat << 'EOF' > ~/ctf-workspace/setup_monitor.sh
#!/bin/bash
# Setup wireless interface for monitor mode
INTERFACE=${1:-wlan0}
sudo ip link set $INTERFACE down
sudo iw dev $INTERFACE set type monitor
sudo ip link set $INTERFACE up
echo "Monitor mode enabled on $INTERFACE"
EOF

chmod +x ~/ctf-workspace/setup_monitor.sh
```

---

## Summary

This setup guide covers **60+ tools and packages** organized by priority:

### Package Summary
- **Python Packages**: 20+ packages including pymodbus, pwntools, scapy, impacket
- **System Tools**: 25+ APT packages including nmap, metasploit, wireshark, hydra
- **Custom ICS Tools**: 5 specialized repositories for industrial system testing
- **Database Support**: MySQL, PostgreSQL, MongoDB connectors
- **Protocol Support**: Modbus (502), S7 (102), DNP3 (20000), EtherNet/IP (44818), BACnet (47808)

### Key Features
- ✅ Priority-based installation (Critical → Low)
- ✅ Virtual environment isolation
- ✅ Comprehensive verification steps
- ✅ Industrial Control Systems focus
- ✅ Troubleshooting guide
- ✅ Post-installation workspace setup

The environment is now ready for industrial CTF competitions with full support for network penetration testing, web application security, and specialized industrial control systems assessment.