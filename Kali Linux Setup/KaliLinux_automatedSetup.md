# Kali Linux CTF Setup - Automated Installation Guide

## Table of Contents
1. [Overview](#overview)
2. [Prerequisites](#prerequisites)
3. [Quick Start](#quick-start)
4. [Script Details](#script-details)
5. [Installation Workflows](#installation-workflows)
6. [Execution Order](#execution-order)
7. [Arguments and Options](#arguments-and-options)
8. [Expected Results](#expected-results)
9. [Verification](#verification)
10. [Troubleshooting](#troubleshooting)
11. [Post-Installation](#post-installation)

---

## Overview

This automated setup system provides a comprehensive, menu-driven installation framework for setting up Kali Linux environments specifically tailored for CTF competitions with a focus on Industrial Control Systems (ICS) security. The automation scripts replace the manual installation process detailed in the [`kalilinux_setup.md`](kalilinux_setup.md) guide, providing consistent, reliable, and faster deployment.

### What Gets Automated
The automation system covers **all 60+ tools and packages** from the manual guide:
- ✅ **Python Environment**: Virtual environment setup with 20+ specialized packages
- ✅ **System Tools**: 25+ APT packages including penetration testing tools
- ✅ **ICS Tools**: 8+ specialized industrial control systems tools
- ✅ **Database Support**: MySQL, PostgreSQL, MongoDB connectors
- ✅ **Protocol Support**: Modbus, S7, DNP3, EtherNet/IP, BACnet
- ✅ **Custom Scripts**: Automated ICS scanners and utilities
- ✅ **Verification**: Complete installation validation

### Key Benefits
- **Priority-based Installation**: Install only what you need, when you need it
- **Error Handling**: Automatic retry logic and comprehensive logging
- **Progress Tracking**: Real-time installation progress with colored output
- **Rollback Support**: System backup and restoration capabilities
- **Verification**: Built-in testing to ensure everything works correctly

---

## Prerequisites

### System Requirements
- **Operating System**: Kali Linux (latest version recommended)
- **Python Version**: 3.8+ (automatically verified)
- **RAM**: Minimum 4GB, 8GB+ recommended for ICS tools
- **Storage**: At least 5GB free space (automatically checked)
- **Network**: Internet connection (automatically tested)
- **Privileges**: Root access for system package installation

### Pre-Installation Checklist
The automation scripts will verify these automatically:
- [ ] Internet connectivity available
- [ ] Sufficient disk space (minimum 5GB)
- [ ] Kali Linux environment detected
- [ ] Python 3.8+ installed
- [ ] User has sudo privileges

---

## Quick Start

### Option 1: Complete Automated Installation
For immediate setup of all components:

```bash
# Navigate to the setup directory
cd "Kali Linux Setup"

# Run complete installation (recommended for first-time setup)
./install_kali_ctf.sh --complete

# Verify installation
./verify_installation.sh
```

### Option 2: Interactive Menu
For guided installation with options:

```bash
# Navigate to the setup directory
cd "Kali Linux Setup"

# Launch interactive menu
./install_kali_ctf.sh

# Follow the menu prompts to select components
```

### Option 3: Priority-Based Installation
For step-by-step installation based on priority:

```bash
# Install only critical components first
./install_kali_ctf.sh --critical

# Verify critical installation
./verify_installation.sh --quick

# Add high priority tools when ready
# (Launch menu again and select option 3)
```

---

## Script Details

### 1. [`install_kali_ctf.sh`](install_kali_ctf.sh) - Main Installation Script

**Purpose**: Menu-driven master script that orchestrates all installations

**Key Features**:
- Interactive menu with 14 installation options
- Command-line arguments for automation
- Pre-flight checks (internet, disk space, OS verification)
- Progress tracking with colored output
- Comprehensive logging to `ctf_setup.log`
- Error handling with automatic retries
- System backup functionality

**Arguments**:
```bash
./install_kali_ctf.sh [option]

# Command-line options:
--complete, -c    # Install all components
--critical        # Install critical components only  
--verify, -v      # Run verification only
--help, -h        # Show help information
```

### 2. [`install_python_deps.sh`](install_python_deps.sh) - Python Dependencies

**Purpose**: Installs Python packages and sets up virtual environments

**Key Features**:
- Creates isolated virtual environment (`~/ctf_env`)
- Priority-based package installation (Critical → High → Medium → Low → ICS)
- Automatic pip upgrades and dependency resolution
- Retry logic for failed installations
- Version verification and import testing
- Generates activation script for easy environment setup

**Package Categories**:
- **Critical**: requests, urllib3, scapy, pwntools, paramiko, click, colorama (7 packages)
- **High**: beautifulsoup4, selenium, cryptography, netaddr, impacket, rich (10 packages)
- **Medium**: pymodbus, pymongo, mysql-connector-python, psycopg2-binary (7 packages)
- **Low**: pandas, numpy, matplotlib, jupyter, notebook, ipython (6 packages)
- **ICS**: pymodbus, python-snap7, python-can, pysnmp, construct (6 packages)

**Arguments**:
```bash
./install_python_deps.sh [priority]

# Priority options:
--priority=critical   # Install critical packages only
--priority=high      # Install high priority packages
--priority=medium    # Install medium priority packages  
--priority=low       # Install low priority packages
--all               # Install all packages
ics                 # Install ICS-specific packages only
```

### 3. [`install_system_tools.sh`](install_system_tools.sh) - System Tools Installation

**Purpose**: Installs APT packages and system-level security tools

**Key Features**:
- Priority and category-based installation
- Automatic package list updates
- Error handling with retry logic for failed packages
- Post-installation configuration (wireshark groups, PATH setup)
- Git repository cloning for additional tools
- Tool verification and availability checking

**Tool Categories**:
- **Critical**: nmap, git, curl, wget, build-essential, python3-dev (9 packages)
- **High**: gobuster, nikto, sqlmap, wireshark, metasploit-framework, masscan (11 packages)
- **Medium**: john, hashcat, hydra, ettercap, unicornscan, libmodbus-dev (11 packages)
- **Low**: aircrack-ng, maltego, burpsuite, zaproxy, amass, nuclei (9 packages)

**Arguments**:
```bash
./install_system_tools.sh [mode]

# Priority modes:
--priority=critical  # Essential tools only
--priority=high     # Web and network tools
--priority=medium   # Password and ICS tools  
--priority=low      # Additional utilities

# Category modes:
--category=network  # Network analysis tools only
--category=web      # Web application testing only
--category=password # Password cracking tools only
--category=dev      # Development tools only
--all              # Install all tools
```

### 4. [`install_ics_tools.sh`](install_ics_tools.sh) - Industrial Control Systems Tools

**Purpose**: Specialized installation for ICS/SCADA security tools

**Key Features**:
- Creates dedicated ICS tools directory (`~/ics_tools`)
- Installs ICS-specific Python packages
- Clones and configures specialized ICS repositories
- Creates custom scanning scripts (Modbus, S7, DNP3)
- Installs modbus-cli gem for Ruby-based tools
- Generates comprehensive ICS scanning wrapper (`ics_scan`)
- Creates protocol-specific configuration files

**ICS Tools Installed**:
- **plcscan**: PLC network scanner
- **icsmap**: ICS discovery and enumeration
- **isf**: Industrial Security Framework
- **redpoint**: Digital Bond's ICS tools
- **aegis**: DNP3 fuzzer
- **modbus-cli**: Ruby-based Modbus client
- **conpot**: ICS honeypot system

**Custom Scripts Created**:
- `modbus_scanner.py`: Modbus TCP device scanner
- `s7_scanner.py`: Siemens S7 protocol scanner  
- `dnp3_scanner.py`: DNP3 protocol scanner
- `ics_scan`: Master ICS scanning wrapper

**Protocol Support**:
- **Port 502**: Modbus TCP
- **Port 102**: Siemens S7
- **Port 20000**: DNP3
- **Port 44818**: EtherNet/IP
- **Port 47808**: BACnet

### 5. [`verify_installation.sh`](verify_installation.sh) - Installation Verification

**Purpose**: Comprehensive validation of all installed components

**Key Features**:
- Multi-category verification (System, Python, Tools, ICS, Network)
- Pass/Fail/Warning status reporting with colored output
- Detailed test summaries with percentage completion
- Logging of all verification results
- Quick test mode for essential components only
- Component-specific verification modes

**Verification Categories**:
- **System**: OS detection, Python version, Git availability
- **Virtual Environment**: Environment creation and activation
- **Python Packages**: Import testing for all installed packages
- **System Tools**: Command availability and version checking
- **Metasploit**: Framework and database verification
- **ICS Tools**: Custom tools and script verification
- **Network**: Internet connectivity and DNS resolution
- **Security**: User groups and permissions

**Arguments**:
```bash
./verify_installation.sh [mode]

# Verification modes:
full      # Complete verification (default)
quick     # Essential components only
python    # Python environment only
system    # System tools only
ics       # ICS tools only
network   # Network connectivity only
help      # Show usage information
```

---

## Installation Workflows

### Workflow 1: Complete Installation (Recommended)

**Use Case**: First-time setup, production environment

```bash
# Step 1: Run complete installation
./install_kali_ctf.sh --complete

# Step 2: Verify everything works
./verify_installation.sh

# Step 3: Activate CTF environment
source activate_ctf_env.sh
```

**Time Required**: 20-45 minutes depending on internet speed
**Components Installed**: All 60+ tools and packages

### Workflow 2: Priority-Based Installation

**Use Case**: Limited time, incremental setup

```bash
# Step 1: Install critical tools (5-10 minutes)
./install_kali_ctf.sh --critical
./verify_installation.sh --quick

# Step 2: Add high priority tools when needed (10-15 minutes)
./install_kali_ctf.sh
# Select option 3 (High Priority)

# Step 3: Add specialized tools as required
./install_kali_ctf.sh
# Select option 8 (ICS Tools)
```

### Workflow 3: Component-Specific Installation

**Use Case**: Targeted tool installation, specific needs

```bash
# Python environment only
./install_kali_ctf.sh
# Select option 6 (Python Dependencies Only)

# Web testing tools only  
./install_kali_ctf.sh
# Select option 9 (Web Application Testing Tools)

# ICS tools only
./install_kali_ctf.sh
# Select option 8 (Industrial Control Systems Tools)
```

### Workflow 4: Automated CI/CD Installation

**Use Case**: Automated deployment, container builds

```bash
# Silent installation with logging
./install_kali_ctf.sh --complete 2>&1 | tee install.log

# Verify and exit with status code
./verify_installation.sh && echo "Success" || echo "Failed"
```

---

## Execution Order

### Recommended Script Execution Sequence

1. **Pre-flight Checks** (Automatic)
   - Internet connectivity test
   - Disk space verification
   - OS and Python version checks

2. **System Package Updates** (Automatic)
   - `apt update && apt upgrade`
   - Essential development tools

3. **Python Environment Setup**
   - Virtual environment creation
   - Pip upgrades and essential tools
   - Package installation by priority

4. **System Tools Installation**
   - APT package installation
   - Tool configuration and setup
   - Git repository cloning

5. **ICS Tools Installation** (Optional)
   - Specialized ICS tool setup
   - Custom script generation
   - Protocol configuration

6. **Verification and Testing**
   - Component functionality testing
   - Installation validation
   - Error reporting

### Dependencies Between Scripts

```
install_kali_ctf.sh (Master)
├── install_python_deps.sh
│   ├── Requires: Python 3.8+, pip
│   └── Creates: ~/ctf_env virtual environment
├── install_system_tools.sh  
│   ├── Requires: apt, sudo privileges
│   └── Creates: System tools, repositories
└── install_ics_tools.sh
    ├── Requires: Virtual environment from python deps
    ├── Requires: System dependencies from system tools
    └── Creates: ~/ics_tools directory, custom scripts
```

---

## Arguments and Options

### Main Script Arguments

**[`install_kali_ctf.sh`](install_kali_ctf.sh)**:
```bash
# Automated execution
--complete, -c     # Complete installation (all components)
--critical         # Critical components only
--verify, -v       # Run verification only  
--help, -h         # Show help and usage

# Interactive menu options (1-14):
1   # Complete Installation (All Components)
2   # Critical Priority Only (Essential tools)
3   # High Priority (Critical + Web/Network tools)  
4   # Medium Priority (High + Password/ICS tools)
5   # Low Priority (All remaining tools)
6   # Python Dependencies Only
7   # System Tools Only
8   # Industrial Control Systems Tools
9   # Web Application Testing Tools
10  # Network Analysis Tools
11  # Verify Installation
12  # View Installation Log
13  # Create System Backup
14  # Configuration Settings
0   # Exit
```

### Component Script Arguments

**[`install_python_deps.sh`](install_python_deps.sh)**:
```bash
--priority=critical   # requests, scapy, pwntools (7 packages)
--priority=high      # beautifulsoup4, selenium, crypto (10 packages)
--priority=medium    # database connectors (7 packages)
--priority=low       # data science tools (6 packages)  
--all               # All Python packages (30+ total)
ics                 # ICS-specific packages only (6 packages)
```

**[`install_system_tools.sh`](install_system_tools.sh)**:
```bash
# Priority-based installation
--priority=critical  # nmap, git, curl, build tools (9 packages)
--priority=high     # gobuster, nikto, wireshark, metasploit (11 packages)
--priority=medium   # john, hashcat, hydra, ettercap (11 packages)
--priority=low      # aircrack-ng, burpsuite, zaproxy (9 packages)

# Category-based installation  
--category=network  # Network analysis tools only
--category=web      # Web testing tools only
--category=password # Password cracking tools only
--category=dev      # Development libraries only
--all              # All system tools (40+ packages)
```

**[`verify_installation.sh`](verify_installation.sh)**:
```bash
full      # Complete verification (default) - all categories
quick     # Essential tests only - critical components
python    # Python environment verification only
system    # System tools verification only
ics       # ICS tools verification only  
network   # Network connectivity tests only
help      # Usage information and examples
```

### Configuration Options

The scripts support configuration through `ctf_config.conf`:

```bash
# Example configuration file
INSTALL_TIMEOUT=300        # Installation timeout in seconds
PROXY_URL=                 # HTTP proxy URL (optional)
VENV_NAME=ctf_env         # Virtual environment name
```

**Configure via menu**:
```bash
./install_kali_ctf.sh
# Select option 14 (Configuration Settings)
```

---

## Expected Results

### After Critical Priority Installation

**Time**: ~5-10 minutes  
**Components Installed**:
- ✅ Python 3.8+ virtual environment at `~/ctf_env`
- ✅ Essential Python packages (7): requests, scapy, pwntools, paramiko
- ✅ Core system tools (9): nmap, git, curl, wget, build-essential
- ✅ Basic networking utilities: netcat, socat

**Verification Results**:
```
=== CTF Setup Verification ===
✓ Operating System: Kali Linux detected
✓ Python Version: 3.9.2 (>= 3.8.0)  
✓ Virtual Environment: Found at /home/user/ctf_env
✓ Python Package: requests (2.28.1)
✓ Python Package: scapy (2.4.5)
✓ System Tool: nmap (7.93)
✓ Internet Connectivity: Available
```

### After High Priority Installation

**Additional Time**: ~10-15 minutes  
**Additional Components**:
- ✅ Web testing tools: gobuster, nikto, dirb, sqlmap
- ✅ Network analysis: wireshark, tshark, tcpdump, masscan
- ✅ Metasploit Framework with initialized database
- ✅ Advanced Python libraries: beautifulsoup4, selenium, cryptography
- ✅ Git repositories: SecLists, PayloadsAllTheThings

**Ready For**: Web application testing, network reconnaissance, basic exploitation

### After Medium Priority Installation

**Additional Time**: ~5-10 minutes  
**Additional Components**:
- ✅ Password cracking: john, hashcat, hydra, medusa
- ✅ Database connectors: pymongo, mysql-connector, psycopg2
- ✅ Network manipulation: ettercap, unicornscan, proxychains
- ✅ Development libraries: libmodbus-dev, libs7-dev

**Ready For**: Password attacks, database exploitation, industrial protocols

### After Complete Installation

**Total Time**: ~20-45 minutes  
**All Components Installed**:
- ✅ **60+ tools and packages** from all categories
- ✅ **Python Environment**: 30+ packages in isolated virtual environment
- ✅ **System Tools**: 40+ APT packages and utilities
- ✅ **ICS Tools**: 8+ specialized industrial security tools
- ✅ **Custom Scripts**: Modbus, S7, and DNP3 scanners
- ✅ **Git Repositories**: Security wordlists and payloads
- ✅ **Protocol Support**: All major industrial protocols

**Directory Structure Created**:
```
~/ctf_env/                    # Python virtual environment
~/ics_tools/                  # ICS-specific tools
├── bin/ics_scan             # Master ICS scanner
├── scripts/                 # Custom scanning scripts
│   ├── modbus_scanner.py   
│   ├── s7_scanner.py
│   └── dnp3_scanner.py
├── configs/                # Protocol configurations
├── plcscan/                # PLC network scanner
├── icsmap/                 # ICS discovery tool
├── isf/                    # Industrial Security Framework
└── redpoint/               # Digital Bond tools

~/tools/                     # Additional security tools
├── SecLists/               # Security wordlists
├── wordlists/              # Common wordlists  
└── PayloadsAllTheThings/   # Exploitation payloads
```

---

## Verification

### Comprehensive Verification Process

The [`verify_installation.sh`](verify_installation.sh) script provides thorough testing:

```bash
# Run complete verification
./verify_installation.sh

# Expected output format:
╔════════════════════════════════════════════════╗
║              CTF Setup Verification            ║
║           Industrial Security Edition          ║
╚════════════════════════════════════════════════╝

=== System Verification ===
✓ Operating System: Kali Linux detected
✓ Python Version: 3.9.2 (>= 3.8.0)
✓ Pip Version: 22.0.4
✓ Git Version: 2.37.2

=== Virtual Environment Verification ===
✓ Virtual Environment: Found at /home/user/ctf_env
✓ Virtual Environment Activation: Success (Python 3.9.2)

=== Python Packages Verification ===
�� Python Package: requests (2.28.1)
✓ Python Package: scapy (2.4.5)
✓ Python Package: pwntools (4.8.0)
✓ ICS Package: pymodbus (3.1.1)

=== Verification Summary ===
Total Tests: 45
Passed: 43 (95%)
Failed: 0
Warnings: 2

✓ CTF environment verification completed successfully!
Your system is ready for CTF competitions.
```

### Quick Verification Commands

**Test Python Environment**:
```bash
# Activate environment and test core packages
source ~/ctf_env/bin/activate
python3 -c "
import requests, scapy, pwntools, pymodbus
print('✓ All critical packages working')
"
```

**Test System Tools**:
```bash
# Test core tools
nmap --version && echo "✓ Nmap working"
gobuster --help >/dev/null && echo "✓ Gobuster working"  
msfconsole -q -x "version; exit" && echo "✓ Metasploit working"
```

**Test ICS Tools**:
```bash
# Test custom ICS scripts
python3 ~/ics_tools/scripts/modbus_scanner.py --help
ics_scan --help
```

### Verification Status Codes

**Exit Codes**:
- `0`: All tests passed successfully
- `1`: Critical failures detected (missing essential components)
- `2`: Warnings present (non-critical issues)

**Test Results**:
- **[PASS]**: Component working correctly
- **[FAIL]**: Component missing or broken  
- **[WARN]**: Component available but may need configuration

---

## Troubleshooting

### Common Issues and Solutions

#### 1. Internet Connectivity Issues

**Problem**: Installation fails with network errors
```bash
# Error: No internet connection detected
# Error: Failed to update package lists
```

**Solutions**:
```bash
# Check connectivity
ping -c 3 google.com

# Check DNS resolution  
nslookup google.com

# Configure proxy if needed
./install_kali_ctf.sh
# Select option 14 (Configuration Settings)
# Select option 2 (Configure proxy settings)
```

#### 2. Virtual Environment Creation Failures

**Problem**: Python virtual environment creation fails
```bash
# Error: Virtual environment creation failed
# Error: Permission denied creating directory
```

**Solutions**:
```bash
# Check Python version
python3 --version  # Should be 3.8+

# Install venv module if missing
sudo apt install python3-venv

# Check disk space
df -h ~  # Should have >1GB available

# Manual environment creation
python3 -m venv ~/ctf_env
source ~/ctf_env/bin/activate
```

#### 3. Package Installation Failures

**Problem**: Python packages fail to install
```bash
# Error: Failed to install pymodbus after 3 attempts
# Error: Building wheel for package failed
```

**Solutions**:
```bash
# Install development headers
sudo apt install python3-dev libssl-dev libffi-dev

# Upgrade pip and setuptools
source ~/ctf_env/bin/activate
pip install --upgrade pip setuptools wheel

# Install packages individually
pip install --no-cache-dir pymodbus

# Check for version conflicts
pip list --outdated
```

#### 4. System Package Installation Issues

**Problem**: APT package installation fails
```bash
# Error: Unable to locate package
# Error: Package has unmet dependencies
```

**Solutions**:
```bash
# Update package lists
sudo apt update

# Fix broken dependencies
sudo apt --fix-broken install

# Check Kali repositories
cat /etc/apt/sources.list
# Should contain: deb http://http.kali.org/kali kali-rolling main

# Force package refresh
sudo apt update --fix-missing
```

#### 5. Metasploit Database Issues

**Problem**: Metasploit database initialization fails
```bash
# Error: Database connection failed
# Error: PostgreSQL service not running
```

**Solutions**:
```bash
# Start PostgreSQL service
sudo systemctl start postgresql

# Reinitialize Metasploit database
sudo msfdb delete
sudo msfdb init
sudo msfdb start

# Verify database connection
msfconsole -q -x "db_status; exit"
```

#### 6. ICS Tools Installation Problems

**Problem**: ICS tools fail to clone or install
```bash
# Error: Failed to clone repository
# Error: modbus-cli gem installation failed
```

**Solutions**:
```bash
# Check git configuration
git config --global user.name "Your Name"
git config --global user.email "your.email@example.com"

# Install Ruby development headers for gems
sudo apt install ruby-dev

# Manual ICS tools installation
mkdir -p ~/ics_tools
cd ~/ics_tools
git clone https://github.com/meeas/plcscan.git

# Install modbus-cli manually
sudo gem install modbus-cli
```

#### 7. Permission and Group Issues

**Problem**: Tools require special permissions
```bash
# Error: You don't have permission to capture on interface
# Error: Access denied to raw sockets
```

**Solutions**:
```bash
# Add user to necessary groups
sudo usermod -a -G wireshark $USER
sudo usermod -a -G netdev $USER

# Apply group changes (logout/login or use newgrp)
newgrp wireshark

# Configure wireshark for non-root capture
sudo dpkg-reconfigure wireshark-common
# Select "Yes" when prompted

# Verify group membership
groups $USER
```

#### 8. Memory and Performance Issues

**Problem**: System becomes slow during installation
```bash
# Error: System appears to hang during large installations
# Warning: High memory usage detected
```

**Solutions**:
```bash
# Monitor system resources
htop
# or
top

# Limit concurrent operations
# Edit scripts to reduce parallelism

# Close unnecessary applications
# Increase swap space if needed
sudo fallocate -l 2G /swapfile
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile
```

### Log Analysis

**Check Installation Logs**:
```bash
# View complete log
less "Kali Linux Setup/ctf_setup.log"

# Check for errors
grep "ERROR" "Kali Linux Setup/ctf_setup.log"

# Check warnings
grep "WARNING" "Kali Linux Setup/ctf_setup.log"

# Monitor installation in real-time
tail -f "Kali Linux Setup/ctf_setup.log"
```

### Recovery Procedures

**Restore from Backup**:
```bash
# If system backup was created (option 13)
./install_kali_ctf.sh
# Select option 13 (Create System Backup)

# Package lists backed up to:
# - backups/package_list.txt
# - backups/python_packages.txt

# Restore packages
sudo dpkg --set-selections < backups/package_list.txt
sudo apt-get dselect-upgrade
```

**Clean Installation**:
```bash
# Remove virtual environment
rm -rf ~/ctf_env

# Remove ICS tools
rm -rf ~/ics_tools

# Clean package cache
sudo apt autoremove
sudo apt autoclean

# Start fresh installation
./install_kali_ctf.sh --complete
```

---

## Post-Installation

### Environment Activation

**Automatic Activation Script**:
```bash
# Use generated activation script
source activate_ctf_env.sh

# Output:
# ✓ CTF Virtual Environment Activated
# Virtual Environment: /home/user/ctf_env
# Python Version: Python 3.9.2
# Pip Version: pip 22.0.4 from /home/user/ctf_env/lib/python3.9/site-packages/pip (python 3.9)
# 
# To deactivate, run: deactivate
```

**Manual Activation**:
```bash
# Activate virtual environment
source ~/ctf_env/bin/activate

# Verify activation
which python3
# Should show: /home/user/ctf_env/bin/python3
```

### Workspace Setup

**Create CTF Workspace**:
```bash
# Create organized directory structure
mkdir -p ~/ctf-workspace/{recon,exploits,tools,reports,targets}
cd ~/ctf-workspace

# Create quick reference
cat > quick_ref.md << 'EOF'
# CTF Quick Reference

## Network Discovery
nmap -sn 192.168.1.0/24              # Network discovery
nmap -sV -sC -O target              # Service and OS detection
masscan -p1-65535 target --rate=1000 # Fast port scan

## Web Application Testing  
gobuster dir -u http://target -w /usr/share/wordlists/dirb/common.txt
nikto -h http://target
sqlmap -u "http://target/page.php?id=1" --batch

## Industrial Control Systems
ics_scan 192.168.1.0/24             # Comprehensive ICS scan
python3 ~/ics_tools/scripts/modbus_scanner.py 192.168.1.100
python3 ~/ics_tools/scripts/s7_scanner.py 192.168.1.100

## Password Attacks
hydra -l admin -P passwords.txt target ssh
john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt
hashcat -m 1000 -a 0 hashes.txt wordlist.txt

## Packet Analysis
wireshark &                          # GUI packet analyzer
tshark -i eth0 -f "port 502"        # Modbus traffic capture
tcpdump -i eth0 -w capture.pcap     # Packet capture to file
EOF
```

### PATH Configuration

**Add Tools to PATH**:
```bash
# Add to ~/.bashrc for permanent access
echo 'export PATH="$PATH:~/ics_tools/bin"' >> ~/.bashrc
echo 'export PATH="$PATH:~/ctf_env/bin"' >> ~/.bashrc

# Create aliases for common operations
cat >> ~/.bashrc << 'EOF'
# CTF Environment Aliases
alias ctf-activate='source ~/ctf_env/bin/activate'
alias ctf-workspace='cd ~/ctf-workspace && source ~/ctf_env/bin/activate'
alias ics-tools='cd ~/ics_tools && source ~/ctf_env/bin/activate'
alias ctf-verify='cd "Kali Linux Setup" && ./verify_installation.sh'
EOF

# Apply changes
source ~/.bashrc
```

### Tool Configuration

**Configure Wireshark for Non-Root Capture**:
```bash
# Reconfigure wireshark (if not done automatically)
sudo dpkg-reconfigure wireshark-common
# Select "Yes" to allow non-superusers to capture packets

# Add user to wireshark group (if not done automatically)
sudo usermod -a -G wireshark $USER

# Apply group changes
newgrp wireshark
```

**Configure Metasploit Workspace**:
```bash
# Start msfconsole and create workspace
msfconsole -q
msf6 > workspace -a ctf_workspace
msf6 > workspace ctf_workspace
msf6 > exit
```

### Testing Your Setup

**Quick Functionality Test**:
```bash
# Test network tools
nmap -sn 127.0.0.1

# Test web tools  
echo "Testing gobuster..."
gobuster --help >/dev/null && echo "✓ Gobuster working"

# Test Python environment
source ~/ctf_env/bin/activate
python3 -c "
import requests, scapy, pwntools, pymodbus
print('✓ Python environment working')
"

# Test ICS tools
ics_scan --help >/dev/null && echo "✓ ICS tools working"
```

**Competition Readiness Checklist**:
- [ ] All verification tests pass (`./verify_installation.sh`)
- [ ] Virtual environment activates correctly
- [ ] Network scanning tools functional (nmap, masscan)
- [ ] Web testing tools available (gobuster, sqlmap, nikto)
- [ ] ICS tools operational (ics_scan, modbus_scanner.py)
- [ ] Metasploit database initialized
- [ ] Packet capture working (wireshark, tcpdump)
- [ ] Password cracking tools ready (john, hashcat, hydra)
- [ ] Workspace directory created and organized

### Maintenance and Updates

**Regular Maintenance**:
```bash
# Update system packages
sudo apt update && sudo apt upgrade -y

# Update Python packages in virtual environment
source ~/ctf_env/bin/activate
pip list --outdated
pip install --upgrade package_name

# Update git repositories
cd ~/ics_tools
for dir in */; do
    if [ -d "$dir/.git" ]; then
        echo "Updating $dir"
        cd "$dir" && git pull && cd ..
    fi
done

# Update exploit database
sudo searchsploit -u

# Re-verify installation after updates
./verify_installation.sh
```

**Before Competitions**:
```bash
# Run complete verification
./verify_installation.sh

# Test critical tools
ctf-verify  # (alias created above)

# Backup current state
./install_kali_ctf.sh
# Select option 13 (Create System Backup)

# Update wordlists and payloads
cd ~/tools/SecLists && git pull
cd ~/tools/PayloadsAllTheThings && git pull
```

---

## Summary

This automated setup system provides a complete, reliable, and efficient way to deploy Kali Linux environments for CTF competitions with specialized support for Industrial Control Systems security. The automation replaces manual processes with:

### Key Achievements
- ✅ **Complete Automation**: All 60+ tools from manual guide automated
- ✅ **Priority-Based Deployment**: Install only what you need, when you need it
- ✅ **Error Resilience**: Automatic retry logic and comprehensive error handling
- ✅ **Verification Suite**: Built-in testing ensures everything works correctly
- ✅ **Industrial Focus**: Specialized ICS/SCADA tools and protocols
- ✅ **Professional Logging**: Complete audit trail of all operations

### Installation Options
1. **Complete** (20-45 min): Everything installed, production ready
2. **Priority-Based** (5-30 min): Incremental installation by importance
3. **Component-Specific** (5-15 min): Targeted installation for specific needs
4. **Interactive Menu**: Guided installation with real-time choices

### Tools and Packages Included
- **Python Environment**: 30+ packages in isolated virtual environment
- **System Tools**: 40+ APT packages for penetration testing
- **ICS Tools**: 8+ specialized industrial security tools
- **Custom Scripts**: Modbus, S7, DNP3 scanners and utilities
- **Protocol Support**: All major industrial protocols (502, 102, 20000, 44818, 47808)

### Ready for Competition
After running the automation, your system will be fully configured for:
- Network reconnaissance and scanning
- Web application security testing  
- Industrial Control Systems assessment
- Password cracking and credential attacks
- Packet capture and network analysis
- Exploitation and post-exploitation activities

The environment is now ready for industrial CTF competitions with complete verification that all components are working correctly.