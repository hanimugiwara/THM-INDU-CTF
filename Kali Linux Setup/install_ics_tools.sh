#!/bin/bash

# Kali Linux CTF Setup - Industrial Control Systems Tools Installation
# Author: CTF Team Setup Automation
# Description: Install specialized ICS/SCADA tools for industrial CTF competitions
# Version: 1.0

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_FILE="$SCRIPT_DIR/ctf_setup.log"
TOOLS_DIR="$HOME/ics_tools"
VENV_NAME="${VENV_NAME:-ctf_env}"
VENV_PATH="$HOME/$VENV_NAME"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
PURPLE='\033[0;35m'
NC='\033[0m'

# Logging function
log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] [$level] $message" >> "$LOG_FILE"
    
    case "$level" in
        "ERROR")   echo -e "${RED}[ERROR]${NC} $message" ;;
        "SUCCESS") echo -e "${GREEN}[SUCCESS]${NC} $message" ;;
        "WARNING") echo -e "${YELLOW}[WARNING]${NC} $message" ;;
        "INFO")    echo -e "${BLUE}[INFO]${NC} $message" ;;
    esac
}

# Progress indicator
show_progress() {
    local current=$1
    local total=$2
    local tool="$3"
    local percent=$((current * 100 / total))
    printf "\r${CYAN}[%d/%d]${NC} Installing: %-30s [%d%%]" "$current" "$total" "$tool" "$percent"
}

# ICS Tools from GitHub repositories
declare -A ICS_GIT_TOOLS=(
    ["plcscan"]="https://github.com/meeas/plcscan.git"
    ["icsmap"]="https://github.com/dark-lbp/icsmap.git"
    ["isf"]="https://github.com/dark-lbp/isf.git"
    ["redpoint"]="https://github.com/digitalbond/Redpoint.git"
    ["aegis"]="https://github.com/CyberSecLabs/aegis.git"
    ["modbus-cli"]="https://github.com/tallakt/modbus-cli.git"
    ["s7-client"]="https://github.com/plcpeople/nodeS7.git"
    ["conpot"]="https://github.com/mushorg/conpot.git"
)

# Industrial Protocol analyzers
declare -A PROTOCOL_TOOLS=(
    ["modbus-tcp"]="https://github.com/digitalbond/Redpoint.git"
    ["dnp3-tools"]="https://github.com/automatak/dnp3.git"
    ["bacnet-tools"]="https://github.com/JoelBender/bacpypes.git"
    ["ethernet-ip"]="https://github.com/EIPStackGroup/EIPStackGroup.git"
)

# Custom ICS Python packages
declare -a ICS_PYTHON_PACKAGES=(
    "pymodbus>=3.0.0"
    "python-snap7"
    "python-can"
    "pysnmp"
    "pyasn1"
    "construct"
    "scapy"
    "crcmod"
)

# Create tools directory
setup_directories() {
    log "INFO" "Setting up ICS tools directories"
    
    mkdir -p "$TOOLS_DIR"
    mkdir -p "$TOOLS_DIR/bin"
    mkdir -p "$TOOLS_DIR/scripts"
    mkdir -p "$TOOLS_DIR/configs"
    
    log "SUCCESS" "Directories created: $TOOLS_DIR"
}

# Install system dependencies
install_dependencies() {
    log "INFO" "Installing ICS tool dependencies"
    
    local dependencies=(
        "libmodbus-dev"
        "libs7-dev" 
        "libpcap-dev"
        "build-essential"
        "cmake"
        "autotools-dev"
        "autoconf"
        "pkg-config"
    )
    
    if [[ $EUID -ne 0 ]]; then
        SUDO_CMD="sudo"
    else
        SUDO_CMD=""
    fi
    
    for dep in "${dependencies[@]}"; do
        if ! dpkg -l | grep -q "^ii  $dep "; then
            log "INFO" "Installing $dep"
            $SUDO_CMD apt-get install -y "$dep" &>> "$LOG_FILE"
        fi
    done
    
    log "SUCCESS" "System dependencies installed"
}

# Install ICS Python packages
install_ics_python_packages() {
    log "INFO" "Installing ICS Python packages"
    
    if [[ ! -d "$VENV_PATH" ]]; then
        log "WARNING" "Virtual environment not found at $VENV_PATH"
        log "INFO" "Creating virtual environment for ICS tools"
        python3 -m venv "$VENV_PATH"
    fi
    
    source "$VENV_PATH/bin/activate"
    
    local total=${#ICS_PYTHON_PACKAGES[@]}
    local current=0
    
    for package in "${ICS_PYTHON_PACKAGES[@]}"; do
        current=$((current + 1))
        local package_name=$(echo "$package" | cut -d'>' -f1 | cut -d'=' -f1)
        
        show_progress "$current" "$total" "$package_name"
        
        if pip show "$package_name" &> /dev/null; then
            echo -e "\n${YELLOW}[SKIP]${NC} $package_name (already installed)"
        else
            if pip install "$package" &>> "$LOG_FILE"; then
                echo -e "\n${GREEN}[OK]${NC} $package_name installed"
            else
                echo -e "\n${RED}[FAIL]${NC} Failed to install $package_name"
                log "ERROR" "Failed to install $package_name"
            fi
        fi
    done
    
    deactivate
    echo ""
    log "SUCCESS" "ICS Python packages installation completed"
}

# Clone and install ICS tools
install_git_tools() {
    log "INFO" "Installing ICS tools from GitHub repositories"
    
    local total=${#ICS_GIT_TOOLS[@]}
    local current=0
    
    cd "$TOOLS_DIR"
    
    for tool in "${!ICS_GIT_TOOLS[@]}"; do
        current=$((current + 1))
        local repo_url="${ICS_GIT_TOOLS[$tool]}"
        local tool_path="$TOOLS_DIR/$tool"
        
        show_progress "$current" "$total" "$tool"
        
        if [[ -d "$tool_path" ]]; then
            echo -e "\n${YELLOW}[UPDATE]${NC} $tool already exists, updating..."
            cd "$tool_path" && git pull &>> "$LOG_FILE"
        else
            echo -e "\n${CYAN}[CLONE]${NC} Cloning $tool..."
            if git clone "$repo_url" "$tool_path" &>> "$LOG_FILE"; then
                echo -e "${GREEN}[OK]${NC} $tool cloned successfully"
            else
                echo -e "${RED}[FAIL]${NC} Failed to clone $tool"
                log "ERROR" "Failed to clone $tool from $repo_url"
                continue
            fi
        fi
        
        # Install tool if it has setup requirements
        cd "$tool_path"
        
        # Check for different installation methods
        if [[ -f "setup.py" ]]; then
            source "$VENV_PATH/bin/activate"
            pip install -e . &>> "$LOG_FILE" || log "WARNING" "Failed to install $tool with pip"
            deactivate
        elif [[ -f "requirements.txt" ]]; then
            source "$VENV_PATH/bin/activate"
            pip install -r requirements.txt &>> "$LOG_FILE" || log "WARNING" "Failed to install $tool requirements"
            deactivate
        elif [[ -f "Makefile" ]]; then
            make &>> "$LOG_FILE" || log "WARNING" "Failed to build $tool with make"
        fi
        
        # Make scripts executable
        find "$tool_path" -name "*.py" -exec chmod +x {} \; 2>/dev/null || true
        find "$tool_path" -name "*.sh" -exec chmod +x {} \; 2>/dev/null || true
    done
    
    echo ""
    log "SUCCESS" "ICS tools installation completed"
}

# Install modbus-cli specifically
install_modbus_cli() {
    log "INFO" "Installing modbus-cli tool"
    
    # Check if Ruby is installed (modbus-cli is a Ruby gem)
    if ! command -v ruby &> /dev/null; then
        log "INFO" "Installing Ruby for modbus-cli"
        if [[ $EUID -ne 0 ]]; then
            sudo apt-get install -y ruby ruby-dev &>> "$LOG_FILE"
        else
            apt-get install -y ruby ruby-dev &>> "$LOG_FILE"
        fi
    fi
    
    # Install modbus-cli gem
    if ! gem list modbus-cli | grep -q modbus-cli; then
        if [[ $EUID -ne 0 ]]; then
            sudo gem install modbus-cli &>> "$LOG_FILE"
        else
            gem install modbus-cli &>> "$LOG_FILE"
        fi
        log "SUCCESS" "modbus-cli installed via gem"
    else
        log "INFO" "modbus-cli already installed"
    fi
}

# Create custom ICS scripts
create_custom_scripts() {
    log "INFO" "Creating custom ICS utility scripts"
    
    # Create Modbus scanner script
    cat > "$TOOLS_DIR/scripts/modbus_scanner.py" << 'EOF'
#!/usr/bin/env python3
"""
Modbus TCP Scanner
Scans for Modbus TCP services and attempts to read device information
"""

import socket
import struct
import sys
from pymodbus.client.sync import ModbusTcpClient
import argparse

def scan_modbus_port(host, port=502, timeout=3):
    """Scan for Modbus TCP service on given host:port"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except:
        return False

def read_modbus_info(host, port=502):
    """Attempt to read device information via Modbus"""
    try:
        client = ModbusTcpClient(host, port=port)
        if client.connect():
            # Try to read holding registers
            result = client.read_holding_registers(0, 10, unit=1)
            if not result.isError():
                print(f"[+] {host}:{port} - Modbus TCP service detected")
                print(f"    Registers 0-9: {result.registers}")
            client.close()
            return True
    except Exception as e:
        pass
    return False

def main():
    parser = argparse.ArgumentParser(description='Modbus TCP Scanner')
    parser.add_argument('hosts', nargs='+', help='Host(s) to scan')
    parser.add_argument('-p', '--port', type=int, default=502, help='Port to scan (default: 502)')
    
    args = parser.parse_args()
    
    for host in args.hosts:
        if scan_modbus_port(host, args.port):
            read_modbus_info(host, args.port)
        else:
            print(f"[-] {host}:{args.port} - No Modbus service detected")

if __name__ == "__main__":
    main()
EOF

    # Create S7 scanner script
    cat > "$TOOLS_DIR/scripts/s7_scanner.py" << 'EOF'
#!/usr/bin/env python3
"""
Siemens S7 Protocol Scanner
Scans for S7 protocol services (port 102)
"""

import socket
import sys
import argparse

def scan_s7_port(host, port=102, timeout=3):
    """Scan for S7 service on given host:port"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        if result == 0:
            print(f"[+] {host}:{port} - S7 service detected")
            return True
    except:
        pass
    print(f"[-] {host}:{port} - No S7 service detected")
    return False

def main():
    parser = argparse.ArgumentParser(description='S7 Protocol Scanner')
    parser.add_argument('hosts', nargs='+', help='Host(s) to scan')
    parser.add_argument('-p', '--port', type=int, default=102, help='Port to scan (default: 102)')
    
    args = parser.parse_args()
    
    for host in args.hosts:
        scan_s7_port(host, args.port)

if __name__ == "__main__":
    main()
EOF

    # Create DNP3 scanner script
    cat > "$TOOLS_DIR/scripts/dnp3_scanner.py" << 'EOF'
#!/usr/bin/env python3
"""
DNP3 Protocol Scanner
Scans for DNP3 protocol services (port 20000)
"""

import socket
import sys
import argparse

def scan_dnp3_port(host, port=20000, timeout=3):
    """Scan for DNP3 service on given host:port"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        if result == 0:
            print(f"[+] {host}:{port} - DNP3 service detected")
            return True
    except:
        pass
    print(f"[-] {host}:{port} - No DNP3 service detected")
    return False

def main():
    parser = argparse.ArgumentParser(description='DNP3 Protocol Scanner')
    parser.add_argument('hosts', nargs='+', help='Host(s) to scan')
    parser.add_argument('-p', '--port', type=int, default=20000, help='Port to scan (default: 20000)')
    
    args = parser.parse_args()
    
    for host in args.hosts:
        scan_dnp3_port(host, args.port)

if __name__ == "__main__":
    main()
EOF

    # Make scripts executable
    chmod +x "$TOOLS_DIR/scripts/"*.py
    
    log "SUCCESS" "Custom ICS scripts created"
}

# Create configuration files
create_configs() {
    log "INFO" "Creating ICS tool configuration files"
    
    # Create nmap script for ICS scanning
    cat > "$TOOLS_DIR/configs/ics_scan.nse" << 'EOF'
-- ICS Protocol Detection Nmap Script
-- Detects common industrial protocols

local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Detects industrial control system protocols including:
- Modbus TCP (502)
- S7 Communication (102)
- DNP3 (20000)
- EtherNet/IP (44818)
- BACnet (47808)
]]

author = "CTF Team"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "intrusive"}

portrule = function(host, port)
  return port.number == 502 or port.number == 102 or 
         port.number == 20000 or port.number == 44818 or 
         port.number == 47808
end

action = function(host, port)
  local protocol = ""
  
  if port.number == 502 then
    protocol = "Modbus TCP"
  elseif port.number == 102 then
    protocol = "Siemens S7"
  elseif port.number == 20000 then
    protocol = "DNP3"
  elseif port.number == 44818 then
    protocol = "EtherNet/IP"
  elseif port.number == 47808 then
    protocol = "BACnet"
  end
  
  return "ICS Protocol detected: " .. protocol
end
EOF

    # Create common ICS ports list
    cat > "$TOOLS_DIR/configs/ics_ports.txt" << 'EOF'
# Common Industrial Control System Ports
# Modbus TCP
502

# Siemens S7
102

# DNP3
20000

# EtherNet/IP
44818

# BACnet
47808

# IEC 61850 MMS
102

# Crimson v3.0
789

# Red Lion Controls
789

# ProConOS
20547

# PC Worx
1962

# Modbus RTU over TCP
502

# CoDeSys
1200
2455
8080

# Schneider Electric
502
102

# Rockwell/Allen-Bradley
44818
2222

# GE SRTP
18245
18246

# Omron FINS
9600

# Mitsubishi MELSEC
5006
5007

# Yokogawa
10001
10002
EOF

    log "SUCCESS" "Configuration files created"
}

# Create wrapper scripts
create_wrappers() {
    log "INFO" "Creating ICS tool wrapper scripts"
    
    # Create master ICS scanner
    cat > "$TOOLS_DIR/bin/ics_scan" << EOF
#!/bin/bash
# ICS Network Scanner Wrapper
# Combines multiple ICS scanning tools

TOOLS_DIR="$TOOLS_DIR"
VENV_PATH="$VENV_PATH"

if [[ \$# -eq 0 ]]; then
    echo "Usage: \$0 <target> [options]"
    echo "Examples:"
    echo "  \$0 192.168.1.0/24        # Scan network range"
    echo "  \$0 192.168.1.10          # Scan single host"
    echo "  \$0 targets.txt           # Scan from file"
    exit 1
fi

TARGET="\$1"

echo "Starting ICS scan of \$TARGET"
echo "=========================="

# Activate virtual environment
source "\$VENV_PATH/bin/activate"

# Port scan for common ICS ports
echo "[*] Scanning for common ICS ports..."
nmap -sT -p 102,502,20000,44818,47808 "\$TARGET"

# Modbus scan
echo "[*] Scanning for Modbus devices..."
python3 "\$TOOLS_DIR/scripts/modbus_scanner.py" "\$TARGET" || true

# S7 scan
echo "[*] Scanning for S7 devices..."
python3 "\$TOOLS_DIR/scripts/s7_scanner.py" "\$TARGET" || true

# DNP3 scan
echo "[*] Scanning for DNP3 devices..."
python3 "\$TOOLS_DIR/scripts/dnp3_scanner.py" "\$TARGET" || true

deactivate
echo "ICS scan completed."
EOF

    chmod +x "$TOOLS_DIR/bin/ics_scan"
    
    # Add to PATH
    if [[ ":$PATH:" != *":$TOOLS_DIR/bin:"* ]]; then
        echo "export PATH=\"$TOOLS_DIR/bin:\$PATH\"" >> "$HOME/.bashrc"
        log "INFO" "Added $TOOLS_DIR/bin to PATH"
    fi
    
    log "SUCCESS" "Wrapper scripts created"
}

# Verify ICS tools installation
verify_installation() {
    log "INFO" "Verifying ICS tools installation"
    
    # Check Python packages
    source "$VENV_PATH/bin/activate"
    
    local python_tools=("pymodbus" "snap7" "scapy")
    local failed_tools=()
    
    for tool in "${python_tools[@]}"; do
        if python3 -c "import $tool" &>/dev/null; then
            echo -e "${GREEN}[OK]${NC} Python package: $tool"
        else
            echo -e "${RED}[FAIL]${NC} Python package: $tool"
            failed_tools+=("$tool")
        fi
    done
    
    deactivate
    
    # Check installed tools
    local git_tools=("plcscan" "isf" "modbus-cli")
    
    for tool in "${git_tools[@]}"; do
        if [[ -d "$TOOLS_DIR/$tool" ]]; then
            echo -e "${GREEN}[OK]${NC} ICS tool: $tool"
        else
            echo -e "${YELLOW}[WARN]${NC} ICS tool: $tool (not found)"
        fi
    done
    
    # Check custom scripts
    if [[ -x "$TOOLS_DIR/scripts/modbus_scanner.py" ]]; then
        echo -e "${GREEN}[OK]${NC} Custom script: modbus_scanner.py"
    else
        echo -e "${RED}[FAIL]${NC} Custom script: modbus_scanner.py"
    fi
    
    if [[ ${#failed_tools[@]} -eq 0 ]]; then
        log "SUCCESS" "ICS tools verification completed successfully"
    else
        log "WARNING" "Some ICS tools failed verification: ${failed_tools[*]}"
    fi
}

# Main installation function
main() {
    log "INFO" "Starting Industrial Control Systems tools installation"
    
    echo -e "${PURPLE}╔════════════════════════════════════════════════╗${NC}"
    echo -e "${PURPLE}║        Industrial Control Systems Setup        ║${NC}"
    echo -e "${PURPLE}║             CTF Tools Installation             ║${NC}"
    echo -e "${PURPLE}╚════════════════════════════════════════════════╝${NC}"
    echo ""
    
    # Setup
    setup_directories
    install_dependencies
    
    # Install ICS tools
    install_ics_python_packages
    install_git_tools
    install_modbus_cli
    
    # Create custom resources
    create_custom_scripts
    create_configs
    create_wrappers
    
    # Verify installation
    verify_installation
    
    log "SUCCESS" "ICS tools installation completed"
    
    echo ""
    echo -e "${GREEN}ICS tools installation completed successfully!${NC}"
    echo -e "${CYAN}Tools installed in:${NC} $TOOLS_DIR"
    echo -e "${CYAN}Available commands:${NC}"
    echo "  ics_scan <target>           # Comprehensive ICS scan"
    echo "  modbus_scanner.py <host>    # Modbus TCP scanner"
    echo "  s7_scanner.py <host>        # Siemens S7 scanner"
    echo "  dnp3_scanner.py <host>      # DNP3 scanner"
    echo ""
    echo -e "${YELLOW}Note:${NC} Restart your shell or run 'source ~/.bashrc' to use new commands"
}

# Handle command line arguments
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi