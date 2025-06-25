#!/bin/bash

# Kali Linux CTF Setup - System Tools Installation
# Author: CTF Team Setup Automation
# Description: Install system packages and tools for CTF competitions
# Version: 1.0

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_FILE="$SCRIPT_DIR/ctf_setup.log"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
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
    local package="$3"
    local percent=$((current * 100 / total))
    printf "\r${CYAN}[%d/%d]${NC} Installing: %-30s [%d%%]" "$current" "$total" "$package" "$percent"
}

# System packages by priority and category
declare -a CRITICAL_PACKAGES=(
    "nmap"
    "git"
    "curl"
    "wget"
    "build-essential"
    "python3-dev"
    "python3-pip"
    "libssl-dev"
    "libffi-dev"
)

declare -a HIGH_PACKAGES=(
    "gobuster"
    "nikto"
    "dirb"
    "sqlmap"
    "wireshark"
    "tshark"
    "tcpdump"
    "metasploit-framework"
    "exploitdb"
    "masscan"
    "arp-scan"
)

declare -a MEDIUM_PACKAGES=(
    "john"
    "hashcat"
    "hydra"
    "medusa"
    "ettercap-text-only"
    "unicornscan"
    "netcat"
    "socat"
    "proxychains"
    "libmodbus-dev"
    "libs7-dev"
)

declare -a LOW_PACKAGES=(
    "aircrack-ng"
    "reaver"
    "maltego"
    "burpsuite"
    "zaproxy"
    "amass"
    "subfinder"
    "httpx"
    "nuclei"
)

# Network tools
declare -a NETWORK_TOOLS=(
    "nmap"
    "masscan"
    "arp-scan"
    "unicornscan"
    "wireshark"
    "tshark"
    "tcpdump"
    "ettercap-text-only"
    "netcat"
    "socat"
)

# Web application testing tools
declare -a WEB_TOOLS=(
    "gobuster"
    "nikto"
    "dirb"
    "sqlmap"
    "burpsuite"
    "zaproxy"
    "nuclei"
    "httpx"
)

# Password cracking tools
declare -a PASSWORD_TOOLS=(
    "john"
    "hashcat"
    "hydra"
    "medusa"
    "crunch"
    "cewl"
)

# Development tools
declare -a DEV_TOOLS=(
    "git"
    "build-essential"
    "cmake"
    "libmodbus-dev"
    "libs7-dev"
    "libpcap-dev"
    "libssl-dev"
    "libffi-dev"
)

# Check if running with appropriate privileges
check_privileges() {
    if [[ $EUID -ne 0 ]]; then
        log "WARNING" "Not running as root. Some packages may require sudo privileges."
        SUDO_CMD="sudo"
    else
        SUDO_CMD=""
    fi
}

# Update package lists
update_package_lists() {
    log "INFO" "Updating package lists"
    
    if ! $SUDO_CMD apt-get update &>> "$LOG_FILE"; then
        log "ERROR" "Failed to update package lists"
        exit 1
    fi
    
    log "SUCCESS" "Package lists updated"
}

# Install single package with error handling
install_package() {
    local package="$1"
    local retry_count=0
    local max_retries=3
    
    # Check if package is already installed
    if dpkg -l | grep -q "^ii  $package "; then
        return 0  # Already installed
    fi
    
    while [[ $retry_count -lt $max_retries ]]; do
        if $SUDO_CMD apt-get install -y "$package" &>> "$LOG_FILE"; then
            return 0  # Success
        else
            retry_count=$((retry_count + 1))
            log "WARNING" "Failed to install $package (attempt $retry_count/$max_retries)"
            sleep 2
        fi
    done
    
    return 1  # Failed after retries
}

# Install packages from array
install_packages() {
    local -n packages_ref=$1
    local category="$2"
    local total=${#packages_ref[@]}
    local current=0
    local failed_packages=()
    
    log "INFO" "Installing $category packages ($total packages)"
    
    for package in "${packages_ref[@]}"; do
        current=$((current + 1))
        show_progress "$current" "$total" "$package"
        
        if install_package "$package"; then
            echo -e "\n${GREEN}[OK]${NC} $package installed successfully"
        else
            echo -e "\n${RED}[FAIL]${NC} Failed to install $package"
            failed_packages+=("$package")
            log "ERROR" "Failed to install $package"
        fi
    done
    
    echo ""
    
    if [[ ${#failed_packages[@]} -eq 0 ]]; then
        log "SUCCESS" "All $category packages installed successfully"
    else
        log "WARNING" "$category installation completed with ${#failed_packages[@]} failures: ${failed_packages[*]}"
    fi
}

# Install Metasploit Framework
install_metasploit() {
    log "INFO" "Installing Metasploit Framework"
    
    # Metasploit is usually pre-installed on Kali, but let's ensure it's updated
    if command -v msfconsole &> /dev/null; then
        log "INFO" "Metasploit already installed, updating database"
        $SUDO_CMD msfdb init &>> "$LOG_FILE" || true
        log "SUCCESS" "Metasploit database initialized"
    else
        if install_package "metasploit-framework"; then
            $SUDO_CMD msfdb init &>> "$LOG_FILE" || true
            log "SUCCESS" "Metasploit Framework installed and configured"
        else
            log "ERROR" "Failed to install Metasploit Framework"
        fi
    fi
}

# Install custom tools via git
install_git_tools() {
    log "INFO" "Installing additional tools from git repositories"
    
    local tools_dir="$HOME/tools"
    mkdir -p "$tools_dir"
    
    # List of tools to clone
    declare -A GIT_TOOLS=(
        ["SecLists"]="https://github.com/danielmiessler/SecLists.git"
        ["wordlists"]="https://github.com/assetnote/commonspeak2-wordlists.git"
        ["PayloadsAllTheThings"]="https://github.com/swisskyrepo/PayloadsAllTheThings.git"
    )
    
    for tool in "${!GIT_TOOLS[@]}"; do
        local repo_url="${GIT_TOOLS[$tool]}"
        local tool_path="$tools_dir/$tool"
        
        if [[ -d "$tool_path" ]]; then
            log "INFO" "$tool already exists, updating"
            cd "$tool_path" && git pull &>> "$LOG_FILE"
        else
            log "INFO" "Cloning $tool"
            git clone "$repo_url" "$tool_path" &>> "$LOG_FILE"
        fi
    done
    
    log "SUCCESS" "Git tools installation completed"
}

# Configure tools
configure_tools() {
    log "INFO" "Configuring installed tools"
    
    # Create symbolic links for common tools
    local bin_dir="$HOME/.local/bin"
    mkdir -p "$bin_dir"
    
    # Add to PATH if not already there
    if [[ ":$PATH:" != *":$bin_dir:"* ]]; then
        echo 'export PATH="$HOME/.local/bin:$PATH"' >> "$HOME/.bashrc"
        log "INFO" "Added $bin_dir to PATH"
    fi
    
    # Configure wireshark for non-root usage
    if command -v wireshark &> /dev/null; then
        $SUDO_CMD usermod -a -G wireshark "$(whoami)" &>> "$LOG_FILE" || true
        log "INFO" "Added user to wireshark group"
    fi
    
    log "SUCCESS" "Tools configuration completed"
}

# Verify installations
verify_installations() {
    log "INFO" "Verifying system tool installations"
    
    declare -a VERIFY_TOOLS=(
        "nmap" "git" "curl" "wget" "gobuster" "nikto"
        "sqlmap" "wireshark" "tshark" "tcpdump"
    )
    
    local failed_verifications=()
    
    for tool in "${VERIFY_TOOLS[@]}"; do
        if command -v "$tool" &> /dev/null; then
            echo -e "${GREEN}[OK]${NC} $tool is available"
        else
            echo -e "${RED}[FAIL]${NC} $tool is not available"
            failed_verifications+=("$tool")
        fi
    done
    
    if [[ ${#failed_verifications[@]} -eq 0 ]]; then
        log "SUCCESS" "All critical tools verified successfully"
    else
        log "WARNING" "Verification failed for: ${failed_verifications[*]}"
    fi
}

# Cleanup
cleanup() {
    log "INFO" "Cleaning up package cache"
    $SUDO_CMD apt-get autoremove -y &>> "$LOG_FILE"
    $SUDO_CMD apt-get autoclean &>> "$LOG_FILE"
    log "SUCCESS" "Cleanup completed"
}

# Main installation function
main() {
    local mode="${1:-all}"
    
    log "INFO" "Starting system tools installation - Mode: $mode"
    
    # Pre-flight checks
    check_privileges
    update_package_lists
    
    # Install packages based on mode
    case "$mode" in
        "critical"|"--priority=critical")
            install_packages CRITICAL_PACKAGES "Critical"
            ;;
        "high"|"--priority=high")
            install_packages HIGH_PACKAGES "High Priority"
            install_metasploit
            ;;
        "medium"|"--priority=medium")
            install_packages MEDIUM_PACKAGES "Medium Priority"
            ;;
        "low"|"--priority=low")
            install_packages LOW_PACKAGES "Low Priority"
            ;;
        "network"|"--category=network")
            install_packages NETWORK_TOOLS "Network Tools"
            ;;
        "web"|"--category=web")
            install_packages WEB_TOOLS "Web Application Testing"
            ;;
        "password"|"--category=password")
            install_packages PASSWORD_TOOLS "Password Cracking"
            ;;
        "dev"|"--category=dev")
            install_packages DEV_TOOLS "Development Tools"
            ;;
        "all"|"--all")
            install_packages CRITICAL_PACKAGES "Critical"
            install_packages HIGH_PACKAGES "High Priority"
            install_metasploit
            install_packages MEDIUM_PACKAGES "Medium Priority"
            install_packages LOW_PACKAGES "Low Priority"
            install_git_tools
            ;;
    esac
    
    # Configure tools
    configure_tools
    
    # Verify installations
    verify_installations
    
    # Cleanup
    cleanup
    
    log "SUCCESS" "System tools installation completed"
    echo ""
    echo -e "${GREEN}System tools installation completed successfully!${NC}"
    echo -e "${CYAN}Note:${NC} You may need to restart your shell or log out/in for group changes to take effect."
}

# Handle command line arguments
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi