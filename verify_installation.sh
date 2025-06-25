#!/bin/bash

# Kali Linux CTF Setup - Installation Verification
# Author: CTF Team Setup Automation
# Description: Verify all CTF tools and dependencies are properly installed
# Version: 1.0

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_FILE="$SCRIPT_DIR/ctf_setup.log"
VENV_NAME="${VENV_NAME:-ctf_env}"
VENV_PATH="$HOME/$VENV_NAME"
TOOLS_DIR="$HOME/ics_tools"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
PURPLE='\033[0;35m'
NC='\033[0m'

# Counters
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0
WARNING_TESTS=0

# Logging function
log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] [$level] $message" >> "$LOG_FILE"
}

# Test result functions
test_pass() {
    local test_name="$1"
    echo -e "${GREEN}[PASS]${NC} $test_name"
    ((PASSED_TESTS++))
    log "INFO" "PASS: $test_name"
}

test_fail() {
    local test_name="$1"
    echo -e "${RED}[FAIL]${NC} $test_name"
    ((FAILED_TESTS++))
    log "ERROR" "FAIL: $test_name"
}

test_warn() {
    local test_name="$1"
    echo -e "${YELLOW}[WARN]${NC} $test_name"
    ((WARNING_TESTS++))
    log "WARNING" "WARN: $test_name"
}

run_test() {
    ((TOTAL_TESTS++))
}

# Header
print_header() {
    clear
    echo -e "${PURPLE}╔════════════════════════════════════════════════╗${NC}"
    echo -e "${PURPLE}║              CTF Setup Verification            ║${NC}"
    echo -e "${PURPLE}║           Industrial Security Edition          ║${NC}"
    echo -e "${PURPLE}╚════════════════════════════════════════════════╝${NC}"
    echo ""
}

# System verification
verify_system() {
    echo -e "${CYAN}=== System Verification ===${NC}"
    
    # Check OS
    run_test
    if grep -q "kali" /etc/os-release 2>/dev/null; then
        test_pass "Operating System: Kali Linux detected"
    else
        test_warn "Operating System: Not Kali Linux ($(lsb_release -d 2>/dev/null | cut -f2 || echo 'Unknown'))"
    fi
    
    # Check Python version
    run_test
    if command -v python3 &> /dev/null; then
        local python_version=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}')")
        if [[ "$(printf '%s\n' "3.8.0" "$python_version" | sort -V | head -n1)" == "3.8.0" ]]; then
            test_pass "Python Version: $python_version (>= 3.8.0)"
        else
            test_fail "Python Version: $python_version (< 3.8.0)"
        fi
    else
        test_fail "Python Version: Python 3 not found"
    fi
    
    # Check pip
    run_test
    if command -v pip3 &> /dev/null; then
        local pip_version=$(pip3 --version | cut -d' ' -f2)
        test_pass "Pip Version: $pip_version"
    else
        test_fail "Pip: Not found"
    fi
    
    # Check git
    run_test
    if command -v git &> /dev/null; then
        local git_version=$(git --version | cut -d' ' -f3)
        test_pass "Git Version: $git_version"
    else
        test_fail "Git: Not found"
    fi
    
    echo ""
}

# Virtual environment verification
verify_virtual_env() {
    echo -e "${CYAN}=== Virtual Environment Verification ===${NC}"
    
    # Check if virtual environment exists
    run_test
    if [[ -d "$VENV_PATH" ]]; then
        test_pass "Virtual Environment: Found at $VENV_PATH"
    else
        test_fail "Virtual Environment: Not found at $VENV_PATH"
        return
    fi
    
    # Check if virtual environment is functional
    run_test
    if source "$VENV_PATH/bin/activate" 2>/dev/null; then
        local venv_python_version=$(python --version 2>&1 | cut -d' ' -f2)
        test_pass "Virtual Environment Activation: Success (Python $venv_python_version)"
        deactivate
    else
        test_fail "Virtual Environment Activation: Failed"
        return
    fi
    
    echo ""
}

# Python packages verification
verify_python_packages() {
    echo -e "${CYAN}=== Python Packages Verification ===${NC}"
    
    if [[ ! -d "$VENV_PATH" ]]; then
        echo -e "${RED}Skipping Python packages - Virtual environment not found${NC}"
        return
    fi
    
    source "$VENV_PATH/bin/activate"
    
    # Critical packages
    local critical_packages=("requests" "urllib3" "scapy" "pwntools" "paramiko" "click" "colorama")
    
    for package in "${critical_packages[@]}"; do
        run_test
        if python -c "import $package" 2>/dev/null; then
            local version=$(pip show "$package" 2>/dev/null | grep Version | cut -d' ' -f2)
            test_pass "Python Package: $package ($version)"
        else
            test_fail "Python Package: $package (not found or broken)"
        fi
    done
    
    # High priority packages
    local high_packages=("beautifulsoup4" "selenium" "cryptography" "netaddr" "impacket")
    
    for package in "${high_packages[@]}"; do
        run_test
        local import_name="$package"
        [[ "$package" == "beautifulsoup4" ]] && import_name="bs4"
        
        if python -c "import $import_name" 2>/dev/null; then
            local version=$(pip show "$package" 2>/dev/null | grep Version | cut -d' ' -f2)
            test_pass "Python Package: $package ($version)"
        else
            test_warn "Python Package: $package (not found)"
        fi
    done
    
    # ICS packages
    local ics_packages=("pymodbus" "snap7" "pysnmp")
    
    for package in "${ics_packages[@]}"; do
        run_test
        local import_name="$package"
        [[ "$package" == "snap7" ]] && import_name="snap7"
        
        if python -c "import $import_name" 2>/dev/null; then
            local version=$(pip show "$package" 2>/dev/null | grep Version | cut -d' ' -f2)
            test_pass "ICS Package: $package ($version)"
        else
            test_warn "ICS Package: $package (not found)"
        fi
    done
    
    deactivate
    echo ""
}

# System tools verification
verify_system_tools() {
    echo -e "${CYAN}=== System Tools Verification ===${NC}"
    
    # Critical tools
    local critical_tools=("nmap" "curl" "wget" "build-essential")
    
    for tool in "${critical_tools[@]}"; do
        run_test
        if [[ "$tool" == "build-essential" ]]; then
            if dpkg -l | grep -q "^ii  build-essential "; then
                test_pass "System Tool: $tool (installed)"
            else
                test_fail "System Tool: $tool (not installed)"
            fi
        else
            if command -v "$tool" &> /dev/null; then
                local version=""
                case "$tool" in
                    "nmap") version=$(nmap --version 2>/dev/null | head -1 | cut -d' ' -f3) ;;
                    "curl") version=$(curl --version 2>/dev/null | head -1 | cut -d' ' -f2) ;;
                    "wget") version=$(wget --version 2>/dev/null | head -1 | cut -d' ' -f3) ;;
                    *) version=$(command -v "$tool") ;;
                esac
                test_pass "System Tool: $tool ($version)"
            else
                test_fail "System Tool: $tool (not found)"
            fi
        fi
    done
    
    # Web testing tools
    local web_tools=("gobuster" "nikto" "dirb" "sqlmap")
    
    for tool in "${web_tools[@]}"; do
        run_test
        if command -v "$tool" &> /dev/null; then
            test_pass "Web Tool: $tool (available)"
        else
            test_warn "Web Tool: $tool (not found)"
        fi
    done
    
    # Network analysis tools
    local network_tools=("wireshark" "tshark" "tcpdump" "masscan")
    
    for tool in "${network_tools[@]}"; do
        run_test
        if command -v "$tool" &> /dev/null; then
            test_pass "Network Tool: $tool (available)"
        else
            test_warn "Network Tool: $tool (not found)"
        fi
    done
    
    # Security tools
    local security_tools=("john" "hashcat" "hydra" "netcat")
    
    for tool in "${security_tools[@]}"; do
        run_test
        local cmd="$tool"
        [[ "$tool" == "netcat" ]] && cmd="nc"
        
        if command -v "$cmd" &> /dev/null; then
            test_pass "Security Tool: $tool (available)"
        else
            test_warn "Security Tool: $tool (not found)"
        fi
    done
    
    echo ""
}

# Metasploit verification
verify_metasploit() {
    echo -e "${CYAN}=== Metasploit Framework Verification ===${NC}"
    
    run_test
    if command -v msfconsole &> /dev/null; then
        test_pass "Metasploit: Framework installed"
        
        # Check database
        run_test
        if sudo -u postgres psql -l 2>/dev/null | grep -q msf; then
            test_pass "Metasploit: Database configured"
        else
            test_warn "Metasploit: Database not configured (run: sudo msfdb init)"
        fi
    else
        test_fail "Metasploit: Framework not found"
    fi
    
    echo ""
}

# ICS tools verification
verify_ics_tools() {
    echo -e "${CYAN}=== ICS Tools Verification ===${NC}"
    
    # Check ICS tools directory
    run_test
    if [[ -d "$TOOLS_DIR" ]]; then
        test_pass "ICS Tools Directory: $TOOLS_DIR exists"
    else
        test_warn "ICS Tools Directory: $TOOLS_DIR not found"
        return
    fi
    
    # Check git tools
    local git_tools=("plcscan" "icsmap" "isf" "redpoint")
    
    for tool in "${git_tools[@]}"; do
        run_test
        if [[ -d "$TOOLS_DIR/$tool" ]]; then
            test_pass "ICS Git Tool: $tool (cloned)"
        else
            test_warn "ICS Git Tool: $tool (not found)"
        fi
    done
    
    # Check custom scripts
    local custom_scripts=("modbus_scanner.py" "s7_scanner.py" "dnp3_scanner.py")
    
    for script in "${custom_scripts[@]}"; do
        run_test
        if [[ -x "$TOOLS_DIR/scripts/$script" ]]; then
            test_pass "ICS Script: $script (executable)"
        else
            test_warn "ICS Script: $script (not found or not executable)"
        fi
    done
    
    # Check wrapper script
    run_test
    if [[ -x "$TOOLS_DIR/bin/ics_scan" ]]; then
        test_pass "ICS Wrapper: ics_scan (executable)"
    else
        test_warn "ICS Wrapper: ics_scan (not found)"
    fi
    
    # Check modbus-cli
    run_test
    if command -v modbus &> /dev/null; then
        test_pass "ICS Tool: modbus-cli (gem installed)"
    else
        test_warn "ICS Tool: modbus-cli (not found)"
    fi
    
    echo ""
}

# Network connectivity test
verify_network() {
    echo -e "${CYAN}=== Network Connectivity Verification ===${NC}"
    
    # Internet connectivity
    run_test
    if ping -c 1 google.com &> /dev/null; then
        test_pass "Internet Connectivity: Available"
    else
        test_warn "Internet Connectivity: Not available or restricted"
    fi
    
    # DNS resolution
    run_test
    if nslookup google.com &> /dev/null; then
        test_pass "DNS Resolution: Working"
    else
        test_warn "DNS Resolution: Not working"
    fi
    
    echo ""
}

# File permissions and security
verify_security() {
    echo -e "${CYAN}=== Security and Permissions Verification ===${NC}"
    
    # Check if user is in necessary groups
    local groups_to_check=("wireshark")
    
    for group in "${groups_to_check[@]}"; do
        run_test
        if groups | grep -q "$group"; then
            test_pass "User Groups: Member of $group group"
        else
            test_warn "User Groups: Not in $group group (may need: sudo usermod -a -G $group \$USER)"
        fi
    done
    
    # Check sudo access
    run_test
    if sudo -n true 2>/dev/null; then
        test_pass "Sudo Access: Available without password"
    elif sudo -v 2>/dev/null; then
        test_pass "Sudo Access: Available with password"
    else
        test_warn "Sudo Access: Not available or not configured"
    fi
    
    echo ""
}

# Generate test report
generate_report() {
    echo -e "${CYAN}=== Verification Summary ===${NC}"
    echo ""
    
    local pass_percentage=$((PASSED_TESTS * 100 / TOTAL_TESTS))
    
    echo -e "Total Tests: ${BLUE}$TOTAL_TESTS${NC}"
    echo -e "Passed: ${GREEN}$PASSED_TESTS${NC} (${pass_percentage}%)"
    echo -e "Failed: ${RED}$FAILED_TESTS${NC}"
    echo -e "Warnings: ${YELLOW}$WARNING_TESTS${NC}"
    echo ""
    
    if [[ $FAILED_TESTS -eq 0 ]]; then
        echo -e "${GREEN}✓ CTF environment verification completed successfully!${NC}"
        echo -e "${GREEN}Your system is ready for CTF competitions.${NC}"
        log "INFO" "Verification completed successfully: $PASSED_TESTS/$TOTAL_TESTS tests passed"
    elif [[ $FAILED_TESTS -le 3 ]]; then
        echo -e "${YELLOW}⚠ CTF environment verification completed with minor issues.${NC}"
        echo -e "${YELLOW}Some non-critical components may need attention.${NC}"
        log "WARNING" "Verification completed with warnings: $FAILED_TESTS failures, $WARNING_TESTS warnings"
    else
        echo -e "${RED}✗ CTF environment verification failed.${NC}"
        echo -e "${RED}Critical components are missing or misconfigured.${NC}"
        log "ERROR" "Verification failed: $FAILED_TESTS failures, $WARNING_TESTS warnings"
    fi
    
    echo ""
    echo -e "${CYAN}Recommendations:${NC}"
    
    if [[ $FAILED_TESTS -gt 0 ]]; then
        echo "• Review failed tests and reinstall missing components"
        echo "• Run individual installation scripts for failed categories"
    fi
    
    if [[ $WARNING_TESTS -gt 0 ]]; then
        echo "• Consider installing warned components for full functionality"
        echo "• Check group memberships and permissions"
    fi
    
    echo "• Regularly update tools and dependencies"
    echo "• Test tools before competitions"
    echo ""
    echo -e "${CYAN}Log file:${NC} $LOG_FILE"
}

# Quick test mode
quick_test() {
    echo -e "${CYAN}Running quick verification...${NC}"
    
    # Essential tests only
    run_test && test_pass "Python 3" || test_fail "Python 3"
    run_test && test_pass "Virtual Environment" || test_fail "Virtual Environment"
    run_test && test_pass "Nmap" || test_fail "Nmap"
    run_test && test_pass "Internet" || test_fail "Internet"
    
    echo -e "${CYAN}Quick test completed: $PASSED_TESTS/$TOTAL_TESTS essential components working${NC}"
}

# Main verification function
main() {
    local mode="${1:-full}"
    
    log "INFO" "Starting CTF setup verification - Mode: $mode"
    
    case "$mode" in
        "quick"|"-q"|"--quick")
            quick_test
            ;;
        "python"|"--python")
            print_header
            verify_virtual_env
            verify_python_packages
            generate_report
            ;;
        "system"|"--system")
            print_header
            verify_system
            verify_system_tools
            verify_metasploit
            generate_report
            ;;
        "ics"|"--ics")
            print_header
            verify_ics_tools
            generate_report
            ;;
        "network"|"--network")
            print_header
            verify_network
            generate_report
            ;;
        "full"|"--full"|"")
            print_header
            verify_system
            verify_virtual_env
            verify_python_packages
            verify_system_tools
            verify_metasploit
            verify_ics_tools
            verify_network
            verify_security
            generate_report
            ;;
        "help"|"-h"|"--help")
            echo "Usage: $0 [mode]"
            echo "Modes:"
            echo "  full     - Complete verification (default)"
            echo "  quick    - Quick essential tests only"
            echo "  python   - Python environment only"
            echo "  system   - System tools only"
            echo "  ics      - ICS tools only"
            echo "  network  - Network connectivity only"
            echo "  help     - Show this help"
            exit 0
            ;;
        *)
            echo "Unknown mode: $mode"
            echo "Use '$0 help' for usage information"
            exit 1
            ;;
    esac
}

# Run main function
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi