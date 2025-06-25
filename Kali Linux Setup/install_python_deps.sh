#!/bin/bash

# Kali Linux CTF Setup - Python Dependencies Installation
# Author: CTF Team Setup Automation
# Description: Install Python packages and setup virtual environments for CTF
# Version: 1.0

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_FILE="$SCRIPT_DIR/ctf_setup.log"
VENV_NAME="${VENV_NAME:-ctf_env}"
VENV_PATH="$HOME/$VENV_NAME"

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

# Python packages by priority
declare -A CRITICAL_PACKAGES=(
    ["requests"]=">=2.25.0"
    ["urllib3"]=">=1.26.0"
    ["scapy"]=""
    ["pwntools"]=""
    ["paramiko"]=""
    ["click"]=""
    ["colorama"]=""
)

declare -A HIGH_PACKAGES=(
    ["beautifulsoup4"]=""
    ["selenium"]=""
    ["cryptography"]=""
    ["pycryptodome"]=""
    ["netaddr"]=""
    ["python-nmap"]=""
    ["impacket"]=""
    ["typer"]=""
    ["termcolor"]=""
    ["rich"]=""
)

declare -A MEDIUM_PACKAGES=(
    ["pymodbus"]=">=3.0.0,<4.0.0"
    ["pymongo"]=""
    ["mysql-connector-python"]=""
    ["psycopg2-binary"]=""
    ["python-snap7"]=""
    ["python-can"]=""
    ["pysnmp"]=""
)

declare -A LOW_PACKAGES=(
    ["pandas"]=""
    ["numpy"]=""
    ["matplotlib"]=""
    ["jupyter"]=""
    ["notebook"]=""
    ["ipython"]=""
)

# Industrial Control Systems packages
declare -A ICS_PACKAGES=(
    ["pymodbus"]=">=3.0.0,<4.0.0"
    ["python-snap7"]=""
    ["python-can"]=""
    ["pysnmp"]=""
    ["pyasn1"]=""
    ["construct"]=""
)

# Check Python version
check_python() {
    log "INFO" "Checking Python installation"
    
    if ! command -v python3 &> /dev/null; then
        log "ERROR" "Python 3 is not installed"
        exit 1
    fi
    
    local python_version=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
    local required_version="3.8"
    
    if [[ "$(printf '%s\n' "$required_version" "$python_version" | sort -V | head -n1)" != "$required_version" ]]; then
        log "ERROR" "Python $required_version or higher required. Found: $python_version"
        exit 1
    fi
    
    log "SUCCESS" "Python $python_version detected"
}

# Install pip and essential tools
install_pip_tools() {
    log "INFO" "Installing pip and essential Python tools"
    
    # Update pip
    python3 -m pip install --upgrade pip
    
    # Install essential tools
    python3 -m pip install --upgrade setuptools wheel virtualenv
    
    log "SUCCESS" "Pip and essential tools installed"
}

# Create virtual environment
create_virtual_env() {
    log "INFO" "Creating virtual environment: $VENV_NAME"
    
    if [[ -d "$VENV_PATH" ]]; then
        log "WARNING" "Virtual environment already exists at $VENV_PATH"
        echo -n "Remove existing environment? [y/N]: "
        read -r response
        if [[ "$response" =~ ^[Yy]$ ]]; then
            rm -rf "$VENV_PATH"
            log "INFO" "Removed existing virtual environment"
        else
            log "INFO" "Using existing virtual environment"
            return 0
        fi
    fi
    
    python3 -m venv "$VENV_PATH"
    log "SUCCESS" "Virtual environment created at $VENV_PATH"
    
    # Activate and upgrade pip in virtual environment
    source "$VENV_PATH/bin/activate"
    pip install --upgrade pip setuptools wheel
    deactivate
    
    log "SUCCESS" "Virtual environment configured"
}

# Install packages
install_packages() {
    local -n packages_ref=$1
    local category="$2"
    local total=${#packages_ref[@]}
    local current=0
    
    log "INFO" "Installing $category packages ($total packages)"
    
    # Activate virtual environment
    source "$VENV_PATH/bin/activate"
    
    for package in "${!packages_ref[@]}"; do
        current=$((current + 1))
        local version_spec="${packages_ref[$package]}"
        local install_name="$package$version_spec"
        
        show_progress "$current" "$total" "$package"
        
        # Check if package is already installed
        if pip show "$package" &> /dev/null; then
            echo -e "\n${YELLOW}[SKIP]${NC} $package (already installed)"
            continue
        fi
        
        # Try to install package with retry logic
        local retry_count=0
        local max_retries=3
        
        while [[ $retry_count -lt $max_retries ]]; do
            if pip install "$install_name" &>> "$LOG_FILE"; then
                echo -e "\n${GREEN}[OK]${NC} $package installed successfully"
                break
            else
                retry_count=$((retry_count + 1))
                echo -e "\n${YELLOW}[RETRY $retry_count/$max_retries]${NC} Failed to install $package"
                sleep 2
            fi
        done
        
        if [[ $retry_count -eq $max_retries ]]; then
            echo -e "\n${RED}[FAIL]${NC} Failed to install $package after $max_retries attempts"
            log "ERROR" "Failed to install $package"
        fi
    done
    
    deactivate
    echo ""
    log "SUCCESS" "$category packages installation completed"
}

# Install requirements.txt if it exists
install_requirements_txt() {
    local req_file="$SCRIPT_DIR/requirements.txt"
    
    if [[ -f "$req_file" ]]; then
        log "INFO" "Installing packages from requirements.txt"
        
        source "$VENV_PATH/bin/activate"
        pip install -r "$req_file"
        deactivate
        
        log "SUCCESS" "Requirements.txt packages installed"
    else
        log "INFO" "No requirements.txt found, skipping"
    fi
}

# Verify installation
verify_packages() {
    log "INFO" "Verifying Python package installation"
    
    source "$VENV_PATH/bin/activate"
    
    # Create verification script
    local verify_script="$SCRIPT_DIR/verify_python.py"
    cat > "$verify_script" << 'EOF'
#!/usr/bin/env python3
import sys
import importlib

packages_to_test = [
    'requests', 'urllib3', 'scapy', 'paramiko', 'click',
    'beautifulsoup4', 'cryptography', 'netaddr', 'pymodbus'
]

failed_imports = []
successful_imports = []

for package in packages_to_test:
    try:
        if package == 'beautifulsoup4':
            importlib.import_module('bs4')
        else:
            importlib.import_module(package)
        successful_imports.append(package)
    except ImportError:
        failed_imports.append(package)

print(f"Successfully imported: {len(successful_imports)} packages")
print(f"Failed imports: {len(failed_imports)} packages")

if failed_imports:
    print(f"Failed packages: {', '.join(failed_imports)}")
    sys.exit(1)
else:
    print("All critical packages imported successfully!")
    sys.exit(0)
EOF
    
    python3 "$verify_script"
    local verify_result=$?
    
    deactivate
    rm -f "$verify_script"
    
    if [[ $verify_result -eq 0 ]]; then
        log "SUCCESS" "Python package verification completed successfully"
    else
        log "ERROR" "Python package verification failed"
        return 1
    fi
}

# Create activation script
create_activation_script() {
    local activate_script="$SCRIPT_DIR/activate_ctf_env.sh"
    
    cat > "$activate_script" << EOF
#!/bin/bash
# CTF Environment Activation Script

source "$VENV_PATH/bin/activate"
echo -e "${GREEN}CTF Virtual Environment Activated${NC}"
echo "Virtual Environment: $VENV_PATH"
echo "Python Version: \$(python --version)"
echo "Pip Version: \$(pip --version)"
echo ""
echo "To deactivate, run: deactivate"
EOF
    
    chmod +x "$activate_script"
    log "SUCCESS" "Activation script created: $activate_script"
}

# Main installation function
main() {
    local priority="${1:-all}"
    
    log "INFO" "Starting Python dependencies installation - Priority: $priority"
    
    # Pre-flight checks
    check_python
    install_pip_tools
    create_virtual_env
    
    # Install packages based on priority
    case "$priority" in
        "critical"|"--priority=critical")
            install_packages CRITICAL_PACKAGES "Critical"
            ;;
        "high"|"--priority=high")
            install_packages HIGH_PACKAGES "High"
            ;;
        "medium"|"--priority=medium")
            install_packages MEDIUM_PACKAGES "Medium"
            ;;
        "low"|"--priority=low")
            install_packages LOW_PACKAGES "Low"
            ;;
        "ics")
            install_packages ICS_PACKAGES "Industrial Control Systems"
            ;;
        "all"|"--all")
            install_packages CRITICAL_PACKAGES "Critical"
            install_packages HIGH_PACKAGES "High"
            install_packages MEDIUM_PACKAGES "Medium"
            install_packages LOW_PACKAGES "Low"
            install_packages ICS_PACKAGES "Industrial Control Systems"
            ;;
    esac
    
    # Install from requirements.txt if available
    install_requirements_txt
    
    # Verify installation
    verify_packages
    
    # Create activation script
    create_activation_script
    
    log "SUCCESS" "Python dependencies installation completed"
    echo ""
    echo -e "${GREEN}Python setup completed successfully!${NC}"
    echo -e "${CYAN}To activate the CTF environment:${NC}"
    echo "  source $SCRIPT_DIR/activate_ctf_env.sh"
    echo ""
    echo -e "${CYAN}Virtual environment location:${NC} $VENV_PATH"
}

# Handle command line arguments
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi