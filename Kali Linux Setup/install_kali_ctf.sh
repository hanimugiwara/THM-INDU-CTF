#!/bin/bash

# Kali Linux CTF Setup - Main Installation Script
# Author: CTF Team Setup Automation
# Description: Menu-driven installation system for CTF competition environment
# Version: 1.0

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_FILE="$SCRIPT_DIR/ctf_setup.log"
CONFIG_FILE="$SCRIPT_DIR/ctf_config.conf"
BACKUP_DIR="$SCRIPT_DIR/backups"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

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
        *)         echo "[$level] $message" ;;
    esac
}

# Progress indicator
show_progress() {
    local current=$1
    local total=$2
    local task="$3"
    local percent=$((current * 100 / total))
    local done=$((percent * 4 / 10))
    local left=$((40 - done))
    
    printf "\r${CYAN}[Progress]${NC} $task "
    printf "[%*s%*s] %d%%" "$done" "$(printf "%*s" "$done" | tr ' ' '=')" "$left" "" "$percent"
}

# Pre-flight checks
preflight_checks() {
    log "INFO" "Running pre-flight checks..."
    
    # Check if running as root for certain operations
    if [[ $EUID -eq 0 ]]; then
        log "WARNING" "Running as root. Some operations may not require root privileges."
    fi
    
    # Check internet connectivity
    if ! ping -c 1 google.com &> /dev/null; then
        log "ERROR" "No internet connection detected. Installation requires internet access."
        exit 1
    fi
    
    # Check available disk space (minimum 5GB)
    local available_space=$(df / | awk 'NR==2 {print $4}')
    if [[ $available_space -lt 5242880 ]]; then  # 5GB in KB
        log "ERROR" "Insufficient disk space. At least 5GB required."
        exit 1
    fi
    
    # Check if running on Kali Linux
    if ! grep -q "kali" /etc/os-release 2>/dev/null; then
        log "WARNING" "Not running on Kali Linux. Some packages may not be available."
    fi
    
    # Create necessary directories
    mkdir -p "$BACKUP_DIR"
    
    log "SUCCESS" "Pre-flight checks completed successfully"
}

# Load configuration
load_config() {
    if [[ -f "$CONFIG_FILE" ]]; then
        source "$CONFIG_FILE"
        log "INFO" "Configuration loaded from $CONFIG_FILE"
    else
        log "INFO" "No configuration file found. Using defaults."
    fi
}

# Main menu
show_menu() {
    clear
    echo -e "${PURPLE}╔════════════════════════════════════════════════╗${NC}"
    echo -e "${PURPLE}║              Kali Linux CTF Setup              ║${NC}"
    echo -e "${PURPLE}║           Industrial Security Edition          ║${NC}"
    echo -e "${PURPLE}╚════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${CYAN}Installation Options:${NC}"
    echo "  1) Complete Installation (All Components)"
    echo "  2) Critical Priority Only (Essential tools)"
    echo "  3) High Priority (Critical + Web/Network tools)"
    echo "  4) Medium Priority (High + Password/ICS tools)"
    echo "  5) Low Priority (All remaining tools)"
    echo ""
    echo -e "${CYAN}Component-Specific Installation:${NC}"
    echo "  6) Python Dependencies Only"
    echo "  7) System Tools Only"
    echo "  8) Industrial Control Systems Tools"
    echo "  9) Web Application Testing Tools"
    echo " 10) Network Analysis Tools"
    echo ""
    echo -e "${CYAN}Management Options:${NC}"
    echo " 11) Verify Installation"
    echo " 12) View Installation Log"
    echo " 13) Create System Backup"
    echo " 14) Configuration Settings"
    echo ""
    echo "  0) Exit"
    echo ""
    echo -n "Select an option [0-14]: "
}

# Installation functions
install_by_priority() {
    local priority="$1"
    log "INFO" "Starting $priority priority installation"
    
    case "$priority" in
        "critical")
            bash "$SCRIPT_DIR/install_python_deps.sh" --priority critical
            bash "$SCRIPT_DIR/install_system_tools.sh" --priority critical
            ;;
        "high")
            install_by_priority "critical"
            bash "$SCRIPT_DIR/install_system_tools.sh" --priority high
            bash "$SCRIPT_DIR/install_python_deps.sh" --priority high
            ;;
        "medium")
            install_by_priority "high"
            bash "$SCRIPT_DIR/install_system_tools.sh" --priority medium
            bash "$SCRIPT_DIR/install_ics_tools.sh"
            ;;
        "low"|"complete")
            install_by_priority "medium"
            bash "$SCRIPT_DIR/install_system_tools.sh" --priority low
            bash "$SCRIPT_DIR/install_python_deps.sh" --priority low
            ;;
    esac
    
    log "SUCCESS" "$priority priority installation completed"
}

# Component-specific installations
install_python_only() {
    log "INFO" "Installing Python dependencies only"
    bash "$SCRIPT_DIR/install_python_deps.sh" --all
}

install_system_only() {
    log "INFO" "Installing system tools only"
    bash "$SCRIPT_DIR/install_system_tools.sh" --all
}

install_ics_only() {
    log "INFO" "Installing ICS tools only"
    bash "$SCRIPT_DIR/install_ics_tools.sh"
}

install_web_tools() {
    log "INFO" "Installing web application testing tools"
    bash "$SCRIPT_DIR/install_system_tools.sh" --category web
}

install_network_tools() {
    log "INFO" "Installing network analysis tools"
    bash "$SCRIPT_DIR/install_system_tools.sh" --category network
}

# Verification
verify_installation() {
    log "INFO" "Running installation verification"
    bash "$SCRIPT_DIR/verify_installation.sh"
}

# View log
view_log() {
    if [[ -f "$LOG_FILE" ]]; then
        less "$LOG_FILE"
    else
        log "WARNING" "No log file found"
    fi
}

# Create backup
create_backup() {
    log "INFO" "Creating system backup"
    local backup_file="$BACKUP_DIR/system_backup_$(date +%Y%m%d_%H%M%S).tar.gz"
    
    # Backup package lists
    dpkg --get-selections > "$BACKUP_DIR/package_list.txt"
    pip list > "$BACKUP_DIR/python_packages.txt" 2>/dev/null || true
    
    log "SUCCESS" "Backup created: $backup_file"
}

# Configuration settings
configure_settings() {
    echo -e "${CYAN}Configuration Settings:${NC}"
    echo "1) Set installation timeout"
    echo "2) Configure proxy settings"
    echo "3) Set virtual environment name"
    echo "4) Reset to defaults"
    echo "0) Back to main menu"
    echo ""
    echo -n "Select option: "
    read config_choice
    
    case "$config_choice" in
        1) 
            echo -n "Enter timeout in seconds (default 300): "
            read timeout
            echo "INSTALL_TIMEOUT=${timeout:-300}" >> "$CONFIG_FILE"
            ;;
        2)
            echo -n "Enter proxy URL (leave empty for none): "
            read proxy
            if [[ -n "$proxy" ]]; then
                echo "PROXY_URL=$proxy" >> "$CONFIG_FILE"
            fi
            ;;
        3)
            echo -n "Enter virtual environment name (default ctf_env): "
            read venv_name
            echo "VENV_NAME=${venv_name:-ctf_env}" >> "$CONFIG_FILE"
            ;;
        4)
            rm -f "$CONFIG_FILE"
            log "INFO" "Configuration reset to defaults"
            ;;
    esac
}

# Error handling
handle_error() {
    local exit_code=$?
    local line_number=$1
    log "ERROR" "Script failed on line $line_number with exit code $exit_code"
    echo -e "${RED}Installation failed. Check log file: $LOG_FILE${NC}"
    exit $exit_code
}

# Signal handlers
cleanup() {
    log "INFO" "Script interrupted. Cleaning up..."
    exit 130
}

# Set up signal handling
trap 'handle_error $LINENO' ERR
trap cleanup SIGINT SIGTERM

# Main execution
main() {
    # Initialize
    log "INFO" "Starting Kali Linux CTF Setup - Version 1.0"
    preflight_checks
    load_config
    
    # Check for command line arguments
    if [[ $# -gt 0 ]]; then
        case "$1" in
            "--complete"|"-c")
                install_by_priority "complete"
                verify_installation
                exit 0
                ;;
            "--critical")
                install_by_priority "critical"
                exit 0
                ;;
            "--verify"|"-v")
                verify_installation
                exit 0
                ;;
            "--help"|"-h")
                echo "Usage: $0 [--complete|--critical|--verify|--help]"
                echo "  --complete, -c : Install all components"
                echo "  --critical     : Install critical components only"
                echo "  --verify, -v   : Verify installation"
                echo "  --help, -h     : Show this help"
                exit 0
                ;;
        esac
    fi
    
    # Interactive menu
    while true; do
        show_menu
        read -r choice
        
        case "$choice" in
            1) install_by_priority "complete" ;;
            2) install_by_priority "critical" ;;
            3) install_by_priority "high" ;;
            4) install_by_priority "medium" ;;
            5) install_by_priority "low" ;;
            6) install_python_only ;;
            7) install_system_only ;;
            8) install_ics_only ;;
            9) install_web_tools ;;
            10) install_network_tools ;;
            11) verify_installation ;;
            12) view_log ;;
            13) create_backup ;;
            14) configure_settings ;;
            0) 
                log "INFO" "Installation script completed"
                echo -e "${GREEN}Thank you for using Kali Linux CTF Setup!${NC}"
                exit 0
                ;;
            *)
                log "WARNING" "Invalid option: $choice"
                echo -e "${RED}Invalid option. Please try again.${NC}"
                sleep 2
                ;;
        esac
        
        if [[ "$choice" =~ ^[1-10]$ ]]; then
            echo ""
            echo -e "${GREEN}Operation completed. Press Enter to continue...${NC}"
            read
        fi
    done
}

# Run main function with all arguments
main "$@"