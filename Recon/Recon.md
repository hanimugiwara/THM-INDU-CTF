# Reconnaissance Field Manual

**Authored by: Hex**
**Version: 2.0 - Enhanced Operations Manual**

Team,

Before we attack, we map. Information is our most valuable weapon. This comprehensive manual covers all reconnaissance techniques we'll use to probe the "Industrial Intrusion" network. From passive OSINT gathering to active ICS protocol fingerprinting, every technique has its place in our methodology.

Execute these scans systematically. Log all findings in our `Network_Map.md`. Document everything—timing, responses, anomalies. Intelligence gathering is an art that requires patience and attention to detail.

---

## Table of Contents
1. [Passive Reconnaissance](#passive-reconnaissance)
2. [Active Scanning (Nmap)](#active-scanning-nmap)
3. [DNS Enumeration](#dns-enumeration)
4. [Web Enumeration](#web-enumeration)
5. [Database Enumeration](#database-enumeration)
6. [SNMP Enumeration](#snmp-enumeration)
7. [Industrial Control Systems (ICS) Enumeration](#industrial-control-systems-ics-enumeration)
8. [Packet Analysis](#packet-analysis)
9. [Post-Exploitation Reconnaissance](#post-exploitation-reconnaissance)
10. [Stealth and Evasion Techniques](#stealth-and-evasion-techniques)

---

## Passive Reconnaissance

Begin with passive techniques that don't directly interact with target systems. These methods gather intelligence without leaving traces in target logs.

### OSINT (Open Source Intelligence)

Gather publicly available information about the target organization, employees, and infrastructure.

*   **Google Dorking:**
    ```
    site:virelia.water filetype:pdf
    site:virelia.water "confidential" OR "internal"
    site:virelia.water inurl:admin OR inurl:login
    "virelia water" filetype:xls OR filetype:doc
    ```
    *   Search for leaked documents, admin panels, and sensitive information indexed by search engines.

*   **Shodan Reconnaissance:**
    ```bash
    # Search for organization's exposed devices
    shodan search "org:Virelia Water"
    shodan search "hostname:virelia.water"
    shodan search "Modbus" country:US city:"Target City"
    ```
    *   Identify internet-facing industrial devices and services.

*   **Certificate Transparency Logs:**
    ```bash
    # Find subdomains via SSL certificates
    curl -s "https://crt.sh/?q=%25.virelia.water&output=json" | jq -r '.[].name_value' | sort -u
    ```

### Social Media Intelligence (SOCMINT)

*   **LinkedIn Enumeration:**
    *   Identify employees, organizational structure, and technologies used
    *   Look for system administrators, engineers, and IT personnel
    *   Note job postings mentioning specific technologies

*   **GitHub/GitLab Reconnaissance:**
    ```bash
    # Search for leaked credentials or configuration files
    python3 gitdorker.py -tf tokens.txt -q virelia.water -d dorkers/
    ```

---

## Active Scanning (Nmap)

Nmap remains our primary tool for network discovery and security auditing. Use different scan types based on the situation and stealth requirements.

### Host Discovery Techniques

**1. ICMP Ping Scan (Default)**
```bash
nmap -sn 10.10.X.X/24
# Fast host discovery using ICMP echo requests
```

**2. TCP SYN Ping (Stealth Alternative)**
```bash
nmap -sn -PS80,443,22 10.10.X.X/24
# Uses TCP SYN packets to common ports when ICMP is blocked
```

**3. ARP Ping (Local Network)**
```bash
nmap -sn -PR 10.10.X.X/24
# Most reliable for local network segments
```

**4. UDP Ping (Firewall Bypass)**
```bash
nmap -sn -PU53,67,68,123 10.10.X.X/24
# Uses UDP packets to common services
```

### Port Scanning Techniques

**1. TCP SYN Scan (Stealth Scan)**
```bash
nmap -sS -p- --min-rate 1000 -T4 [TARGET_IP]
# Half-open scan, doesn't complete TCP handshake
```

**2. TCP Connect Scan (Full Connection)**
```bash
nmap -sT -p 1-65535 [TARGET_IP]
# Full TCP connection, more reliable but easily logged
```

**3. UDP Scan (Critical for ICS)**
```bash
nmap -sU --top-ports 1000 [TARGET_IP]
# Many ICS protocols use UDP (SNMP, DHCP, DNS)
```

**4. Comprehensive Service Detection**
```bash
nmap -sV -sC -A -p- -oA nmap_comprehensive [TARGET_IP]
# -A enables OS detection, version detection, script scanning, and traceroute
```

### Advanced Scanning Options

**1. Timing Templates**
```bash
nmap -T0 [TARGET_IP]  # Paranoid (very slow, IDS evasion)
nmap -T1 [TARGET_IP]  # Sneaky (slow, some IDS evasion)
nmap -T2 [TARGET_IP]  # Polite (slower, less bandwidth)
nmap -T3 [TARGET_IP]  # Normal (default)
nmap -T4 [TARGET_IP]  # Aggressive (faster, parallel scans)
nmap -T5 [TARGET_IP]  # Insane (very fast, may miss results)
```

**2. Firewall/IDS Evasion**
```bash
# Fragment packets
nmap -f [TARGET_IP]

# Use decoys
nmap -D RND:10 [TARGET_IP]

# Source port spoofing
nmap --source-port 53 [TARGET_IP]

# Randomize target order
nmap --randomize-hosts [TARGET_RANGE]
```

### Specialized ICS Scanning

**1. Modbus Protocol (Port 502/TCP)**
```bash
# Basic Modbus discovery
nmap --script modbus-discover -p 502 [TARGET_IP]

# Enumerate Modbus device information
nmap --script modbus-discover,modbus-enum -p 502 [TARGET_IP]

# Read Modbus coils and registers
nmap --script modbus-discover --script-args modbus-discover.aggressive=true -p 502 [TARGET_IP]
```

**2. Siemens S7 Protocol (Port 102/TCP)**
```bash
# S7 device information
nmap --script s7-info -p 102 [TARGET_IP]

# Enumerate S7 modules
nmap --script s7-enum -p 102 [TARGET_IP]

# S7 security assessment
nmap --script s7-info,s7-enum --script-args s7-enum.aggressive=true -p 102 [TARGET_IP]
```

**3. DNP3 Protocol (Port 20000/TCP)**
```bash
# DNP3 device discovery
nmap --script dnp3-info -p 20000 [TARGET_IP]
```

**4. EtherNet/IP Protocol (Port 44818/TCP)**
```bash
# Allen-Bradley and Rockwell devices
nmap --script enip-info -p 44818 [TARGET_IP]
```

**5. BACnet Protocol (Port 47808/UDP)**
```bash
# Building automation systems
nmap --script bacnet-info -sU -p 47808 [TARGET_IP]
```

---

## DNS Enumeration

DNS holds critical infrastructure information. Enumerate thoroughly to map the network architecture.

### Zone Transfer Attempts
```bash
# Attempt zone transfer
dig axfr @[DNS_SERVER] virelia.water

# Try with different record types
dig @[DNS_SERVER] virelia.water ANY
dig @[DNS_SERVER] virelia.water TXT
dig @[DNS_SERVER] virelia.water MX
```

### Subdomain Enumeration
```bash
# DNSRecon - comprehensive DNS enumeration
dnsrecon -d virelia.water -t std,rvl,brt,srv,axfr

# Sublist3r - passive subdomain discovery
sublist3r -d virelia.water -o subdomains.txt

# Fierce - DNS scanner
fierce -dns virelia.water

# Manual brute force with custom wordlist
dnsrecon -d virelia.water -t brt -D /usr/share/wordlists/dnsmap.txt
```

### DNS Cache Snooping
```bash
# Check if DNS server has cached specific records
dig @[DNS_SERVER] virelia.water +norecurse
nslookup -norecurse virelia.water [DNS_SERVER]
```

---

## Web Enumeration

Web applications often provide the largest attack surface in industrial environments.

### Directory and File Discovery

**1. Gobuster (Fast and Reliable)**
```bash
# Directory enumeration
gobuster dir -u http://[TARGET_IP] -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,txt,bak,old,zip

# Common backup files
gobuster dir -u http://[TARGET_IP] -w /usr/share/wordlists/dirb/common.txt -x bak,backup,old,tmp

# API endpoint discovery
gobuster dir -u http://[TARGET_IP] -w /usr/share/wordlists/api_endpoints.txt -x json,xml

# Virtual host enumeration
gobuster vhost -u http://[TARGET_IP] -w /usr/share/wordlists/subdomains-top1million-5000.txt
```

**2. Dirb (Recursive Scanning)**
```bash
# Basic directory scan
dirb http://[TARGET_IP] /usr/share/wordlists/dirb/common.txt

# Scan with extensions
dirb http://[TARGET_IP] -X .php,.txt,.bak,.old
```

**3. Dirsearch (Python-based)**
```bash
# Fast directory brute force
python3 dirsearch.py -u http://[TARGET_IP] -e php,txt,bak,old,zip -t 50

# Recursive scanning
python3 dirsearch.py -u http://[TARGET_IP] -e * -r -R 3
```

### Web Application Analysis

**1. Nikto (Vulnerability Scanner)**
```bash
# Basic vulnerability scan
nikto -h http://[TARGET_IP]

# Comprehensive scan with all plugins
nikto -h http://[TARGET_IP] -Plugins @@ALL

# Output to file
nikto -h http://[TARGET_IP] -o nikto_results.html -Format htm
```

**2. WhatWeb (Technology Fingerprinting)**
```bash
# Basic fingerprinting
whatweb http://[TARGET_IP]

# Aggressive scanning
whatweb -a 3 http://[TARGET_IP]

# Batch scanning
whatweb -i targets.txt --log-brief whatweb_results.log
```

**3. Wappalyzer (Technology Stack Detection)**
```bash
# Command line version
wappalyzer http://[TARGET_IP]
```

### SSL/TLS Analysis
```bash
# SSL certificate information
openssl s_client -connect [TARGET_IP]:443 -servername [HOSTNAME]

# SSL vulnerability testing
sslscan [TARGET_IP]:443
testssl.sh [TARGET_IP]:443

# Certificate transparency logs
curl -s "https://crt.sh/?q=[TARGET_IP]&output=json" | jq '.'
```

---

## Database Enumeration

Industrial systems often use databases for configuration, logging, and process data storage.

### MySQL (Port 3306)
```bash
# Version detection
nmap --script mysql-info -p 3306 [TARGET_IP]

# Brute force authentication
nmap --script mysql-brute -p 3306 [TARGET_IP]

# Database enumeration
nmap --script mysql-databases --script-args mysqluser=root,mysqlpass='' -p 3306 [TARGET_IP]

# Empty password check
nmap --script mysql-empty-password -p 3306 [TARGET_IP]
```

### PostgreSQL (Port 5432)
```bash
# Basic enumeration
nmap --script pgsql-brute -p 5432 [TARGET_IP]

# Database listing
psql -h [TARGET_IP] -U postgres -l
```

### Microsoft SQL Server (Port 1433)
```bash
# MSSQL information gathering
nmap --script ms-sql-info -p 1433 [TARGET_IP]

# Authentication brute force
nmap --script ms-sql-brute -p 1433 [TARGET_IP]

# Empty password check
nmap --script ms-sql-empty-password -p 1433 [TARGET_IP]
```

### Oracle (Port 1521)
```bash
# Oracle TNS enumeration
nmap --script oracle-tns-version -p 1521 [TARGET_IP]

# SID enumeration
nmap --script oracle-sid-brute -p 1521 [TARGET_IP]
```

---

## SNMP Enumeration

SNMP is commonly found in network infrastructure and industrial devices.

### Basic SNMP Scanning
```bash
# SNMP version detection
nmap -sU --script snmp-info -p 161 [TARGET_IP]

# Community string brute force
nmap --script snmp-brute -p 161 [TARGET_IP]

# SNMP walking
snmpwalk -c public -v1 [TARGET_IP]
snmpwalk -c public -v2c [TARGET_IP] 1.3.6.1.2.1.1
```

### Advanced SNMP Enumeration
```bash
# System information
snmpwalk -c public -v2c [TARGET_IP] 1.3.6.1.2.1.1.1.0

# Network interfaces
snmpwalk -c public -v2c [TARGET_IP] 1.3.6.1.2.1.2.2.1.2

# Routing table
snmpwalk -c public -v2c [TARGET_IP] 1.3.6.1.2.1.4.21.1.1

# ARP table
snmpwalk -c public -v2c [TARGET_IP] 1.3.6.1.2.1.4.22.1.2

# Process list
snmpwalk -c public -v2c [TARGET_IP] 1.3.6.1.2.1.25.4.2.1.2
```

### SNMP Wordlist Attack
```bash
# Community string enumeration
onesixtyone -c /usr/share/wordlists/metasploit/snmp_default_pass.txt [TARGET_IP]
hydra -P /usr/share/wordlists/metasploit/snmp_default_pass.txt [TARGET_IP] snmp
```

---

## Industrial Control Systems (ICS) Enumeration

Comprehensive enumeration of industrial protocols and devices.

### Modbus Protocol Analysis
```bash
# Advanced Modbus scanning with custom Python script
python3 modbus_scanner.py --target [TARGET_IP] --port 502 --unit-id 1-247

# Read specific registers
nmap --script modbus-discover --script-args modbus-discover.registers="40001-40010" -p 502 [TARGET_IP]

# Function code enumeration
nmap --script modbus-discover --script-args modbus-discover.functions="1,2,3,4,5,6" -p 502 [TARGET_IP]
```

### Siemens S7 Deep Analysis
```bash
# Complete S7 enumeration
nmap --script s7-info,s7-enum --script-args s7-enum.modules=true -p 102 [TARGET_IP]

# Memory layout discovery
nmap --script s7-info --script-args s7-info.timeout=5s -p 102 [TARGET_IP]
```

### DNP3 (Distributed Network Protocol)
```bash
# DNP3 comprehensive scan
nmap --script dnp3-info,dnp3-enum -p 20000 [TARGET_IP]

# Data link layer analysis
python3 dnp3_analyzer.py --target [TARGET_IP] --port 20000
```

### EtherNet/IP (Allen-Bradley)
```bash
# EtherNet/IP device enumeration
nmap --script enip-info,enip-enum -p 44818 [TARGET_IP]

# CIP (Common Industrial Protocol) analysis
python3 cip_scanner.py --target [TARGET_IP]
```

### OPC (OLE for Process Control)
```bash
# OPC server discovery
nmap --script opc-enum -p 135 [TARGET_IP]

# OPC DA enumeration
python3 opc_client.py --server [TARGET_IP] --enumerate
```

### BACnet (Building Automation)
```bash
# BACnet device discovery
nmap --script bacnet-info -sU -p 47808 [TARGET_IP]

# BACnet object enumeration
python3 bacnet_scanner.py --target [TARGET_IP] --broadcast
```

### ICS-Specific Tools
```bash
# PLCScan - PLC device scanner
python plcscan.py [TARGET_RANGE]

# Redpoint - ICS enumeration framework
redpoint --target [TARGET_IP] --protocol modbus,s7,dnp3

# ISF (Industrial Security Framework)
python isf.py
use scanners/s7_scanner
set target [TARGET_IP]
run
```

---

## Packet Analysis

Network traffic analysis is crucial for understanding ICS communications and finding cleartext credentials.

### Tcpdump Capture
```bash
# Capture all traffic
tcpdump -i eth0 -w capture.pcap

# Capture specific protocols
tcpdump -i eth0 'port 502 or port 102' -w modbus_s7.pcap

# Capture with timestamps
tcpdump -i eth0 -tttt -w timestamped_capture.pcap
```

### Wireshark Analysis

**Display Filters for ICS Protocols:**
```
# Modbus traffic
modbus

# Siemens S7 communication
s7comm

# DNP3 protocol
dnp3

# EtherNet/IP
enip

# BACnet
bacnet

# OPC traffic
dcerpc

# Combined ICS filter
modbus or s7comm or dnp3 or enip or bacnet

# Suspicious activity
tcp.flags.reset==1 or icmp.type==3

# Large data transfers
frame.len > 1000

# Failed authentication attempts
tcp.flags.rst==1 and tcp.seq==1
```

**Advanced Wireshark Techniques:**
```bash
# Command line analysis
tshark -r capture.pcap -Y "modbus" -T fields -e modbus.func_code -e modbus.reference_num

# Export specific protocol data
tshark -r capture.pcap -Y "s7comm" -w s7_only.pcap

# Statistics generation
tshark -r capture.pcap -q -z conv,tcp
tshark -r capture.pcap -q -z proto,colinfo,modbus.func_code,modbus.func_code
```

### Network Forensics
```bash
# NetworkMiner - passive network sniffer
networkminer capture.pcap

# Extract files from PCAP
foremost -i capture.pcap -o extracted_files/

# Analyze HTTP traffic
python3 http_analyzer.py --pcap capture.pcap --extract-files
```

---

## Post-Exploitation Reconnaissance

Once you have initial access, expand your understanding of the internal network.

### Internal Network Discovery
```bash
# ARP table enumeration
arp -a
cat /proc/net/arp

# Network configuration
ip route show
netstat -rn

# Active connections
netstat -tulpn
ss -tulpn

# Internal port scanning from compromised host
./nmap_static -sS -p- internal_target

# Ping sweep internal networks
for i in {1..254}; do ping -c 1 192.168.1.$i | grep "bytes from"; done
```

### Windows Active Directory Enumeration
```bash
# Domain information
net user /domain
net group /domain
net group "Domain Admins" /domain

# System information
systeminfo
whoami /all

# Network shares
net view
net share

# PowerShell AD enumeration
powershell -ep bypass
Import-Module ActiveDirectory
Get-ADUser -Filter *
Get-ADComputer -Filter *
```

### Linux System Enumeration
```bash
# User enumeration
cat /etc/passwd
cat /etc/group
who
w

# Cron jobs and scheduled tasks
crontab -l
cat /etc/crontab
ls -la /etc/cron*

# Network services
systemctl list-units --type=service
service --status-all

# File system interesting locations
find / -name "*.conf" 2>/dev/null
find / -name "*password*" 2>/dev/null
find / -name "*key*" 2>/dev/null
```

---

## Stealth and Evasion Techniques

Avoid detection while gathering intelligence.

### Timing and Rate Limiting
```bash
# Slow scan with delays
nmap --scan-delay 5s [TARGET_IP]

# Randomize timing
nmap --max-rtt-timeout 200ms --initial-rtt-timeout 100ms [TARGET_IP]

# Limit concurrent connections
nmap --max-parallelism 1 [TARGET_IP]
```

### Source IP Obfuscation
```bash
# Use proxies
proxychains nmap [TARGET_IP]

# Tor network
torsocks nmap [TARGET_IP]

# VPN rotation
openvpn config1.ovpn &
nmap [TARGET_IP]
killall openvpn
openvpn config2.ovpn &
```

### Packet Fragmentation
```bash
# IP fragmentation
nmap -f [TARGET_IP]
nmap -ff [TARGET_IP]

# MTU specification
nmap --mtu 16 [TARGET_IP]
```

### Living off the Land
```bash
# Use legitimate tools
curl -I http://[TARGET_IP]
telnet [TARGET_IP] 80
nc -nv [TARGET_IP] 22

# PowerShell web requests (Windows)
powershell -c "Invoke-WebRequest -Uri http://[TARGET_IP]"

# Built-in port scanners
bash -c 'cat < /dev/tcp/[TARGET_IP]/22'
```

---

## Documentation and Reporting

Maintain detailed logs of all reconnaissance activities:

1. **Command Log:** Record every command executed with timestamps
2. **Target Inventory:** Maintain a spreadsheet of discovered systems
3. **Vulnerability Matrix:** Map discovered vulnerabilities to systems
4. **Network Diagrams:** Create visual representations of network topology
5. **Screenshot Archive:** Capture evidence of web interfaces and applications

Remember: Reconnaissance is 80% of the penetration test. The more thorough your information gathering, the more successful your exploitation phase will be.

**Stay methodical. Stay stealthy. Stay persistent.**

---
*End of Enhanced Reconnaissance Field Manual v2.0*

---

## Web Enumeration

If a host is running a web server (port 80/443), we need to enumerate its content.

### Directory Brute-Forcing (Gobuster)

Find hidden files and directories that aren't linked from the main page. This can reveal admin panels, config files, or source code.

*   **Command:**
    ```bash
    gobuster dir -u http://[TARGET_IP] -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,txt,bak
    ```
    *   `-u`: Target URL.
    *   `-w`: Path to your wordlist.
    *   `-x`: Search for specific file extensions.

### Subdomain Enumeration (Gobuster)

Some applications are segmented across subdomains (e.g., `api.virelia.water`, `admin.virelia.water`).

*   **Command:**
    ```bash
    gobuster vhost -u http://[TARGET_IP] -w /path/to/subdomains.txt
    ```

### Vulnerability Scanning (Nikto)

Nikto is an automated web server scanner that checks for thousands of potentially dangerous files/CGIs, outdated software versions, and other common misconfigurations.

*   **Command:**
    ```bash
    nikto -h http://[TARGET_IP]
    ```

---

## Packet Analysis (Wireshark)

In ICS environments, many protocols transmit data in cleartext. If we can capture network traffic (e.g., via a Man-in-the-Middle attack or from a compromised host), Wireshark is our microscope. Look for credentials, commands, and flag data being sent over the wire.

*   **Useful Display Filters:**
    *   `modbus`: Show only Modbus traffic.
    *   `s7comm`: Show only Siemens S7 traffic.
    *   `dnp3`: Show only DNP3 traffic.
    *   `ip.addr == [TARGET_IP]`: Show all traffic to and from a specific IP.
    *   `tcp.port == 80 && http.request`: Isolate HTTP GET/POST requests to see what users are accessing.