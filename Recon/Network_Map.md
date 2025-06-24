# Operation Virelia: Network & Asset Intelligence Map

**Authored by: Hex**
**Version: 2.0 - Comprehensive Asset Mapping & Threat Analysis**
**Last Updated:** [TIMESTAMP]
**Mission Status:** Active Intelligence Gathering

---

## Executive Summary

This document serves as our central intelligence repository for the "Industrial Intrusion" operation targeting the Virelia Water Treatment Facility. This is a **living document** requiring real-time updates as intelligence is gathered. Every bit of information—from network topology to device fingerprints—contributes to our operational success.

**Operational Objective**: Map the complete network infrastructure, identify high-value targets, and establish attack paths to critical industrial control systems.

---

## Table of Contents
1. [Network Infrastructure Overview](#network-infrastructure-overview)
2. [Target Environment Analysis](#target-environment-analysis)
3. [Discovered Assets & Systems](#discovered-assets--systems)
4. [Industrial Control Systems Matrix](#industrial-control-systems-matrix)
5. [Vulnerability Assessment Matrix](#vulnerability-assessment-matrix)
6. [Network Topology Mapping](#network-topology-mapping)
7. [Attack Path Analysis](#attack-path-analysis)
8. [Credential Harvesting Log](#credential-harvesting-log)
9. [Evidence & Flag Tracking](#evidence--flag-tracking)
10. [Operational Timeline](#operational-timeline)

---

## Network Infrastructure Overview

### Network Ranges & Addressing

| Network Segment | IP Range | Purpose | VLAN ID | Gateway | Notes |
|:---|:---|:---|:---|:---|:---|
| **Primary Target** | `10.10.X.X/24` | Main Network | TBD | TBD | Confirm from THM room |
| **DMZ Segment** | `10.10.X.X/26` | Web Services | TBD | TBD | Public-facing services |
| **OT Network** | `10.10.X.X/26` | Industrial Controls | TBD | TBD | Critical ICS devices |
| **Management** | `10.10.X.X/28` | Admin/Monitoring | TBD | TBD | Network management |
| **Attack Position** | `[YOUR_THM_IP]` | External | N/A | N/A | Our attack platform |

### Network Architecture Assessment

```
┌─────────────────────────────────────────────────────────────┐
│                     INTERNET                                │
└─────────────────────┬───────────────────────────────────────┘
                      │
┌─────────────────────▼───────────────────────────────────────┐
│                  FIREWALL/ROUTER                           │
│                 (Unknown Model)                            │
└─────────────────────┬───────────────────────────────────────┘
                      │
          ┌───────────┼───────────┐
          │           │           │
┌─────────▼──┐  ┌─────▼──┐  ┌─────▼──────┐
│ DMZ Network │  │Corp LAN│  │ OT Network │
│ Web Services│  │ Offices│  │ SCADA/ICS  │
└─────────────┘  └────────┘  └────────────┘
```

---

## Target Environment Analysis

### Organization Profile: Virelia Water Treatment
- **Industry:** Water Treatment & Distribution
- **Location:** [TBD from CTF details]
- **Employees:** ~50-200 (estimated)
- **Primary Assets:** Water treatment processes, pumping stations, quality monitoring

### Technology Stack Assessment
- **Operating Systems:** Linux (Apache servers), Windows (likely workstations)
- **Web Technologies:** Apache 2.4.29, PHP
- **Industrial Protocols:** Modbus TCP (confirmed), Potentially S7, DNP3
- **Security Posture:** Basic (self-signed certificates, open Modbus)

### Critical Infrastructure Components
1. **Human Machine Interface (HMI)** - Process control interface
2. **Programmable Logic Controllers (PLCs)** - Process automation
3. **SCADA System** - Supervisory control and data acquisition
4. **Engineering Workstation (EWS)** - Configuration and programming
5. **Data Historian** - Process data storage and analysis

---

## Discovered Assets & Systems

### Legend
- 🔴 **Critical** - Direct process control, high-value target
- 🟡 **Important** - Network services, potential pivot point
- 🟢 **Standard** - General network device, lower priority
- ⚠️ **Vulnerable** - Known security issues identified
- 🏆 **Compromised** - Successfully exploited

---

### Host: 10.10.141.23 (EXAMPLE - PRIMARY HMI) 🔴⚠️
- **Status:** Online, Critical Target
- **Hostname:** `hmi.virelia.water`
- **Device Type:** Human Machine Interface (HMI)
- **Operating System:** Linux (Apache/2.4.29)
- **Discovery Method:** Initial network scan
- **Last Verified:** [TIMESTAMP]

**Open Ports & Services:**
| Port | Service | Version | Banner/Details | Security Notes |
|:---|:---|:---|:---|:---|
| 22 | SSH | OpenSSH 7.6 | Ubuntu banner | Password auth enabled |
| 80 | HTTP | Apache 2.4.29 | "Virelia Water Control HMI" | Plain HTTP, no HTTPS redirect |
| 443 | HTTPS | Apache 2.4.29 | Self-signed certificate | SSL/TLS config issues |
| 502 | Modbus | Unknown | Unit ID 1, Function codes 1-6 | No authentication |
| 8080 | HTTP | Jetty 9.4.x | Management interface | Basic auth required |

**Web Application Analysis:**
- **Login Page:** `/login.php` - Potential SQL injection
- **Admin Panel:** `/admin/` - Directory listing enabled
- **File Upload:** `/upload/` - Unrestricted file types
- **API Endpoints:** `/api/v1/status`, `/api/v1/control`
- **Configuration:** `/config/` - Backup files exposed

**Modbus Analysis:**
- **Unit ID:** 1 (primary controller)
- **Function Codes:** Read/Write coils and registers
- **Registers:** 40001-40100 (analog inputs), 10001-10050 (discrete inputs)
- **Security:** No authentication, cleartext protocol

**Identified Vulnerabilities:**
- **CVE-2021-41773** - Apache path traversal (potential)
- **SQL Injection** - Login form parameter manipulation
- **Weak SSL/TLS** - Self-signed certificate, weak ciphers
- **Directory Traversal** - Backup files accessible
- **Modbus Security** - No authentication, device manipulation possible

**Attack Vectors:**
1. **Web Application** - SQL injection bypass → admin access
2. **File Upload** - PHP webshell upload → remote code execution
3. **Modbus Protocol** - Direct PLC manipulation
4. **SSH Brute Force** - Weak credentials possible

**Exploitation Status:** 🎯 **PRIMARY TARGET** - Initial entry point
**Estimated Difficulty:** Medium
**Priority:** CRITICAL

---

### Host: [IP_ADDRESS] (TEMPLATE - COPY FOR NEW HOSTS)
- **Status:** [Online/Offline/Unknown]
- **Hostname:** [FQDN or blank]
- **Device Type:** [HMI/PLC/Workstation/Server/Router/etc.]
- **Operating System:** [OS and version]
- **Discovery Method:** [Network scan/DNS/Certificate/etc.]
- **Last Verified:** [TIMESTAMP]

**Open Ports & Services:**
| Port | Service | Version | Banner/Details | Security Notes |
|:---|:---|:---|:---|:---|
| | | | | |

**Additional Analysis:**
- **Web Applications:** [URLs and findings]
- **Industrial Protocols:** [Modbus/S7/DNP3/etc. details]
- **Certificates:** [SSL/TLS certificate details]
- **File Shares:** [SMB/NFS/FTP shares]

**Identified Vulnerabilities:**
- [CVE numbers and descriptions]
- [Configuration weaknesses]
- [Protocol security issues]

**Attack Vectors:**
1. [Primary attack method]
2. [Secondary attack method]
3. [Additional vectors]

**Exploitation Status:** [Not attempted/In progress/Successful/Failed]
**Priority:** [Critical/High/Medium/Low]

---

## Industrial Control Systems Matrix

### Discovered ICS Devices

| IP Address | Device Type | Protocol | Port | Unit/Node ID | Manufacturer | Model | Firmware | Access Level |
|:---|:---|:---|:---|:---|:---|:---|:---|:---|
| 10.10.141.23 | HMI/PLC | Modbus TCP | 502 | 1 | Unknown | Unknown | Unknown | Full Access |
| | | | | | | | | |
| | | | | | | | | |

### Protocol Analysis Summary

**Modbus TCP**
- **Devices Found:** 1 confirmed
- **Security:** No authentication, cleartext
- **Function Codes Supported:** 1,2,3,4,5,6,15,16
- **Register Ranges:** Input: 10001-10050, Holding: 40001-40100
- **Exploitation Potential:** HIGH - Direct process control

**Siemens S7**
- **Devices Found:** 0 (scan pending)
- **Default Port:** 102
- **Security:** Varies by model
- **Exploitation Potential:** TBD

**DNP3**
- **Devices Found:** 0 (scan pending)
- **Default Port:** 20000
- **Security:** Optional authentication
- **Exploitation Potential:** TBD

### Critical Process Control Points
1. **Main Water Treatment Process** - [IP/Port TBD]
2. **Chemical Dosing System** - [IP/Port TBD]
3. **Pumping Station Controls** - [IP/Port TBD]
4. **Quality Monitoring Sensors** - [IP/Port TBD]

---

## Vulnerability Assessment Matrix

### Critical Vulnerabilities (CVSS 9.0-10.0)

| CVE ID | Description | Affected Systems | CVSS Score | Exploitability | Impact |
|:---|:---|:---|:---|:---|:---|
| CVE-2021-41773 | Apache Path Traversal | 10.10.141.23 | 9.8 | High | RCE |
| | | | | | |

### High Vulnerabilities (CVSS 7.0-8.9)

| CVE ID | Description | Affected Systems | CVSS Score | Exploitability | Impact |
|:---|:---|:---|:---|:---|:---|
| Custom-001 | Unauthenticated Modbus | 10.10.141.23 | 8.5 | High | Process Control |
| | | | | | |

### Medium Vulnerabilities (CVSS 4.0-6.9)

| CVE ID | Description | Affected Systems | CVSS Score | Exploitability | Impact |
|:---|:---|:---|:---|:---|:---|
| Custom-002 | Weak SSL Configuration | 10.10.141.23 | 5.3 | Medium | Data Confidentiality |
| | | | | | |

### Configuration Weaknesses

| Issue | System | Severity | Description | Remediation |
|:---|:---|:---|:---|:---|
| Default Credentials | TBD | High | Default usernames/passwords | Change credentials |
| Open File Shares | TBD | Medium | Anonymous SMB/NFS access | Implement authentication |
| Unnecessary Services | TBD | Low | Unused network services | Disable services |

---

## Network Topology Mapping

### Physical Network Layout

```
                    ┌─────────────────┐
                    │   INTERNET      │
                    └─────────┬───────┘
                              │
                    ┌─────────▼───────┐
                    │   FIREWALL      │
                    │   (Unknown)     │
                    └─────────┬───────┘
                              │
                ┌─────────────┼─────────────┐
                │             │             │
        ┌───────▼───┐  ┌──────▼──┐  ┌──────▼──────┐
        │    DMZ    │  │ CORP LAN│  │ OT NETWORK  │
        │ 10.10.X.0 │  │10.10.X.0│  │ 10.10.X.0   │
        └───────────┘  └─────────┘  └─────────────┘
             │              │              │
        ┌────▼────┐    ┌────▼────┐    ┌────▼────┐
        │Web Svcs │    │Desktops │    │HMI/SCADA│
        │         │    │ Servers │    │  PLCs   │
        └─────────┘    └─────────┘    └─────────┘
```

### Logical Network Relationships

**Trust Relationships:**
- DMZ → CORP LAN: Limited (firewall rules)
- CORP LAN → OT NETWORK: Management access
- OT NETWORK → DMZ: Data flow (historians)

**Communication Flows:**
- HMI → PLCs: Modbus TCP/IP
- SCADA → Database: SQL connections
- Workstations → HMI: Web interface
- External → DMZ: HTTP/HTTPS

### Network Segmentation Analysis

| Segment | Security Level | Access Controls | Monitoring | Risk Level |
|:---|:---|:---|:---|:---|
| DMZ | Medium | Firewall rules | Unknown | Medium |
| Corporate LAN | Medium | Domain policies | Unknown | Medium |
| OT Network | Low | Minimal | None | HIGH |

---

## Attack Path Analysis

### Primary Attack Paths

**Path 1: Web Application → System Compromise**
```
External Access → HMI Web Interface → SQL Injection → Admin Access →
File Upload → Web Shell → System Shell → Network Pivot
```

**Path 2: Modbus Protocol Exploitation**
```
External Access → Modbus Port 502 → Direct PLC Access →
Process Manipulation → Flag Extraction
```

**Path 3: Lateral Movement**
```
Initial Compromise → Credential Harvesting → SSH/RDP →
Domain Admin → Full Network Control
```

### Attack Scenario Matrix

| Scenario | Entry Point | Technique | Target | Success Rate | Impact |
|:---|:---|:---|:---|:---|:---|
| Quick Win | HMI Web App | SQL Injection | Database | High | Medium |
| Process Control | Modbus Port | Protocol Abuse | PLC | High | Critical |
| Network Takeover | Initial Shell | Lateral Movement | Domain | Medium | Critical |

### Recommended Attack Sequence

1. **Phase 1:** Web application exploitation (SQL injection)
2. **Phase 2:** File upload and shell establishment
3. **Phase 3:** Local privilege escalation
4. **Phase 4:** Network reconnaissance and lateral movement
5. **Phase 5:** Industrial system manipulation
6. **Phase 6:** Flag collection and evidence gathering

---

## Credential Harvesting Log

### Discovered Credentials

| Username | Password | Source | System | Access Level | Verified | Notes |
|:---|:---|:---|:---|:---|:---|:---|
| admin | admin | Default | HMI Web | Unknown | No | Common default |
| root | toor | Guess | SSH | Unknown | No | Reverse default |
| | | | | | | |

### Hash Dumps

| System | Hash Type | Username | Hash | Cracked | Method |
|:---|:---|:---|:---|:---|:---|
| | | | | | |

### Password Patterns

- **Common Patterns:** [Pattern analysis]
- **Dictionary Hits:** [Successful dictionary attacks]
- **Complexity:** [Password strength assessment]

---

## Evidence & Flag Tracking

### Flags Discovered

| Flag ID | Flag Value | System | Location | Discovery Method | Timestamp |
|:---|:---|:---|:---|:---|:---|
| FLAG1 | THM{XXXX} | HMI | /var/www/flag1.txt | File exploration | [TIME] |
| | | | | | |

### Evidence Collected

| Evidence Type | Description | System | Location | Preservation Method |
|:---|:---|:---|:---|:---|
| Screenshot | Login page | HMI | /login.php | PNG file |
| Packet Capture | Modbus traffic | Network | Port 502 | PCAP file |
| Configuration | Apache config | HMI | /etc/apache2/ | Text file |

### Digital Forensics

| Artifact | Hash (MD5) | Size | Description | Chain of Custody |
|:---|:---|:---|:---|:---|
| capture.pcap | ABC123... | 2.1MB | Network traffic | Collected at [TIME] |
| webshell.php | DEF456... | 1.2KB | Uploaded web shell | Created at [TIME] |

---

## Operational Timeline

### Discovery Phase
- **[TIME]** - Initial network scan initiated
- **[TIME]** - Primary HMI discovered (10.10.141.23)
- **[TIME]** - Modbus service identified
- **[TIME]** - Web application analysis started

### Exploitation Phase
- **[TIME]** - SQL injection attempt #1
- **[TIME]** - File upload vulnerability confirmed
- **[TIME]** - Web shell deployed
- **[TIME]** - System shell established

### Post-Exploitation Phase
- **[TIME]** - Local privilege escalation
- **[TIME]** - Network reconnaissance
- **[TIME]** - Lateral movement attempt
- **[TIME]** - Additional systems compromised

### Objectives Completed
- **[TIME]** - Flag 1 recovered
- **[TIME]** - Flag 2 recovered
- **[TIME]** - Flag 3 recovered
- **[TIME]** - Mission completion

---

## Operational Notes

### Team Communications
- **Slack Channel:** #virelia-ops
- **Status Updates:** Every 30 minutes
- **Critical Findings:** Immediate notification required

### Documentation Standards
- **Screenshots:** PNG format, annotated
- **Commands:** Full command line with context
- **Timestamps:** UTC format (YYYY-MM-DD HH:MM:SS)
- **Evidence:** Cryptographic hashes for integrity

### Risk Mitigation
- **Avoid Process Disruption:** Do not interfere with water treatment
- **Stealth Operations:** Minimize detection footprint
- **Data Protection:** Secure handling of sensitive information

---

## Next Steps & Action Items

### Immediate Priorities
1. **Complete network discovery** - Scan remaining IP ranges
2. **Exploit HMI web application** - SQL injection and file upload
3. **Enumerate Modbus devices** - Map all industrial controllers
4. **Establish persistent access** - Deploy backdoors and maintain shells

### Secondary Objectives
1. **Lateral movement** - Compromise additional systems
2. **Privilege escalation** - Gain administrative access
3. **Data exfiltration** - Collect sensitive information
4. **Process manipulation** - Demonstrate control capabilities

### Long-term Goals
1. **Complete network mapping** - Document all systems and services
2. **Vulnerability assessment** - Identify all security weaknesses
3. **Attack path documentation** - Map all possible exploitation routes
4. **Remediation recommendations** - Provide security improvement suggestions

---

**⚠️ OPERATIONAL SECURITY REMINDER ⚠️**

This document contains sensitive operational intelligence. Ensure proper handling:
- Encrypt at rest and in transit
- Limit access to authorized personnel only
- Update in real-time with accurate information
- Maintain operational security at all times

**Stay vigilant. Stay methodical. Stay successful.**

---
*End of Network & Asset Intelligence Map v2.0*