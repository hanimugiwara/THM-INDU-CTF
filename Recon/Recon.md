# Reconnaissance Field Manual

**Authored by: Hex**

Team,

Before we attack, we map. Information is our most valuable weapon. This manual is a cheat sheet for the primary recon tools and commands we will use to probe the "Industrial Intrusion" network.

Execute these scans systematically. Log all findings in our `Network_Map.md`. Don't just run the commands—understand what they do.

---

## Active Scanning (Nmap)

Nmap is our primary tool for network discovery and security auditing.

### Initial Network Sweep

First, we identify which hosts are online. A simple ping scan is fast and avoids triggering more sensitive intrusion detection systems.

*   **Command:**
    ```bash
    nmap -sn 10.10.X.X/24
    ```
*   **Purpose:** The `-sn` flag tells Nmap to perform a "ping scan" - it disables port scanning. It's used to quickly find live hosts on the target subnet.

### Comprehensive Port & Service Scan

Once we have a list of live IPs, we perform a deep dive on each one to identify open ports, running services, and their versions. This scan is noisy but provides maximum information.

*   **Command:**
    ```bash
    nmap -sV -sC -p- -oN nmap_full.txt [TARGET_IP]
    ```
*   **Breakdown:**
    *   `-sV`: Probes open ports to determine service/version info. Crucial for finding vulnerable software.
    *   `-sC`: Runs a set of default, safe Nmap Scripting Engine (NSE) scripts. Often finds misconfigurations.
    *   `-p-`: Scans all 65,535 TCP ports, not just the top 1000. Essential for finding services on non-standard ports.
    *   `-oN`: Saves the output in a normal format to a text file for later review.

### Targeted ICS Scans

Nmap has specialized NSE scripts for industrial protocols. These are invaluable for identifying and fingerprinting ICS devices like PLCs.

*   **Modbus Discovery (Port 502):**
    ```bash
    nmap --script modbus-discover -p 502 [TARGET_IP]
    ```
    *   This script attempts to query the Modbus device to get its Unit ID and other basic information.

*   **Siemens S7 Discovery (Port 102):**
    ```bash
    nmap --script s7-info -p 102 [TARGET_IP]
    ```
    *   This script enumerates details from Siemens S7 PLCs, such as hardware model, firmware version, and plant identification data.

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