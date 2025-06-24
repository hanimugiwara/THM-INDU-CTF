# CTF Toolkit Reference

**Authored by: Hex**

Team,

This isn't a manual; it's a speed dial for our most critical tools. When you identify a target or a vulnerability, this table gives you the command you need, right now. No hesitation.

Reference this to stay fast and efficient.

---

| Tool | Purpose | Go-To Command Example |
| :--- | :--- | :--- |
| **Nmap** | Network/Port Scanning | `nmap -sV -sC -p- <IP>` |
| **Gobuster** | Web Directory/File Brute-Force | `gobuster dir -u http://<IP> -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,txt` |
| **Wireshark** | Network Protocol Analysis | `(GUI) - Display Filter: modbus` |
| **Metasploit** | Exploitation Framework | `msfconsole -q -x "search type:exploit platform:windows smb; use 0; show options"` |
| **Burp Suite** | Web App Proxy & Analysis | `(GUI) - Intercept requests to analyze/modify` |
| **modbus-cli** | Direct Modbus Interaction | `modbus-cli --host <IP> read-holding-registers 0 10` |
| **netcat** | Network "Swiss Army Knife" | `nc -lvnp 4444` (To set up a listener) |
| **John the Ripper** | Password Cracking | `john --wordlist=/path/to/rockyou.txt hashes.txt` |
| **Hashcat** | Advanced GPU Password Cracking | `hashcat -m 0 -a 0 hashes.txt /path/to/rockyou.txt` |