# Operation Virelia: Network & Asset Map

**Authored by: Hex**

Team,

This document is our live map of the target network for the "Industrial Intrusion" CTF. This is a living document. **Update it in real-time as new assets are discovered. Accuracy is critical.**

Every host, every open port, every piece of banner information is a potential foothold. Log everything. We will use this map to plan our lateral movements and pinpoint high-value targets, like the Engineering Workstation (EWS) or the PLC controlling the primary process.

---

## Known IP Ranges

*   **Target Subnet:** `10.10.X.X/24` (TBC - Confirm range from THM room details)
*   **Our Attack IP:** `[YOUR_TRYHACKME_IP]`

---

## Discovered Hosts & Services

<!-- 
COPY THE TEMPLATE BELOW FOR EACH NEW HOST
-------------------------------------------------
### Host: [IP_ADDRESS_HERE]
- **Status:** Online
- **Hostname:**
- **Open Ports & Services:**
| Port | Service | Version | Banner/Notes |
| :--- | :--- | :--- |:--- |
|      |        |         |              |
|      |        |         |              |
- **Identified Vulnerabilities:**
  - 
- **Notes & Strategy:**

-------------------------------------------------
-->

### Host: 10.10.141.23 (EXAMPLE)
- **Status:** Online, Pivotal
- **Hostname:** `hmi.virelia.water` (Discovered via port 80 title)
- **Open Ports & Services:**
| Port | Service | Version | Banner/Notes |
| :--- | :--- | :--- |:--- |
| 80 | http | Apache 2.4.29 | "Virelia Water Control HMI" |
| 443 | https | Apache 2.4.29 | (Self-signed cert) |
| 502 | modbus | | Unit ID 1 Found via nmap script. Looks like a PLC. |
- **Identified Vulnerabilities:**
  - Login page (`/login.php`) may be vulnerable to SQLi.
  - Modbus port is open to the network without authentication.
- **Notes & Strategy:**
  This appears to be the primary HMI and our initial point of entry. The web server is our first target. Let's try SQLi bypass on the login form. If we get access, we'll look for admin panels or file upload features. The Modbus port is our secondary target; if we can get a shell on this box, we can interact with the PLC directly. Possible flag location in the HMI's database or by manipulating the PLC.

### Host: [IP_ADDRESS_HERE]
- **Status:** 
- **Hostname:** 
- **Open Ports & Services:**
| Port | Service | Version | Banner/Notes |
| :--- | :--- | :--- |:--- |
|      |        |         |              |
|      |        |         |              |
- **Identified Vulnerabilities:**
  - 
- **Notes & Strategy:**