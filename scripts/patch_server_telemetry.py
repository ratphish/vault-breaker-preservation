import re
import time

with open(r'D:\vault-breaker-preservation\scripts\marathon_server.py', 'r', encoding='utf-8') as f:
    content = f.read()

target = """        status, payload = self.server_instance.handle_signon_request(body)
        
        self.send_response(status)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(payload)
        self.wfile.flush()
        server_log(f"[HTTPS POST] Dispatched SignOn Protobuf response ({len(payload)} bytes) -> Status {status}")"""

replacement = """        # Handle Bungie Frontdoor Anonymous Events / Telemetry
        if "anon/events" in self.path or "analytics" in self.path:
            ts = int(time.time())
            dump_fn = f"telemetry_{ts}_{client_port}.bin"
            try:
                with open(dump_fn, "wb") as f_dump:
                    f_dump.write(body)
                ascii_strings = [s for s in body.decode("latin1", errors="ignore").split("\\x00") if len(s) > 4 and any(c.isalnum() for c in s)]
                server_log(f"[Telemetry] Saved {len(body)} bytes to {dump_fn}. Preview: {ascii_strings[:5]}")
            except Exception as e:
                server_log(f"[-] Telemetry dump error: {e}")

            resp = b'{"result":"ok"}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(resp)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(resp)
            self.wfile.flush()
            server_log(f"[Telemetry] Dispatched 200 OK to {self.path}")
            return

        status, payload = self.server_instance.handle_signon_request(body)
        
        self.send_response(status)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(payload)
        self.wfile.flush()
        server_log(f"[HTTPS POST] Dispatched SignOn Protobuf response ({len(payload)} bytes) -> Status {status}")"""

assert target in content, "Target pattern not found in marathon_server.py"
content = content.replace(target, replacement, 1)
with open(r'D:\vault-breaker-preservation\scripts\marathon_server.py', 'w', encoding='utf-8') as f:
    f.write(content)
print("Successfully patched marathon_server.py with telemetry handler!")
