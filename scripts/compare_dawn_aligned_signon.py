import sys
sys.path.insert(0, r"D:\Marathon-preservation\tools\python")
sys.path.insert(0, "scripts")

import json
from pathlib import Path
from probe_dawn_signon_writer import run_writer, describe
from marathon_server import MarathonServer
from marathon_protobuf import ProtobufReader

dawn_dll = Path("D:/Dawnv0.1.5.2/payload/steam_api64.dll")
dawn_payload = run_writer(dawn_dll, config_key=False)

server = MarathonServer()
status, emulator_payload = server.handle_signon_request(b"\x00" * 100)

print("=" * 60)
print(f"Dawn 0.1.5.2 baseline payload size: {len(dawn_payload)} bytes")
print(f"Emulator current payload size:     {len(emulator_payload)} bytes")
print("=" * 60)

dawn_desc = describe(dawn_payload)
emul_desc = describe(emulator_payload)

print("\n--- Dawn Decoded Message Schema ---")
print(json.dumps(dawn_desc, indent=2))

print("\n--- Emulator Decoded Message Schema ---")
print(json.dumps(emul_desc, indent=2))

# Verify schema matching (field tags and wire types)
def extract_schema(desc):
    schema = []
    for item in desc:
        fnum, wire, val = item
        if isinstance(val, list):
            schema.append((fnum, wire, extract_schema(val)))
        else:
            schema.append((fnum, wire))
    return schema

dawn_schema = extract_schema(dawn_desc)
emul_schema = extract_schema(emul_desc)

print("\n--- Schema Structure Comparison ---")
if dawn_schema == emul_schema:
    print("[+] SUCCESS: Protobuf field structure EXACTLY MATCHES Dawn 0.1.5.2 baseline!")
else:
    print("[-] MISMATCH in schema:")
    print("Dawn:", dawn_schema)
    print("Emul:", emul_schema)
