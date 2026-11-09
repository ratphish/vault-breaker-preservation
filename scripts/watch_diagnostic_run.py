"""Monitor and analyze live Marathon execution when launched interactively."""
import os
import sys
import time
import hashlib
from pathlib import Path

GAME_DIR = Path("D:/Marathon-live")
PROXY_LOG = GAME_DIR / "marathon_proxy.log"
RAW_PAYLOAD_BIN = GAME_DIR / "pDataToInclude_raw.bin"

def main():
    print("=" * 70)
    print("  WATCHING MARATHON DIAGNOSTIC EXECUTION (PROTOCAL APP TICKET)")
    print("  Waiting for player SignOn ('Press Enter' at Title Screen)...")
    print("=" * 70)

    # Note the starting offset of proxy log
    start_offset = 0
    if PROXY_LOG.exists():
        start_offset = PROXY_LOG.stat().st_size

    ticket_requested = False
    ticket_retrieved = False
    shutdown_detected = False

    while True:
        time.sleep(0.5)
        if not PROXY_LOG.exists():
            continue

        try:
            with open(PROXY_LOG, "r", encoding="utf-8", errors="ignore") as f:
                f.seek(start_offset)
                new_text = f.read()
        except Exception:
            continue

        if not ticket_requested and "RequestEncryptedAppTicket called" in new_text:
            ticket_requested = True
            print("\n[+] [EVENT] RequestEncryptedAppTicket DETECTED!")

        if not ticket_retrieved and "Generated valid EncryptedAppTicket Protobuf" in new_text:
            ticket_retrieved = True
            print("[+] [EVENT] Valid EncryptedAppTicket Protobuf delivered to client!")

        if "[Egress]" in new_text or "[TCP]" in new_text or "[DNS]" in new_text or "[WinHTTP]" in new_text:
            for line in new_text.splitlines():
                if any(tag in line for tag in ["[Egress]", "[TCP]", "[DNS]", "[WinHTTP]"]):
                    print(f"[*] [NETWORK] {line}")

        if "SteamAPI_Shutdown called" in new_text:
            print("\n[+] [EVENT] SteamAPI_Shutdown DETECTED!")
            shutdown_detected = True
            time.sleep(2)
            break

    print("\n" + "=" * 70)
    print("  EXECUTION COMPLETE - NEW LOG SUMMARY")
    print("=" * 70)
    with open(PROXY_LOG, "r", encoding="utf-8", errors="ignore") as f:
        f.seek(start_offset)
        full_new = f.read()

    for line in full_new.splitlines():
        if any(k in line for k in ["SteamUser", "SteamAPI_Shutdown", "Protobuf", "Crypto", "CertVerify", "Egress", "TCP", "DNS"]):
            print(line)

if __name__ == "__main__":
    main()
