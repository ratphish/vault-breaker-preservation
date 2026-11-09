"""Controlled live execution test harness for Option 1 (Marathon-live).

Starts marathon_server in background, launches Marathon.exe from D:\Marathon-live,
collects proxy and server logs for 12 seconds, then terminates the game process.
"""
import os
import sys
import time
import subprocess
import threading
from pathlib import Path

# Add scripts directory to path
sys.path.insert(0, str(Path(__file__).parent))
from marathon_server import main as run_server

GAME_DIR = Path("D:/Marathon-live")
GAME_EXE = GAME_DIR / "Marathon.exe"
PROXY_LOG = GAME_DIR / "marathon_proxy.log"

def start_server_thread():
    t = threading.Thread(target=run_server, daemon=True)
    t.start()
    time.sleep(1) # Allow server to bind ports

def main():
    print("[*] Starting marathon_server in background...")
    start_server_thread()
    
    # Clean previous proxy log if present
    if PROXY_LOG.exists():
        try:
            PROXY_LOG.unlink()
        except Exception:
            pass

    print(f"[*] Launching {GAME_EXE}...")
    proc = subprocess.Popen(
        [str(GAME_EXE)],
        cwd=str(GAME_DIR),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )
    print(f"[+] Marathon.exe launched with PID: {proc.pid}")

    print("[*] Monitoring execution telemetry for 12 seconds...")
    for sec in range(1, 13):
        time.sleep(1)
        ret = proc.poll()
        if ret is not None:
            print(f"[!] Process exited early at {sec}s with code: {ret}")
            break
        if PROXY_LOG.exists() and PROXY_LOG.stat().st_size > 0:
            print(f"[*] [t+{sec}s] Telemetry active (log size: {PROXY_LOG.stat().st_size} bytes)")

    # Terminate process cleanly if still running
    if proc.poll() is None:
        print("[*] Gracefully stopping Marathon.exe...")
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()
        print("[+] Process stopped.")

    print("\n" + "=" * 60)
    print("  MARATHON PROXY TELEMETRY LOG")
    print("=" * 60)
    if PROXY_LOG.exists():
        content = PROXY_LOG.read_text(encoding="utf-8", errors="ignore")
        print(content if content.strip() else "[Log file exists but is empty]")
    else:
        print("[-] marathon_proxy.log was not created.")

if __name__ == "__main__":
    main()
