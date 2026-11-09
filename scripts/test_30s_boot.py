"""Test boot with longer observation window to observe SignOn request."""
import os
import sys
import time
import subprocess
import threading
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from marathon_server import main as run_server

GAME_DIR = Path("D:/Marathon-live")
GAME_EXE = GAME_DIR / "Marathon.exe"
PROXY_LOG = GAME_DIR / "marathon_proxy.log"

def main():
    print("[*] Starting marathon_server thread...")
    t = threading.Thread(target=run_server, daemon=True)
    t.start()
    time.sleep(1)

    print(f"[*] Launching {GAME_EXE} for 30s observation...")
    proc = subprocess.Popen(
        [str(GAME_EXE)],
        cwd=str(GAME_DIR),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )
    print(f"[+] Marathon.exe PID: {proc.pid}")

    for sec in range(1, 31):
        time.sleep(1)
        ret = proc.poll()
        if ret is not None:
            print(f"[!] Process exited at t+{sec}s with exit code {ret}")
            break
        if sec % 5 == 0:
            print(f"[*] [t+{sec}s] Process alive, proxy log size: {PROXY_LOG.stat().st_size if PROXY_LOG.exists() else 0} bytes")

    if proc.poll() is None:
        print("[*] Terminating process after 30s test...")
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()

    print("\n--- PROXY LOG ---")
    if PROXY_LOG.exists():
        print(PROXY_LOG.read_text(encoding="utf-8", errors="ignore"))

if __name__ == "__main__":
    main()
