import subprocess
import time
from pathlib import Path

GAME_DIR = Path("D:/Marathon-live")
GAME_EXE = GAME_DIR / "Marathon.exe"
PROXY_LOG = GAME_DIR / "marathon_proxy.log"

print(f"[*] Launching {GAME_EXE} to verify startup...")
proc = subprocess.Popen([str(GAME_EXE)], cwd=str(GAME_DIR))
print(f"[+] Marathon.exe launched with PID {proc.pid}")

crashed = False
for sec in range(1, 16):
    time.sleep(1)
    ret = proc.poll()
    if ret is not None:
        print(f"[!] Marathon.exe exited/crashed at t+{sec}s with code: 0x{ret & 0xFFFFFFFF:08X}")
        crashed = True
        break
    if PROXY_LOG.exists():
        size = PROXY_LOG.stat().st_size
        print(f"[*] [t+{sec}s] Alive and healthy! Log size: {size} bytes")

if not crashed:
    print("[+] SUCCESS: Marathon.exe is stably running past the loading screen!")
    print("[*] Stopping test process...")
    proc.terminate()
    try:
        proc.wait(timeout=3)
    except Exception:
        proc.kill()
    print("[+] Test completed cleanly.")
