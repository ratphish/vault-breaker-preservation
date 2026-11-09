"""Diagnostic test harness for Marathon Post-Ticket State Machine & Thread Analysis."""
import os
import sys
import time
import subprocess
import hashlib
import ctypes
from pathlib import Path

GAME_DIR = Path("D:/Marathon-live")
GAME_EXE = GAME_DIR / "Marathon.exe"
PROXY_LOG = GAME_DIR / "marathon_proxy.log"
RAW_PAYLOAD_BIN = GAME_DIR / "pDataToInclude_raw.bin"
PREV_HASH_FILE = GAME_DIR / "pDataToInclude_prev_hash.txt"

user32 = ctypes.windll.user32
EnumWindows = user32.EnumWindows
EnumWindowsProc = ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_void_p, ctypes.c_void_p)
GetWindowThreadProcessId = user32.GetWindowThreadProcessId
SetForegroundWindow = user32.SetForegroundWindow
keybd_event = user32.keybd_event
VK_RETURN = 0x0D

def get_file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest().upper()

def find_marathon_windows(target_pid: int):
    hwnds = []
    def enum_cb(hwnd, extra):
        pid = ctypes.c_ulong()
        GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
        if pid.value == target_pid:
            hwnds.append(hwnd)
        return True
    EnumWindows(EnumWindowsProc(enum_cb), 0)
    return hwnds

def send_enter_key(hwnd=None):
    if hwnd:
        try:
            SetForegroundWindow(hwnd)
        except Exception:
            pass
    keybd_event(VK_RETURN, 0, 0, 0)
    time.sleep(0.05)
    keybd_event(VK_RETURN, 0, 2, 0)

def main():
    print("=" * 70)
    print("  MARATHON POST-TICKET STATE MACHINE & THREAD TRACE HARNESS")
    print("=" * 70)

    proxy_dll = GAME_DIR / "steam_api64.dll"
    if not proxy_dll.exists():
        print("[-] Missing proxy DLL in game dir!")
        sys.exit(1)

    proxy_hash = get_file_sha256(proxy_dll)
    print(f"[*] Active steam_api64.dll SHA-256: {proxy_hash}")

    # Clean existing logs and raw payload bin
    if RAW_PAYLOAD_BIN.exists():
        try:
            RAW_PAYLOAD_BIN.unlink()
        except Exception:
            pass
    if PROXY_LOG.exists():
        try:
            PROXY_LOG.unlink()
        except Exception:
            pass

    print(f"[*] Launching {GAME_EXE}...")
    start_time = time.time()
    proc = subprocess.Popen(
        [str(GAME_EXE)],
        cwd=str(GAME_DIR),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )
    print(f"[+] Marathon.exe launched with PID: {proc.pid}")

    shutdown_seen = False
    ticket_seen = False
    snapshots_seen = 0

    max_seconds = 80
    for sec in range(1, max_seconds + 1):
        time.sleep(1)
        elapsed = time.time() - start_time
        ret = proc.poll()
        if ret is not None:
            print(f"[!] Marathon.exe exited early at t+{sec}s with code: 0x{ret & 0xFFFFFFFF:08X}")
            break

        if PROXY_LOG.exists():
            log_size = PROXY_LOG.stat().st_size
            try:
                log_text = PROXY_LOG.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                log_text = ""

            if not ticket_seen:
                if "RequestEncryptedAppTicket called" in log_text:
                    ticket_seen = True
                    print(f"\n[+] [t+{sec}s] Encrypted App Ticket requested! Monitoring thread snapshots...\n")
                elif sec >= 15:
                    # After 15 seconds, title screen is loading / ready. Send Enter to trigger sign-on
                    hwnds = find_marathon_windows(proc.pid)
                    main_hwnd = hwnds[0] if hwnds else None
                    send_enter_key(main_hwnd)
                    if sec % 3 == 0:
                        print(f"[*] [t+{sec}s] Title screen active (log: {log_size} B, windows: {len(hwnds)}). Sent Enter to trigger SignOn...")
                elif sec % 5 == 0:
                    print(f"[*] [t+{sec}s] Booting packages... (log: {log_size} B)")

            if ticket_seen:
                current_snapshots = log_text.count("[THREAD-SNAPSHOT")
                if current_snapshots > snapshots_seen:
                    # Print newly captured snapshot lines
                    new_lines = [l for l in log_text.splitlines() if "[THREAD-SNAPSHOT" in l or "TID" in l and "RIP" in l]
                    print(f"[*] [t+{sec}s] Captured thread snapshot update (snapshot count: {current_snapshots})")
                    snapshots_seen = current_snapshots

                if "SteamAPI_Shutdown called" in log_text:
                    print(f"\n[+] [t+{sec}s] SteamAPI_Shutdown detected! STINGRAY transition reached.\n")
                    shutdown_seen = True
                    time.sleep(3)
                    break

    print(f"[*] Stopping Marathon.exe (PID {proc.pid})...")
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()
    print("[+] Marathon.exe process terminated.")

    print("\n" + "=" * 70)
    print("  POST-RUN DIAGNOSTIC TELEMETRY ANALYSIS")
    print("=" * 70)

    if RAW_PAYLOAD_BIN.exists():
        raw_bytes = RAW_PAYLOAD_BIN.read_bytes()
        sha = hashlib.sha256(raw_bytes).hexdigest()
        print(f"[+] pDataToInclude captured: {len(raw_bytes)} bytes")
        print(f"[+] SHA-256 fingerprint: {sha}")
        print(f"[+] Hex dump: {raw_bytes.hex()}")
    else:
        print("[-] pDataToInclude_raw.bin was not written.")

    if PROXY_LOG.exists():
        log_text = PROXY_LOG.read_text(encoding="utf-8", errors="ignore")
        lines = log_text.splitlines()
        print(f"[+] Total proxy log lines: {len(lines)}")
        
        # Print all Thread-Snapshot lines
        snapshot_lines = [l for l in lines if "[THREAD-SNAPSHOT" in l or "TID" in l and "RIP" in l]
        print(f"\n--- Thread Snapshot Log Entries ({len(snapshot_lines)} lines) ---")
        for sl in snapshot_lines:
            print(sl)

        # Print all VTable-Stub lines
        stub_lines = [l for l in lines if "[VTABLE-STUB]" in l or "ISteam" in l and "STUB" in l]
        print(f"\n--- VTable Stub Invocations ({len(stub_lines)} lines) ---")
        for stl in stub_lines:
            print(stl)
    else:
        print("[-] marathon_proxy.log not found.")

if __name__ == "__main__":
    main()
