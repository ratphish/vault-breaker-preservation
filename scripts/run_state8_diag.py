import os
import sys
import time
import subprocess
import ctypes
from pathlib import Path

GAME_DIR = Path("D:/Marathon-live")
GAME_EXE = GAME_DIR / "Marathon.exe"
PROXY_LOG = GAME_DIR / "marathon_proxy.log"

user32 = ctypes.windll.user32
EnumWindows = user32.EnumWindows
EnumWindowsProc = ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_void_p, ctypes.c_void_p)
GetWindowThreadProcessId = user32.GetWindowThreadProcessId
SetForegroundWindow = user32.SetForegroundWindow
SetActiveWindow = user32.SetActiveWindow
AttachThreadInput = user32.AttachThreadInput
PostMessageW = user32.PostMessageW
SendMessageW = user32.SendMessageW
keybd_event = user32.keybd_event
kernel32 = ctypes.windll.kernel32
GetCurrentThreadId = kernel32.GetCurrentThreadId

VK_RETURN = 0x0D
VK_SPACE = 0x20
WM_KEYDOWN = 0x0100
WM_KEYUP = 0x0101
WM_CHAR = 0x0102

def send_enter_key(target_pid: int):
    hwnds = []
    def enum_cb(hwnd, extra):
        pid = ctypes.c_ulong()
        GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
        if pid.value == target_pid:
            hwnds.append(hwnd)
        return True
    EnumWindows(EnumWindowsProc(enum_cb), 0)
    
    cur_tid = GetCurrentThreadId()
    for hwnd in hwnds:
        title = ctypes.create_unicode_buffer(256)
        cls = ctypes.create_unicode_buffer(256)
        user32.GetWindowTextW(hwnd, title, 256)
        user32.GetClassNameW(hwnd, cls, 256)
        w_pid = ctypes.c_ulong()
        w_tid = GetWindowThreadProcessId(hwnd, ctypes.byref(w_pid))
        
        # Attach thread input to reliably set focus
        AttachThreadInput(cur_tid, w_tid, True)
        try:
            SetForegroundWindow(hwnd)
            SetActiveWindow(hwnd)
        except Exception:
            pass
        
        # Direct PostMessage to window (handles Tiger Input Window and Tiger D3D Window)
        PostMessageW(hwnd, WM_KEYDOWN, VK_RETURN, 0x001C0001)
        PostMessageW(hwnd, WM_CHAR, VK_RETURN, 0x001C0001)
        PostMessageW(hwnd, WM_KEYUP, VK_RETURN, 0xC01C0001)
        PostMessageW(hwnd, WM_KEYDOWN, VK_SPACE, 0x00390001)
        PostMessageW(hwnd, WM_CHAR, VK_SPACE, 0x00390001)
        PostMessageW(hwnd, WM_KEYUP, VK_SPACE, 0xC0390001)
        AttachThreadInput(cur_tid, w_tid, False)

    # Also global keybd_event as fallback
    keybd_event(VK_RETURN, 0x1C, 0, 0)
    time.sleep(0.05)
    keybd_event(VK_RETURN, 0x1C, 2, 0)
    time.sleep(0.05)
    keybd_event(VK_SPACE, 0x39, 0, 0)
    time.sleep(0.05)
    keybd_event(VK_SPACE, 0x39, 2, 0)

def main():
    print(f"[*] Starting controlled diagnostic run of {GAME_EXE}...")
    
    if PROXY_LOG.exists():
        try:
            with open(PROXY_LOG, "w") as f:
                f.truncate(0)
        except Exception as e:
            print(f"[-] Could not truncate log: {e}")

    lmdetail_path = Path(os.path.expandvars(r"%LOCALAPPDATA%\Temp\Marathon\lmdetail.json"))
    if lmdetail_path.exists():
        try:
            lmdetail_path.unlink()
            print("[+] Removed stale lmdetail.json")
        except Exception as e:
            print(f"[-] Could not unlink lmdetail.json: {e}")

    proc = subprocess.Popen(
        [str(GAME_EXE)],
        cwd=str(GAME_DIR),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )
    print(f"[+] Marathon.exe launched with PID: {proc.pid}")

    last_state = None
    state3_pressed = 0

    for sec in range(1, 121):
        time.sleep(1)
        ret = proc.poll()
        if ret is not None:
            print(f"[!] Marathon.exe exited early at {sec}s with exit code {ret}")
            break

        # Read lmdetail.json
        cur_state = None
        tasks = None
        dur = None
        if lmdetail_path.exists():
            try:
                with open(lmdetail_path, "r") as f:
                    data = f.read().strip()
                if data.startswith("{"):
                    import json
                    j = json.loads(data)
                    cur_state = str(j.get("state"))
                    tasks = j.get("tasks")
                    dur = j.get("state_duration")
                    if cur_state != last_state:
                        print(f"\n[+] [t+{sec:02d}s] STATE TRANSITION -> State {cur_state} (dur={dur}ms, tasks={tasks})")
                        last_state = cur_state
                    elif sec % 5 == 0 or cur_state == "8":
                        print(f"[*] [t+{sec:02d}s] State: {cur_state} (dur={dur}ms, tasks={tasks})")
            except Exception:
                pass

        # If State 3 (Title Screen / Press Enter), send Enter/Space
        if cur_state == "3" or (cur_state is None and sec >= 25):
            print(f"[*] [t+{sec:02d}s] State 3 active -> sending simulated ENTER & SPACE...")
            send_enter_key(proc.pid)
            state3_pressed += 1

        if sec % 15 == 0:
            sz = PROXY_LOG.stat().st_size if PROXY_LOG.exists() else 0
            print(f"[*] [t+{sec:02d}s] Status check (proxy log: {sz} bytes)")

    if proc.poll() is None:
        print("[*] Terminating Marathon.exe after diagnostic window...")
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()

    print("[+] Diagnostic run complete.")

if __name__ == "__main__":
    main()
