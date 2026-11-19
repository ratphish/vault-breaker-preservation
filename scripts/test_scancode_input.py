import os
import sys
import time
import subprocess
import ctypes
from ctypes import wintypes
from pathlib import Path

GAME_DIR = Path("D:/Marathon-live")
GAME_EXE = GAME_DIR / "Marathon.exe"
lmdetail_path = Path(os.path.expandvars(r"%LOCALAPPDATA%\Temp\Marathon\lmdetail.json"))

user32 = ctypes.windll.user32

KEYEVENTF_SCANCODE = 0x0008
KEYEVENTF_KEYUP = 0x0002
INPUT_KEYBOARD = 1
INPUT_MOUSE = 0
MOUSEEVENTF_LEFTDOWN = 0x0002
MOUSEEVENTF_LEFTUP = 0x0004

class KEYBDINPUT(ctypes.Structure):
    _fields_ = [
        ("wVk", wintypes.WORD),
        ("wScan", wintypes.WORD),
        ("dwFlags", wintypes.DWORD),
        ("time", wintypes.DWORD),
        ("dwExtraInfo", ctypes.c_size_t),
    ]

class MOUSEINPUT(ctypes.Structure):
    _fields_ = [
        ("dx", wintypes.LONG),
        ("dy", wintypes.LONG),
        ("mouseData", wintypes.DWORD),
        ("dwFlags", wintypes.DWORD),
        ("time", wintypes.DWORD),
        ("dwExtraInfo", ctypes.c_size_t),
    ]

class INPUT_UNION(ctypes.Union):
    _fields_ = [("ki", KEYBDINPUT), ("mi", MOUSEINPUT)]

class INPUT(ctypes.Structure):
    _anonymous_ = ("_u",)
    _fields_ = [
        ("type", wintypes.DWORD),
        ("_u", INPUT_UNION),
    ]

def send_scancode_key(scan_code):
    # Key down
    inp_down = INPUT()
    inp_down.type = INPUT_KEYBOARD
    inp_down.ki.wVk = 0
    inp_down.ki.wScan = scan_code
    inp_down.ki.dwFlags = KEYEVENTF_SCANCODE
    inp_down.ki.time = 0
    inp_down.ki.dwExtraInfo = 0
    
    # Key up
    inp_up = INPUT()
    inp_up.type = INPUT_KEYBOARD
    inp_up.ki.wVk = 0
    inp_up.ki.wScan = scan_code
    inp_up.ki.dwFlags = KEYEVENTF_SCANCODE | KEYEVENTF_KEYUP
    inp_up.ki.time = 0
    inp_up.ki.dwExtraInfo = 0

    user32.SendInput(1, ctypes.byref(inp_down), ctypes.sizeof(INPUT))
    time.sleep(0.05)
    user32.SendInput(1, ctypes.byref(inp_up), ctypes.sizeof(INPUT))

def send_mouse_click():
    inp_down = INPUT()
    inp_down.type = INPUT_MOUSE
    inp_down.mi.dwFlags = MOUSEEVENTF_LEFTDOWN
    inp_up = INPUT()
    inp_up.type = INPUT_MOUSE
    inp_up.mi.dwFlags = MOUSEEVENTF_LEFTUP

    user32.SendInput(1, ctypes.byref(inp_down), ctypes.sizeof(INPUT))
    time.sleep(0.05)
    user32.SendInput(1, ctypes.byref(inp_up), ctypes.sizeof(INPUT))

def focus_marathon(pid):
    hwnds = []
    def cb(hwnd, extra):
        p = ctypes.c_ulong()
        user32.GetWindowThreadProcessId(hwnd, ctypes.byref(p))
        if p.value == pid:
            cls = ctypes.create_unicode_buffer(256)
            user32.GetClassNameW(hwnd, cls, 256)
            if "Tiger D3D" in cls.value:
                hwnds.append(hwnd)
        return True
    user32.EnumWindows(ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_void_p, ctypes.c_void_p)(cb), 0)
    if hwnds:
        hwnd = hwnds[0]
        user32.AllowSetForegroundWindow(pid)
        user32.LockSetForegroundWindow(2) # LSFW_UNLOCK
        user32.ShowWindow(hwnd, 9)        # SW_RESTORE
        user32.SetForegroundWindow(hwnd)
        user32.BringWindowToTop(hwnd)
        user32.SetActiveWindow(hwnd)
        return hwnd
    return None

def main():
    if lmdetail_path.exists():
        try:
            lmdetail_path.unlink()
        except Exception:
            pass

    print("[*] Launching Marathon.exe for DirectInput scancode test...")
    proc = subprocess.Popen([str(GAME_EXE)], cwd=str(GAME_DIR))
    print(f"[+] Marathon.exe PID: {proc.pid}")

    last_state = None
    try:
        for sec in range(1, 85):
            time.sleep(1)
            if proc.poll() is not None:
                print(f"[!] Exited early at {sec}s with code {proc.poll()}")
                break

            cur_state = None
            tasks = None
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
                            print(f"[+] [t+{sec:02d}s] STATE TRANSITION -> State {cur_state} (dur={dur}ms, tasks={tasks})")
                            last_state = cur_state
                except Exception:
                    pass

            if cur_state == "3" or sec >= 30:
                hwnd = focus_marathon(proc.pid)
                print(f"[*] [t+{sec:02d}s] Sending DirectInput scancodes (Enter=0x1C, Space=0x39, Click, hwnd={hwnd})...")
                send_scancode_key(0x1C) # Enter
                time.sleep(0.05)
                send_scancode_key(0x39) # Space
                time.sleep(0.05)
                send_mouse_click()

            if cur_state in ("6", "7", "8", "9"):
                print(f"[!] SUCCESS! Advanced to State {cur_state} at t+{sec:02d}s!")
                if cur_state == "8":
                    print(f"[+] State 8 tasks: {tasks}")
                break
    finally:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except Exception:
                proc.kill()
        print("[+] Test completed.")

if __name__ == "__main__":
    main()
