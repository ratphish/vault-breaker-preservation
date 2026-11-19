import os
import sys
import time
import subprocess
import ctypes
import ctypes.wintypes
from pathlib import Path

GAME_DIR = Path("D:/Marathon-live")
GAME_EXE = GAME_DIR / "Marathon.exe"
lmdetail_path = Path(os.path.expandvars(r"%LOCALAPPDATA%\Temp\Marathon\lmdetail.json"))

user32 = ctypes.windll.user32

WM_ACTIVATE = 0x0006
WM_SETFOCUS = 0x0007
WM_KEYDOWN = 0x0100
WM_KEYUP = 0x0101
WM_CHAR = 0x0102
WM_LBUTTONDOWN = 0x0201
WM_LBUTTONUP = 0x0202
MK_LBUTTON = 0x0001
VK_RETURN = 0x0D
VK_SPACE = 0x20
MOUSEEVENTF_LEFTDOWN = 0x0002
MOUSEEVENTF_LEFTUP = 0x0004

def get_marathon_windows(pid):
    wins = {}
    def cb(hwnd, extra):
        p = ctypes.c_ulong()
        user32.GetWindowThreadProcessId(hwnd, ctypes.byref(p))
        if p.value == pid:
            cls = ctypes.create_unicode_buffer(256)
            title = ctypes.create_unicode_buffer(256)
            user32.GetClassNameW(hwnd, cls, 256)
            user32.GetWindowTextW(hwnd, title, 256)
            vis = user32.IsWindowVisible(hwnd)
            wins[cls.value] = (hwnd, vis, title.value)
        return True
    user32.EnumWindows(ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_void_p, ctypes.c_void_p)(cb), 0)
    return wins

def trigger_input(hwnd_d3d, hwnd_input):
    rect = ctypes.wintypes.RECT()
    user32.GetClientRect(hwnd_d3d, ctypes.byref(rect))
    cx = (rect.right - rect.left) // 2
    cy = (rect.bottom - rect.top) // 2
    if cx <= 0 or cy <= 0:
        cx, cy = 640, 360
    lParam = (cy << 16) | cx

    # Bring to foreground
    user32.ShowWindow(hwnd_d3d, 9) # SW_RESTORE
    user32.SetForegroundWindow(hwnd_d3d)
    user32.BringWindowToTop(hwnd_d3d)
    user32.SetActiveWindow(hwnd_d3d)
    
    # Send activate / focus
    user32.PostMessageW(hwnd_d3d, WM_ACTIVATE, 1, 0)
    user32.PostMessageW(hwnd_d3d, WM_SETFOCUS, 0, 0)

    # Post mouse click to D3D window
    user32.PostMessageW(hwnd_d3d, WM_LBUTTONDOWN, MK_LBUTTON, lParam)
    time.sleep(0.02)
    user32.PostMessageW(hwnd_d3d, WM_LBUTTONUP, 0, lParam)

    # Post keyboard keys to D3D and Input windows
    for target in [hwnd_d3d, hwnd_input]:
        if not target:
            continue
        user32.PostMessageW(target, WM_KEYDOWN, VK_RETURN, 0x001C0001)
        user32.PostMessageW(target, WM_CHAR, VK_RETURN, 0x001C0001)
        user32.PostMessageW(target, WM_KEYUP, VK_RETURN, 0xC01C0001)
        user32.PostMessageW(target, WM_KEYDOWN, VK_SPACE, 0x00390001)
        user32.PostMessageW(target, WM_CHAR, VK_SPACE, 0x00390001)
        user32.PostMessageW(target, WM_KEYUP, VK_SPACE, 0xC0390001)

    # Global synthesis
    user32.keybd_event(VK_RETURN, 0x1C, 0, 0)
    time.sleep(0.02)
    user32.keybd_event(VK_RETURN, 0x1C, 2, 0)
    user32.keybd_event(VK_SPACE, 0x39, 0, 0)
    time.sleep(0.02)
    user32.keybd_event(VK_SPACE, 0x39, 2, 0)
    user32.mouse_event(MOUSEEVENTF_LEFTDOWN, 0, 0, 0, 0)
    time.sleep(0.02)
    user32.mouse_event(MOUSEEVENTF_LEFTUP, 0, 0, 0, 0)

def main():
    if lmdetail_path.exists():
        try:
            lmdetail_path.unlink()
        except Exception:
            pass

    print("[*] Launching Marathon.exe...")
    proc = subprocess.Popen([str(GAME_EXE)], cwd=str(GAME_DIR))
    print(f"[+] Marathon.exe PID: {proc.pid}")

    last_state = None
    try:
        for sec in range(1, 75):
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

            wins = get_marathon_windows(proc.pid)
            d3d_w = wins.get("Tiger D3D Window", (None,))[0]
            inp_w = wins.get("Tiger Input Window", (None,))[0]

            if cur_state == "3" or sec >= 32:
                print(f"[*] [t+{sec:02d}s] State 3 active -> triggering comprehensive input (D3D={d3d_w}, Input={inp_w})...")
                if d3d_w:
                    trigger_input(d3d_w, inp_w)

            if cur_state in ("6", "7", "8", "9"):
                print(f"[!] SUCCESS! Reached State {cur_state} at t+{sec:02d}s!")
                if cur_state == "8":
                    print(f"[+] State 8 tasks: {tasks}")
    finally:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except Exception:
                proc.kill()
        print("[+] Test finished.")

if __name__ == "__main__":
    main()
