import ctypes
import time
import subprocess
from pathlib import Path

user32 = ctypes.windll.user32

def enum_windows():
    results = []
    def cb(hwnd, extra):
        pid = ctypes.c_ulong()
        user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
        title = ctypes.create_unicode_buffer(512)
        user32.GetWindowTextW(hwnd, title, 512)
        cls = ctypes.create_unicode_buffer(512)
        user32.GetClassNameW(hwnd, cls, 512)
        visible = user32.IsWindowVisible(hwnd)
        results.append((hwnd, pid.value, visible, cls.value, title.value))
        return True
    user32.EnumWindows(ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_void_p, ctypes.c_void_p)(cb), 0)
    return results

print("Starting Marathon.exe...")
proc = subprocess.Popen(["D:/Marathon-live/Marathon.exe"], cwd="D:/Marathon-live")
print(f"PID: {proc.pid}")
for s in range(15):
    time.sleep(1)
    wins = [w for w in enum_windows() if w[1] == proc.pid]
    if wins:
        print(f"[t+{s}s] Windows for PID {proc.pid}: {wins}")
        break

proc.terminate()
proc.wait()
