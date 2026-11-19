import ctypes
import time
import subprocess

user32 = ctypes.windll.user32

def enum_windows(target_pid):
    results = []
    def cb(hwnd, extra):
        pid = ctypes.c_ulong()
        tid = user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
        if pid.value == target_pid:
            title = ctypes.create_unicode_buffer(512)
            user32.GetWindowTextW(hwnd, title, 512)
            cls = ctypes.create_unicode_buffer(512)
            user32.GetClassNameW(hwnd, cls, 512)
            vis = user32.IsWindowVisible(hwnd)
            results.append((hwnd, tid, vis, cls.value, title.value))
        return True
    user32.EnumWindows(ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_void_p, ctypes.c_void_p)(cb), 0)
    return results

print("[*] Launching Marathon.exe...")
proc = subprocess.Popen(["D:/Marathon-live/Marathon.exe"], cwd="D:/Marathon-live")
print(f"PID: {proc.pid}")
for s in range(30):
    time.sleep(1)
    wins = enum_windows(proc.pid)
    if wins:
        print(f"[t+{s:02d}s] Found {len(wins)} windows: {wins}")
        if any(w[2] for w in wins): # visible
            print(f"[t+{s:02d}s] Visible window found! Sending Enter...")
            for w in wins:
                hwnd = w[0]
                user32.SetForegroundWindow(hwnd)
                user32.PostMessageW(hwnd, 0x0100, 0x0D, 0) # WM_KEYDOWN
                time.sleep(0.05)
                user32.PostMessageW(hwnd, 0x0101, 0x0D, 0) # WM_KEYUP
    if s >= 20:
        # Check lmdetail
        try:
            lmd = open(r'C:\Users\marra\AppData\Local\Temp\Marathon\lmdetail.json').read()
            import json
            j = json.loads(lmd)
            print(f"[t+{s:02d}s] lmdetail state={j.get('state')} tasks={j.get('tasks')}")
            if j.get('state') != '3':
                print(f"[+] TRANSITIONED! State is now {j.get('state')}")
                break
        except Exception as e:
            pass

proc.terminate()
proc.wait()
