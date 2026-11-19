import sys
import json
import time
from pathlib import Path
from datetime import datetime, timezone

# Find Marathon.exe PID
import ctypes
from ctypes import wintypes as W

k = ctypes.windll.kernel32
TH32CS_SNAPPROCESS = 0x00000002

class PROCESSENTRY32(ctypes.Structure):
    _fields_ = [
        ('dwSize', W.DWORD),
        ('cntUsage', W.DWORD),
        ('th32ProcessID', W.DWORD),
        ('th32DefaultHeapID', ctypes.c_size_t),
        ('th32ModuleID', W.DWORD),
        ('cntThreads', W.DWORD),
        ('th32ParentProcessID', W.DWORD),
        ('pcPriClassBase', ctypes.c_long),
        ('dwFlags', W.DWORD),
        ('szExeFile', ctypes.c_char * 260)
    ]

def get_marathon_pid():
    snap = k.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snap == -1 or snap == 0xFFFFFFFFFFFFFFFF:
        return None
    pe = PROCESSENTRY32()
    pe.dwSize = ctypes.sizeof(PROCESSENTRY32)
    pids = []
    if k.Process32First(snap, ctypes.byref(pe)):
        while True:
            exe = pe.szExeFile.decode('latin1', errors='ignore')
            if exe.lower() == 'marathon.exe':
                pids.append(pe.th32ProcessID)
            if not k.Process32Next(snap, ctypes.byref(pe)):
                break
    k.CloseHandle(snap)
    return pids[-1] if pids else None

def main():
    pid = get_marathon_pid()
    if not pid:
        print('[*] Waiting for Marathon.exe to start... (Launch the game now)', flush=True)
        while not pid:
            time.sleep(0.5)
            pid = get_marathon_pid()

    ts = datetime.now().strftime('%Y%m%d-%H%M%S')
    evidence_dir = Path(r'D:\Marathon-preservation\analysis') / f'force-state2-{ts}'
    evidence_dir.mkdir(parents=True, exist_ok=True)

    arm_file = evidence_dir / 'ARM_FORCE_STATE2.json'
    arm_file.write_text(json.dumps({'mode': 'force-state2-v1', 'pid': pid}), encoding='utf-8')

    print(f'[+] Detected Marathon.exe (PID {pid})', flush=True)
    print(f'[+] Prepared evidence dir: {evidence_dir}', flush=True)
    print('[+] Waiting for stable stall signature and forcing provider state 1 -> 2...', flush=True)

    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import force_provider_state_once

    class Args:
        pass
    args = Args()
    args.pid = pid
    args.evidence_dir = evidence_dir

    try:
        force_provider_state_once.run(args)
    except BaseException as e:
        print(json.dumps({'status': 'aborted', 'error': str(e)}))
        sys.exit(1)

if __name__ == '__main__':
    main()
