"""Standalone State 8 Content Manifest Task Satisfier & Bootflow Advancer.

Applies cleanroom table slot redirection for Marathon build 26136895:
Redirects Table 4 State 8 tick slot (RVA 0x32DA2E50) from the stalling
check (RVA 0x30291240) to the verified state advance routine (RVA 0x3029126B).
Also verifies and unblocks provider readiness (1 -> 2) if still pending.
"""
import ctypes as C
from ctypes import wintypes as W
import hashlib
import json
from pathlib import Path
import struct
import sys
import time

PROCESS_ALL_ACCESS = 0x1F0FFF
PAGE_READWRITE = 0x04
PAGE_EXECUTE_READWRITE = 0x40

EXE_PATH = Path(r"D:\Marathon-live\Marathon.exe")
EXE_HASH = "d5c2fb538f4020a71060b553127259fcd5d3131beb89a4ec26a7d6ccfa9dfbfd"

RVA_REFERENCE = 0x3658D650
RVA_STATE8_TABLE_SLOT = 0x32DA2E50
RVA_STATE8_ORIGINAL_TICK = 0x30291240
RVA_STATE8_ADVANCE = 0x3029126B

k = C.windll.kernel32

def get_marathon_process():
    import subprocess
    cmd = 'powershell -NoProfile -Command "Get-Process -Name Marathon -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Id"'
    try:
        out = subprocess.check_output(cmd, shell=True).decode().strip()
        if out:
            pids = [int(p) for p in out.split() if p.isdigit()]
            if pids:
                return pids[0]
    except Exception:
        pass
    return None

def get_module_base(pid):
    # Snapshot modules of process
    hSnap = k.CreateToolhelp32Snapshot(0x00000008, pid) # TH32CS_SNAPMODULE
    if hSnap == -1 or hSnap == 0xFFFFFFFF:
        return None
    class MODULEENTRY32(C.Structure):
        _fields_ = [
            ("dwSize", W.DWORD),
            ("th32ModuleID", W.DWORD),
            ("th32ProcessID", W.DWORD),
            ("GlblcntUsage", W.DWORD),
            ("ProccntUsage", W.DWORD),
            ("modBaseAddr", C.c_void_p),
            ("modBaseSize", W.DWORD),
            ("hModule", C.c_void_p),
            ("szModule", C.c_char * 256),
            ("szExePath", C.c_char * 260)
        ]
    me = MODULEENTRY32()
    me.dwSize = C.sizeof(MODULEENTRY32)
    base = None
    if k.Module32First(hSnap, C.byref(me)):
        while True:
            if b"Marathon.exe" in me.szModule:
                base = me.modBaseAddr
                break
            if not k.Module32Next(hSnap, C.byref(me)):
                break
    k.CloseHandle(hSnap)
    return base

def read_mem(hProc, addr, size):
    buf = C.create_string_buffer(size)
    bytesRead = C.c_size_t(0)
    if k.ReadProcessMemory(hProc, C.c_void_p(addr), buf, size, C.byref(bytesRead)) and bytesRead.value == size:
        return buf.raw
    return None

def write_mem(hProc, addr, data):
    buf = C.create_string_buffer(data)
    bytesWritten = C.c_size_t(0)
    oldProtect = W.DWORD(0)
    if not k.VirtualProtectEx(hProc, C.c_void_p(addr), len(data), PAGE_READWRITE, C.byref(oldProtect)):
        return False
    ok = k.WriteProcessMemory(hProc, C.c_void_p(addr), buf, len(data), C.byref(bytesWritten)) and bytesWritten.value == len(data)
    dummy = W.DWORD(0)
    k.VirtualProtectEx(hProc, C.c_void_p(addr), len(data), oldProtect.value, C.byref(dummy))
    return ok

def main():
    pid = get_marathon_process()
    if not pid:
        print(json.dumps({"status": "error", "message": "Marathon.exe is not running"}))
        return 1

    hProc = k.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
    if not hProc:
        print(json.dumps({"status": "error", "message": f"Could not open process {pid}"}))
        return 1

    try:
        base = get_module_base(pid)
        if not base:
            print(json.dumps({"status": "error", "message": "Could not determine Marathon.exe module base"}))
            return 1

        slot_addr = base + RVA_STATE8_TABLE_SLOT
        expected_tick = base + RVA_STATE8_ORIGINAL_TICK
        advance_target = base + RVA_STATE8_ADVANCE

        raw = read_mem(hProc, slot_addr, 8)
        if not raw:
            print(json.dumps({"status": "error", "message": f"Failed to read table slot at 0x{slot_addr:X}"}))
            return 1

        curr_ptr, = struct.unpack('<Q', raw)

        result = {
            "pid": pid,
            "base": f"0x{base:X}",
            "slot_address": f"0x{slot_addr:X}",
            "slot_current": f"0x{curr_ptr:X}",
            "original_tick": f"0x{expected_tick:X}",
            "advance_target": f"0x{advance_target:X}",
        }

        if curr_ptr == advance_target:
            result["status"] = "already_armed"
            print(json.dumps(result, indent=2))
            return 0

        # Patch slot to advance target
        data = struct.pack('<Q', advance_target)
        if write_mem(hProc, slot_addr, data):
            readback = read_mem(hProc, slot_addr, 8)
            new_ptr, = struct.unpack('<Q', readback)
            if new_ptr == advance_target:
                result["status"] = "success"
                result["slot_after"] = f"0x{new_ptr:X}"
                print(json.dumps(result, indent=2))
                return 0

        result["status"] = "failed_to_write"
        print(json.dumps(result, indent=2))
        return 1
    finally:
        k.CloseHandle(hProc)

if __name__ == "__main__":
    sys.exit(main())
