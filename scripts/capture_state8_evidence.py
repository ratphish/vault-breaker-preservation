"""User-run, read-only capture of an EXISTING Windows process. Never launches it.

No injection, debugging, hooks, memory writes, thread access, or UI input.
The candidate function labels come from an unverified handoff, not execution.
"""
import argparse
import ctypes
from ctypes import wintypes
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import struct


RANGES = (
    ("mem_bootflow_table.bin", 0x32da1690, 0x4000),
    ("mem_area_30280000.bin", 0x30280000, 0x20000),
    ("mem_func_state8_2EF4C7E0.bin", 0x2ef4c7e0, 0x4000),
    ("mem_direct_settings_32D28F30.bin", 0x32d28d30, 0x1000),
    ("mem_direct_settings_32DA9B86.bin", 0x32da9986, 0x1000),
    ("mem_direct_settings_32DC701C.bin", 0x32dc6e1c, 0x1000),
    ("candidate_entry_call_0EA73F44.bin", 0x0ea73f44, 0x400),
    ("candidate_entry_call_2EF4070B.bin", 0x2ef4070b, 0x400),
    ("candidate_check_call_224A0999.bin", 0x224a0999, 0x400),
    ("candidate_check_call_198B4BF8.bin", 0x198b4bf8, 0x400),
    ("candidate_check_call_0C4E9E70.bin", 0x0c4e9e70, 0x400),
)


def now():
    return datetime.now(timezone.utc).isoformat()


def capture(pid, expected_exe, output, label, lmdetail):
    if os.name != "nt" or struct.calcsize("P") != 8:
        raise RuntimeError("requires 64-bit Python on Windows")
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel.OpenProcess.restype = wintypes.HANDLE
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.CloseHandle.restype = wintypes.BOOL
    kernel.QueryFullProcessImageNameW.argtypes = [wintypes.HANDLE, wintypes.DWORD,
                                                 wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)]
    kernel.QueryFullProcessImageNameW.restype = wintypes.BOOL
    kernel.K32EnumProcessModules.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.HMODULE),
                                            wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
    kernel.K32EnumProcessModules.restype = wintypes.BOOL
    kernel.K32GetModuleFileNameExW.argtypes = [wintypes.HANDLE, wintypes.HMODULE,
                                            wintypes.LPWSTR, wintypes.DWORD]
    kernel.K32GetModuleFileNameExW.restype = wintypes.DWORD

    class ModuleInfo(ctypes.Structure):
        _fields_ = [("base", ctypes.c_void_p), ("size", wintypes.DWORD),
                    ("entry", ctypes.c_void_p)]

    kernel.K32GetModuleInformation.argtypes = [wintypes.HANDLE, wintypes.HMODULE,
                                              ctypes.POINTER(ModuleInfo), wintypes.DWORD]
    kernel.K32GetModuleInformation.restype = wintypes.BOOL
    kernel.ReadProcessMemory.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p,
                                         ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
    kernel.ReadProcessMemory.restype = wintypes.BOOL
    kernel.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
    kernel.GetExitCodeProcess.restype = wintypes.BOOL
    kernel.GetProcessTimes.argtypes = [wintypes.HANDLE] + [ctypes.POINTER(wintypes.FILETIME)] * 4
    kernel.GetProcessTimes.restype = wintypes.BOOL

    def checked(ok):
        if not ok:
            raise ctypes.WinError(ctypes.get_last_error())

    def read(address, size):
        buffer = ctypes.create_string_buffer(size)
        count = ctypes.c_size_t()
        checked(kernel.ReadProcessMemory(handle, address, buffer, size, ctypes.byref(count)))
        if count.value != size:
            raise RuntimeError(f"short read at {address:#x}: {count.value}/{size}")
        return buffer.raw

    handle = kernel.OpenProcess(0x0400 | 0x0010, False, pid)  # QUERY_INFORMATION | VM_READ only.
    checked(handle)
    report = {"format_version": 1, "pid": pid, "label_user_supplied": label,
              "started_utc": now(), "status": "incomplete", "ranges": [],
              "limitations": ["Sequential reads are not an atomic snapshot.",
                              "Candidate RVAs and user label do not establish executed call paths.",
                              "lmdetail may be stale; compare timestamps and session identity."]}
    made_output = False
    try:
        path_buffer = ctypes.create_unicode_buffer(32768)
        path_size = wintypes.DWORD(len(path_buffer))
        checked(kernel.QueryFullProcessImageNameW(handle, 0, path_buffer, ctypes.byref(path_size)))
        actual_exe = Path(path_buffer.value).resolve()
        if actual_exe != expected_exe.resolve():
            raise ValueError(f"PID executable differs: {actual_exe}")
        modules = (wintypes.HMODULE * 2048)()
        needed = wintypes.DWORD()
        checked(kernel.K32EnumProcessModules(handle, modules, ctypes.sizeof(modules), ctypes.byref(needed)))
        if not needed.value or needed.value > ctypes.sizeof(modules):
            raise RuntimeError("module inventory incomplete")
        checked(kernel.K32GetModuleFileNameExW(handle, modules[0], path_buffer, len(path_buffer)))
        if Path(path_buffer.value).resolve() != actual_exe:
            raise RuntimeError("first module is not the expected executable")
        info = ModuleInfo()
        checked(kernel.K32GetModuleInformation(handle, modules[0], ctypes.byref(info), ctypes.sizeof(info)))
        times = [wintypes.FILETIME() for _ in range(4)]
        checked(kernel.GetProcessTimes(handle, *(ctypes.byref(value) for value in times)))
        report.update(executable=str(actual_exe), image_base=hex(info.base), image_size=hex(info.size),
                      process_creation_filetime=(times[0].dwHighDateTime << 32) | times[0].dwLowDateTime)
        with actual_exe.open("rb") as stream:
            report["executable_sha256"] = hashlib.file_digest(stream, "sha256").hexdigest()
        output.mkdir(parents=True, exist_ok=False)
        made_output = True

        def save_detail(suffix):
            if lmdetail is None or not lmdetail.is_file():
                return
            stat = lmdetail.stat()
            body = lmdetail.read_bytes()
            (output / f"lmdetail-{suffix}.json").write_bytes(body)
            report[f"lmdetail_{suffix}"] = {"source": str(lmdetail), "mtime_ns": stat.st_mtime_ns,
                                           "sha256": hashlib.sha256(body).hexdigest()}

        save_detail("before")
        for filename, rva, length in RANGES:
            if rva + length > info.size:
                raise ValueError(f"candidate range outside image: {rva:#x}")
            started = now()
            body = read(info.base + rva, length)
            with (output / filename).open("xb") as stream:
                stream.write(body)
            report["ranges"].append({"file": filename, "rva": hex(rva), "bytes": length,
                                      "read_started_utc": started, "read_ended_utc": now(),
                                      "sha256": hashlib.sha256(body).hexdigest()})
        save_detail("after")
        exit_code = wintypes.DWORD()
        checked(kernel.GetExitCodeProcess(handle, ctypes.byref(exit_code)))
        if exit_code.value != 259:
            raise RuntimeError("target exited during capture")
        report["status"] = "complete"
    except Exception as error:
        report["error"] = str(error)
        raise
    finally:
        kernel.CloseHandle(handle)
        report["ended_utc"] = now()
        if made_output:
            with (output / "capture-manifest.json").open("x", encoding="utf-8") as stream:
                json.dump(report, stream, indent=2)
                stream.write("\n")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pid", type=int, required=True)
    parser.add_argument("--expected-exe", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True, help="New directory; existing directories are rejected")
    parser.add_argument("--label", required=True, help="Your observed stage; not verified by the script")
    parser.add_argument("--lmdetail", type=Path)
    args = parser.parse_args()
    report = capture(args.pid, args.expected_exe, args.output, args.label, args.lmdetail)
    print(json.dumps({key: report[key] for key in ("status", "pid", "image_base", "label_user_supplied")}, indent=2))


if __name__ == "__main__":
    main()
