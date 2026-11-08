"""Test and validate Mode 1 replay execution continuation past instruction 10,000."""
import json
import subprocess
import sys
from pathlib import Path

PYTHON_EXE = sys.executable
TOOLS_PYTHON = Path("D:/Marathon-preservation/tools/python")
TOOLS_UNICORN = Path("D:/Marathon-preservation/tools/unicorn-2.0.1-post1")
SCRIPTS_DIR = Path("D:/vault-breaker-preservation/scripts")

def run_mode1_harness(count=20000):
    env = dict(PYTHONPATH=f"{TOOLS_UNICORN};{TOOLS_PYTHON};{SCRIPTS_DIR}")
    cmd = [
        PYTHON_EXE, str(SCRIPTS_DIR / "emulate_synthetic_function.py"),
        "D:/Marathon-preservation/build-26136895-20261031/Marathon.exe",
        "D:/Marathon-preservation/analysis/synthetic-text-section.bin",
        "D:/Marathon-preservation/analysis/rdata-synthetic-build26136895.bin",
        "--modeled-data", "D:/Marathon-preservation/analysis/parent-data-virtual-full.bin",
        "--modeled-vmp", "D:/Marathon-preservation/analysis/parent-vmp0-transformed.bin",
        "--registry-data-checkpoint", "D:/Marathon-preservation/analysis/checkpoint-parent-waits-empty",
        "--registry-heap-pages",
        "--row7-mode1-fixture",
        "--start", "0x17123efa0",
        "--target", "0x730000000000",
        "--model-object",
        "--model-tls",
        "--model-tls-template",
        "--inline-dispatch",
        "--trace-dispatch",
        "--stub-getcurrentprocess",
        "--stub-flush",
        "--stub-crt-basics",
        "--stub-srw-lock",
        "--count", str(count)
    ]
    res = subprocess.run(cmd, capture_output=True, text=True, env=env)
    assert res.returncode == 0, f"Harness failed with code {res.returncode}: {res.stderr}"
    return json.loads(res.stdout)

def test_mode1_continuation():
    out = run_mode1_harness(20000)
    
    # Verify execution advanced past 10,000 instructions
    assert out["instructions"] >= 10000, f"Instruction count {out['instructions']} < 10000"
    print(f"PASS: Executed {out['instructions']} instructions past Mode 1 trampolines")
    
    # Verify synthetic GetCurrentProcess calls
    assert out.get("stubbed_getcurrentprocess", 0) >= 2, "Must stub at least 2 GetCurrentProcess calls"
    print(f"PASS: Stubbed {out['stubbed_getcurrentprocess']} GetCurrentProcess calls")
    
    # Verify instruction cache flushes
    flushes = out.get("stubbed_flushes", [])
    assert len(flushes) >= 2, "Must stub at least 2 FlushInstructionCache calls"
    print(f"PASS: Stubbed {len(flushes)} FlushInstructionCache calls")
    
    # Verify AVX 160-byte blit YMM load/store pairs
    avx_events = out.get("general_avx_events", [])
    avx_rips = {ev["rip"] for ev in avx_events}
    for expected_rip in ["0x14757e415", "0x14757e419", "0x14757e431", "0x14757e439", 
                         "0x14757e43e", "0x14757e443", "0x14757e448", "0x14757e450"]:
        assert expected_rip in avx_rips, f"Missing expected AVX event at {expected_rip}"
    print(f"PASS: Verified all 4 AVX YMM store pairs in 160-byte transform state blit")
    
    # Verify SRW synchronization stubs
    srw_calls = out.get("fake_srw_calls", [])
    srw_imports = [c["import"] for c in srw_calls]
    assert "KERNEL32.dll!AcquireSRWLockExclusive" in srw_imports
    assert "KERNEL32.dll!ReleaseSRWLockExclusive" in srw_imports
    assert "KERNEL32.dll!WakeAllConditionVariable" in srw_imports
    print(f"PASS: Verified SRWLock and ConditionVariable synchronization sequence ({len(srw_calls)} calls)")
    
    # Verify thread local storage index 64 initialization
    tls_calls = out.get("fake_tls_calls", [])
    assert any(c["import"].lower().endswith("tlsgetvalue") and c["index"] == 64 for c in tls_calls), "Must query TLS slot 64"
    assert any(c["import"].lower().endswith("tlssetvalue") and c["index"] == 64 for c in tls_calls), "Must store to TLS slot 64"
    print("PASS: Verified dynamic TLS slot 64 thread context initialization")

    # Verify target reached
    assert out.get("stop", {}).get("kind") == "target_reached", f"Mode 1 did not reach target: {out.get('stop')}"
    assert out.get("stop", {}).get("address") == "0x730000000000", "Target address mismatch"
    print(f"PASS: Mode 1 completed replay and reached designated target 0x730000000000 cleanly at instruction {out['instructions']}")

if __name__ == "__main__":
    test_mode1_continuation()
