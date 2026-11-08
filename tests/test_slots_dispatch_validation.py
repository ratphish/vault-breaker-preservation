"""Test and validate listener slots 7, 8, 9 input/output contracts and investment resolution."""
import json
import subprocess
import sys
from pathlib import Path

PYTHON_EXE = sys.executable
TOOLS_PYTHON = Path("D:/Marathon-preservation/tools/python")
TOOLS_UNICORN = Path("D:/Marathon-preservation/tools/unicorn-2.0.1-post1")
SCRIPTS_DIR = Path("D:/vault-breaker-preservation/scripts")

def run_probe(cmd_args):
    env = dict(PYTHONPATH=f"{TOOLS_UNICORN};{TOOLS_PYTHON};{SCRIPTS_DIR}")
    res = subprocess.run([PYTHON_EXE, str(SCRIPTS_DIR / "emulate_synthetic_function.py")] + cmd_args,
                         capture_output=True, text=True, env=env)
    assert res.returncode == 0, f"Probe failed: {res.stderr}"
    return json.loads(res.stdout)

def test_slot8_field_extraction():
    cmd = [
        "D:/Marathon-preservation/build-26136895-20261031/Marathon.exe",
        "D:/Marathon-preservation/analysis/synthetic-text-section.bin",
        "D:/Marathon-preservation/analysis/rdata-synthetic-build26136895.bin",
        "--modeled-data", "D:/Marathon-preservation/analysis/parent-data-virtual-full.bin",
        "--modeled-vmp", "D:/Marathon-preservation/analysis/parent-vmp0-transformed.bin",
        "--registry-data-checkpoint", "D:/Marathon-preservation/analysis/checkpoint-parent-waits-empty",
        "--start", "0x16f1a0a90", "--target", "0x730000000000",
        "--rcx", "0x760000000010", "--model-object", "--a23f-field-fixture",
        "--model-tls", "--model-tls-template", "--inline-dispatch", "--trace-dispatch",
        "--count", "10000"
    ]
    out = run_probe(cmd)
    assert out["stop"]["kind"] == "target_reached"
    # Output must be 80800070 container with field 0x11223344 at +8
    assert out["synthetic_a23f_field_fixture"]["output"] == "70008080000000004433221100000000"
    print("PASS: Slot 8 (0x16f1a0a90) extracted +0x20 field into 80800070 container")

def test_slot9_field_extraction():
    cmd = [
        "D:/Marathon-preservation/build-26136895-20261031/Marathon.exe",
        "D:/Marathon-preservation/analysis/synthetic-text-section.bin",
        "D:/Marathon-preservation/analysis/rdata-synthetic-build26136895.bin",
        "--modeled-data", "D:/Marathon-preservation/analysis/parent-data-virtual-full.bin",
        "--modeled-vmp", "D:/Marathon-preservation/analysis/parent-vmp0-transformed.bin",
        "--registry-data-checkpoint", "D:/Marathon-preservation/analysis/checkpoint-parent-waits-empty",
        "--start", "0x16f159160", "--target", "0x730000000000",
        "--rcx", "0x760000000010", "--model-object", "--a23f-field-fixture",
        "--model-tls", "--model-tls-template", "--inline-dispatch", "--trace-dispatch",
        "--count", "10000"
    ]
    out = run_probe(cmd)
    assert out["stop"]["kind"] == "target_reached"
    # Output must be 80800070 container with field 0x55667788 at +8
    assert out["synthetic_a23f_field_fixture"]["output"] == "70008080000000008877665500000000"
    print("PASS: Slot 9 (0x16f159160) extracted +0x24 field into 80800070 container")

def test_slot7_investment_resolution():
    cmd = [
        "D:/Marathon-preservation/build-26136895-20261031/Marathon.exe",
        "D:/Marathon-preservation/analysis/synthetic-text-section.bin",
        "D:/Marathon-preservation/analysis/rdata-synthetic-build26136895.bin",
        "--modeled-data", "D:/Marathon-preservation/analysis/parent-data-virtual-full.bin",
        "--modeled-vmp", "D:/Marathon-preservation/analysis/parent-vmp0-transformed.bin",
        "--registry-data-checkpoint", "D:/Marathon-preservation/analysis/checkpoint-parent-waits-empty",
        "--registry-heap-pages",
        "--a23f-serialized-component", "D:/Marathon-preservation/analysis/vault-reference-records/80B37FED.bin",
        "--a23f-package-entry-fixture",
        "--a23f-startup-service-fixture", "D:/Marathon-preservation/analysis/row7-service-table-assets",
        "--a23f-startup-key", "0x00244270",
        "--start", "0x16f765b80", "--target", "0x15f8daa17",
        "--rcx", "0x760000003b58", "--rdx", "0x760000000200", "--r8", "0x760000000100",
        "--model-object", "--model-tls", "--model-tls-template",
        "--inline-dispatch", "--trace-dispatch",
        "--stub-getcurrentprocess", "--stub-flush", "--stub-crt-basics",
        "--count", "30000"
    ]
    out = run_probe(cmd)
    assert out["stop"]["kind"] == "target_reached"
    assert out["registers_at_stop"]["rdx"] == "0x12"
    print("PASS: Slot 7 (0x16f765b80) fallback resolved investment table key 0x00244270 -> record byte 0x12")

if __name__ == "__main__":
    test_slot8_field_extraction()
    test_slot9_field_extraction()
    test_slot7_investment_resolution()
