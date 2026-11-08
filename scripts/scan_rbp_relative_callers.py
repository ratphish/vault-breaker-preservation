"""Scan for direct RVAs, table entries, and indirect branches targeting the context insertion block."""
import argparse
import hashlib
import json
import mmap
import struct
from pathlib import Path

from capstone import Cs, CS_ARCH_X86, CS_MODE_64

def scan_file_for_rvash(path: Path, rvas: list[int], image_base=0x140000000):
    hits = []
    data = path.read_bytes()
    for rva in rvas:
        target_va = image_base + rva
        pattern = struct.pack("<I", rva)
        pos = 0
        while True:
            pos = data.find(pattern, pos)
            if pos == -1:
                break
            hits.append({
                "file": path.name,
                "file_offset": hex(pos),
                "matched_rva": hex(rva),
                "target_va": hex(target_va),
            })
            pos += 1
    return hits

def scan_text_for_branches(text_path: Path, target_start: int, target_end: int, base=0x140001000):
    decoder = Cs(CS_ARCH_X86, CS_MODE_64)
    data = text_path.read_bytes()
    branches = []
    # Search for relative near jump/call instructions (e8, e9, 0f 80..8f)
    for pos in range(len(data) - 5):
        b0 = data[pos]
        if b0 in (0xe8, 0xe9): # call / jmp near rel32
            disp = int.from_bytes(data[pos+1:pos+5], "little", signed=True)
            dest = base + pos + 5 + disp
            if target_start <= dest <= target_end:
                branches.append({
                    "type": "call" if b0 == 0xe8 else "jmp",
                    "instruction_va": hex(base + pos),
                    "target_va": hex(dest),
                    "displacement": hex(disp),
                })
        elif b0 == 0x0f and 0x80 <= data[pos+1] <= 0x8f and pos + 6 <= len(data): # jcc near rel32
            disp = int.from_bytes(data[pos+2:pos+6], "little", signed=True)
            dest = base + pos + 6 + disp
            if target_start <= dest <= target_end:
                branches.append({
                    "type": "jcc",
                    "instruction_va": hex(base + pos),
                    "target_va": hex(dest),
                    "displacement": hex(disp),
                })
    return branches

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--analysis-dir", type=Path, default=Path("D:/Marathon-preservation/analysis"))
    args = parser.parse_args()

    target_rvas = [0x1bb67025, 0x1bb67083]
    image_base = 0x140000000
    
    results = {"rva_hits": [], "direct_branches": []}
    
    for filename in ["synthetic-text-section.bin", "rdata-synthetic-build26136895.bin", "parent-vmp0-transformed.bin"]:
        file_path = args.analysis_dir / filename
        if file_path.exists():
            hits = scan_file_for_rvash(file_path, target_rvas, image_base)
            results["rva_hits"].extend(hits)
            
    text_path = args.analysis_dir / "synthetic-text-section.bin"
    if text_path.exists():
        branches = scan_text_for_branches(text_path, 0x15b687000, 0x15b687090)
        results["direct_branches"].extend(branches)
        
    print(json.dumps(results, indent=2))

if __name__ == "__main__":
    main()
