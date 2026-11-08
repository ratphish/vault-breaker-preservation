"""Fast branch and RVA scanner targeting the candidate insertion block."""
import json
import mmap
import struct
from pathlib import Path

def scan():
    base = 0x140001000
    target_start = 0x15b687000
    target_end = 0x15b687090
    image_base = 0x140000000
    rvas = [0x1bb67025, 0x1bb67083]
    
    analysis_dir = Path("D:/Marathon-preservation/analysis")
    results = {"rva_hits": [], "direct_branches": []}
    
    # 1. Fast RVA scan
    for fname in ["synthetic-text-section.bin", "rdata-synthetic-build26136895.bin", "parent-vmp0-transformed.bin"]:
        p = analysis_dir / fname
        if not p.exists(): continue
        with p.open("rb") as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
            for rva in rvas:
                pattern = struct.pack("<I", rva)
                pos = mm.find(pattern)
                while pos != -1:
                    results["rva_hits"].append({
                        "file": fname,
                        "offset": hex(pos),
                        "rva": hex(rva),
                        "target_va": hex(image_base + rva)
                    })
                    pos = mm.find(pattern, pos + 1)
                    
    # 2. Fast branch scan using find()
    text_path = analysis_dir / "synthetic-text-section.bin"
    if text_path.exists():
        with text_path.open("rb") as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
            for opcode, name in [(b"\xe8", "call"), (b"\xe9", "jmp")]:
                pos = mm.find(opcode)
                while pos != -1:
                    if pos + 5 <= len(mm):
                        disp = int.from_bytes(mm[pos+1:pos+5], "little", signed=True)
                        dest = base + pos + 5 + disp
                        if target_start <= dest <= target_end:
                            results["direct_branches"].append({
                                "type": name,
                                "instruction_va": hex(base + pos),
                                "target_va": hex(dest),
                                "displacement": hex(disp)
                            })
                    pos = mm.find(opcode, pos + 1)
                    
    print(json.dumps(results, indent=2))

if __name__ == "__main__":
    scan()
