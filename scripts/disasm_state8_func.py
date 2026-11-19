import capstone
import struct
from pathlib import Path

def analyze_dump(dump_path, base_va, rva, length=4096):
    p = Path(dump_path)
    if not p.exists():
        print(f"[-] Dump {dump_path} does not exist yet.")
        return

    data = p.read_bytes()
    print(f"\n========================================================")
    print(f"[*] Analyzing {dump_path} ({len(data)} bytes) at RVA 0x{rva:08X} (VA 0x{base_va + rva:016X})")
    print(f"========================================================")

    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True

    calls = []
    jumps = []
    rip_refs = []

    count = 0
    for ins in md.disasm(data[:length], base_va + rva):
        count += 1
        # Track calls and jumps
        if ins.mnemonic.startswith("call"):
            calls.append((ins.address, ins.op_str))
        elif ins.mnemonic.startswith("j") and ins.mnemonic != "jmp":
            jumps.append((ins.address, ins.mnemonic, ins.op_str))

        # Check for rip-relative operands
        for op in ins.operands:
            if op.type == capstone.x86.X86_OP_MEM:
                if op.mem.base == capstone.x86.X86_REG_RIP:
                    target_va = ins.address + ins.size + op.mem.disp
                    target_rva = target_va - base_va
                    rip_refs.append((ins.address, ins.mnemonic, ins.op_str, target_rva))

        if count <= 120:
            print(f"0x{ins.address:016X} (RVA +0x{ins.address - (base_va+rva):04X}): {ins.mnemonic:<8} {ins.op_str}")

    print(f"\n--- Summary of Function at RVA 0x{rva:08X} ---")
    print(f"Total instructions disassembled: {count}")
    print(f"Total CALLs: {len(calls)}")
    for addr, target in calls[:15]:
        print(f"   CALL at 0x{addr:X}: {target}")
    if len(calls) > 15:
        print(f"   ... ({len(calls) - 15} more calls)")

    print(f"\nTotal RIP-relative references: {len(rip_refs)}")
    for addr, mnem, op_str, trva in rip_refs[:20]:
        print(f"   0x{addr:X}: {mnem} {op_str} -> Target RVA 0x{trva:08X}")

if __name__ == "__main__":
    base_va = 0x00007FF70F850000
    analyze_dump("D:/Marathon-live/mem_func_state8_2EF4C7E0.bin", base_va, 0x2EF4C7E0, length=8192)
