import capstone

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
base = 0x00007FF70F850000
data = open("D:/Marathon-live/mem_area_2EF40000.bin", "rb").read()

target_rva = 0x2EF4070B
target_off = target_rva - 0x2EF40000

# Search backwards for function prologue (e.g. sub rsp / push rbp)
start_off = target_off
for off in range(target_off, max(0, target_off - 128), -1):
    if data[off-1] == 0xC3 or data[off-1] == 0xCC:
        start_off = off
        break

start_rva = 0x2EF40000 + start_off
print(f"Disassembling from 0x{start_rva:08X} (offset 0x{start_off:04X}) to +256 bytes:")
code = data[start_off:start_off + 256]
for ins in md.disasm(code, base + start_rva):
    marker = "  <=== CALL TARGET" if ins.address == base + target_rva else ""
    print(f"0x{ins.address:016X} (RVA 0x{ins.address-base:08X}): {ins.mnemonic:<8} {ins.op_str}{marker}")
    if ins.mnemonic == 'ret' and ins.address >= base + target_rva:
        break
