import capstone

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
base = 0x00007FF70F850000
data = open("D:/Marathon-live/mem_func_state8_2EF4C7E0.bin", "rb").read()

# Let's inspect bytes from offset 0x30 to 0x200
print("Scanning functions in mem_func_state8 from offset 0x30...")
for off in range(0x30, 0x200):
    # Check if offset looks like function start (e.g. sub rsp / mov / push / int3 before)
    if data[off-1] == 0xC3 or data[off-1] == 0xCC:
        insns = list(md.disasm(data[off:off+128], base + 0x2EF4C7E0 + off))
        if len(insns) >= 5:
            print(f"\n--- Function at offset +0x{off:04X} (RVA 0x{0x2EF4C7E0 + off:08X}) ---")
            for ins in insns[:12]:
                print(f"0x{ins.address:016X}: {ins.mnemonic:<8} {ins.op_str}")
