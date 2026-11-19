import capstone
import struct

data = open("D:/Marathon-live/mem_func_state8_2EF4C7E0.bin", "rb").read()
base = 0x00007FF70F850000
start_rva = 0x2EF4C7E0

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
md.detail = True

print(f"Scanning 16KB dump at RVA 0x{start_rva:X}...")

# Let's find function prologues or ret instructions
# In x64, common prologues:
# sub rsp, ...
# push rbp/rbx/rdi/rsi
# mov [rsp+...], ...

offset = 0
functions = []
while offset < len(data) - 16:
    # Check for ret followed by int3 or prologue
    # Or common prologues
    b = data[offset:offset+4]
    # Check if this offset is a known target or interesting
    offset += 1

# Let's disassemble sequentially in chunks where instructions make sense
for chunk_start in range(0, min(len(data), 2048), 64):
    chunk = data[chunk_start:chunk_start+64]
    insns = list(md.disasm(chunk, base + start_rva + chunk_start))
    # if valid instructions found
    if len(insns) >= 3:
        # print first instruction
        first = insns[0]
        # check if interesting (call, lea, cmp, mov)
        for ins in insns:
            if ins.mnemonic in ['call', 'lea', 'cmp', 'test']:
                rva = ins.address - base
                # print
                # print(f"RVA 0x{rva:08X}: {ins.mnemonic:<8} {ins.op_str}")
