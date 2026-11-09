import capstone

with open(r'D:\Dawnv0.1.5.2\payload\steam_api64.dll', 'rb') as f:
    data = f.read()

# Function is around file offset 0x48DA0F
# Let's find function start (scan backwards for int3 or standard prologue push rbp/sub rsp)
start_off = 0x48DA0F
while start_off > 0x48D000:
    if data[start_off:start_off+2] == b'\xCC\xCC' or data[start_off-1:start_off+1] == b'\xC3\xCC':
        start_off += 1
        while data[start_off] == 0xCC:
            start_off += 1
        break
    start_off -= 1

print(f"Function start candidate: 0x{start_off:X}")

cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
code_slice = data[start_off:start_off + 2000]

lines = []
for ins in cs.disasm(code_slice, 0x180000000 + (start_off - 0x48DA0F + 0x48E60F)):
    lines.append(f"0x{ins.address:X}: {ins.mnemonic} {ins.op_str}")

print("\n".join(lines[:120]))
