import glob
import os
import capstone

# Initialize Capstone for x86_64
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)

files = glob.glob(r'D:\Marathon-live\code_bootflow_ref_*.bin')
print(f"Total dumped code files: {len(files)}")

for fpath in sorted(files):
    fname = os.path.basename(fpath)
    rva_str = fname.replace('code_bootflow_ref_', '').replace('.bin', '')
    try:
        rva = int(rva_str, 16)
    except ValueError:
        continue
    
    data = open(fpath, 'rb').read()
    # The dump is 512 bytes: 256 bytes before instruction, 256 bytes after
    # So instruction is at offset 256 in the dump, corresponding to RVA
    instr_code = data[256:256+32]
    disasm = list(md.disasm(instr_code, rva))
    if disasm:
        ins = disasm[0]
        print(f"RVA 0x{rva:X}: {ins.mnemonic} {ins.op_str}")
        # print next 3 instructions
        for next_ins in disasm[1:4]:
            print(f"    0x{next_ins.address:X}: {next_ins.mnemonic} {next_ins.op_str}")
