import glob
import os
import capstone

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
files = glob.glob(r'D:\Marathon-live\code_bootflow_ref_*.bin')

for fpath in sorted(files):
    fname = os.path.basename(fpath)
    rva_str = fname.replace('code_bootflow_ref_', '').replace('.bin', '')
    try:
        rva = int(rva_str, 16)
    except ValueError:
        continue
    
    data = open(fpath, 'rb').read()
    instr_code = data[256:256+16]
    disasm = list(md.disasm(instr_code, rva))
    if disasm:
        ins = disasm[0]
        # Check if rip-relative
        if '[rip +' in ins.op_str or '[rip -' in ins.op_str:
            # calculate target
            # disp
            op = ins.op_str.split('[rip ')[1].split(']')[0]
            if '+' in op:
                disp = int(op.replace('+', '').strip(), 16)
            else:
                disp = -int(op.replace('-', '').strip(), 16)
            target = ins.address + ins.size + disp
            print(f"RVA 0x{rva:08X}: {ins.mnemonic:<6} {ins.op_str:<32} -> Target RVA 0x{target:08X}")
