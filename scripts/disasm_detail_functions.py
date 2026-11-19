import capstone

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)

for rva_str in ['302CD27F', '1EF24ECE', '704D2E9', '8892074', '16146ADA', '1D6D1440']:
    fn = f'D:/Marathon-live/code_bootflow_ref_{rva_str}.bin'
    try:
        data = open(fn, 'rb').read()
        rva = int(rva_str, 16)
        print(f"\n==================== DUMP: {rva_str} ====================")
        # Disassemble from offset 200 to 350
        start_rva = rva - (256 - 200)
        chunk = data[200:350]
        for ins in md.disasm(chunk, start_rva):
            marker = "  <--- TARGET" if ins.address == rva else ""
            print(f"0x{ins.address:08X}:  {ins.mnemonic:<8} {ins.op_str}{marker}")
    except Exception as e:
        print(f"Error for {rva_str}: {e}")
