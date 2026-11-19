import struct

data = open(r'D:\Marathon-live\mem_bootflow_table.bin', 'rb').read()
dump_start_rva = 0x32DA2690 - 0x1000 # 0x32DA1690
dump_end_rva = dump_start_rva + len(data)

base = 0x7ff70f850000

print(f"Dump covers RVA: 0x{dump_start_rva:X} - 0x{dump_end_rva:X}")

# Let's inspect all pointer entries at 0x1000 and onwards
print("=== Entries starting at offset 0x1000 (RVA 0x32DA2690) ===")
for offset in range(0x1000, 0x1200, 8):
    ptr = struct.unpack('<Q', data[offset:offset+8])[0]
    rva = ptr - base
    # Check if rva falls inside dump
    target_str = ""
    if dump_start_rva <= rva < dump_end_rva:
        off_in_dump = rva - dump_start_rva
        # read null-terminated string
        end_str = data.find(b'\x00', off_in_dump)
        if end_str != -1:
            target_str = data[off_in_dump:end_str].decode('latin1', errors='replace')
    print(f"Offset 0x{offset:04X} (RVA 0x{dump_start_rva + offset:X}): Ptr=0x{ptr:016X} (RVA 0x{rva:X}) -> '{target_str}'")
