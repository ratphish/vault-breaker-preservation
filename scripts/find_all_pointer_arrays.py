import struct

data = open(r'D:\Marathon-live\mem_bootflow_table.bin', 'rb').read()
base = 0x00007FF70F850000

# Search for contiguous sequences of >= 8 64-bit pointers
print("Scanning for pointer arrays in mem_bootflow_table.bin...")
i = 0
while i < len(data) - 64:
    ptrs = []
    curr = i
    while curr < len(data) - 8:
        val = struct.unpack('<Q', data[curr:curr+8])[0]
        # check if 64-bit pointer starting with 0x7FF7
        if (val >> 32) == 0x7FF7:
            ptrs.append(val)
            curr += 8
        else:
            break
    if len(ptrs) >= 8:
        rva = 0x32DA1690 + i
        print(f"Array at offset 0x{i:04X} (RVA 0x{rva:X}) with {len(ptrs)} pointers:")
        for idx, p in enumerate(ptrs[:5]):
            target_rva = p - base
            print(f"    [{idx}] 0x{p:016X} (RVA 0x{target_rva:X})")
        if len(ptrs) > 5:
            print(f"    ... ({len(ptrs) - 5} more)")
        i = curr
    else:
        i += 8
