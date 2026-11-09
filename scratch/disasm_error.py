with open(r'D:\Marathon-live\Marathon.exe', 'rb') as f:
    off = 0xC97262F
    f.seek(off - 128)
    data = f.read(256)

print(f"Offset 0x{off:X} (RVA 0xC97302F):")
print("Hex dump:")
for i in range(0, len(data), 16):
    chunk = data[i:i+16]
    hex_str = ' '.join(f'{b:02X}' for b in chunk)
    ascii_str = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
    rel_off = (off - 128 + i) - off
    print(f"{rel_off:+04d} (0x{off-128+i:08X}): {hex_str:<48} | {ascii_str}")
