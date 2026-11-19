# Let's inspect the XOR transformation:
# r8d = rax + 0x52
# byte = r8b ^ data[rcx + 8 + i]

print("If key byte is (i + 0x52):")
for i in range(29):
    k = (i + 0x52) & 0xFF
    print(f"i={i:2d}: key=0x{k:02X} ('{chr(k) if 32 <= k <= 126 else '.'}')")
