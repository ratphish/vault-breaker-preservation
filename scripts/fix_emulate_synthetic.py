from pathlib import Path

path = Path("D:/vault-breaker-preservation/scripts/emulate_synthetic_function.py")
raw = path.read_bytes()
lines = raw.splitlines(keepends=True)

# Delete lines 182-185 (0-indexed: 181 to 184) and restore line 186 indentation (2 spaces)
# lines[181] is ' row7_scratch = 0x7FFF0000\r\n'
# lines[185] is 'if a.bitset_fixture:\r\n'
new_lines = lines[:181] + [b"  if a.bitset_fixture:\r\n"] + lines[186:]

# Find where uc.reg_write(UC_X86_REG_EFLAGS,0x202) is
found_uc = False
final_lines = []
for line in new_lines:
    final_lines.append(line)
    if b"uc.reg_write(UC_X86_REG_EFLAGS,0x202)" in line:
        final_lines.append(b"row7_scratch = 0x7FFF0000\r\n")
        final_lines.append(b"if a.row7_mode1_fixture:\r\n")
        final_lines.append(b" uc.mem_map(row7_scratch, 4096, 7)\r\n")
        final_lines.append(b" uc.mem_write(row7_scratch, bytes(4096))\r\n")
        found_uc = True

assert found_uc, "found_uc failed"
path.write_bytes(b"".join(final_lines))
print("SUCCESS: Perfectly fixed emulate_synthetic_function.py")
