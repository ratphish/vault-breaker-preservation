with open(r'D:\vault-breaker-preservation\scripts\dawn_signon_asm.txt', 'r') as f:
    lines = f.readlines()

# Scan through lines from line 0 to line 1040 (function 0x1804BDD70)
for idx, line in enumerate(lines[:1040]):
    # check for mov to r9d, r8d, ebx, eax, ecx, edx
    parts = line.strip().split()
    if len(parts) >= 3 and parts[1] == 'mov':
        dest = parts[2].rstrip(',')
        src = parts[3] if len(parts) > 3 else ''
        if src.startswith('0x') or src.isdigit():
            try:
                v = int(src, 16) if src.startswith('0x') else int(src)
                # check tag
                fnum = v >> 3
                wtype = v & 7
                if 1 <= fnum <= 30 and wtype in (0, 1, 2, 5):
                    print(f"Line {idx:3d} [Tag candidate]: {line.strip()} ==> Field {fnum}, WireType {wtype}")
            except:
                pass
        elif '; ->' in line:
            print(f"Line {idx:3d} [Ref candidate]: {line.strip()}")
