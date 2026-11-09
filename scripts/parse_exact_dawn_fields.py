with open(r'D:\vault-breaker-preservation\scripts\dawn_signon_asm.txt', 'r') as f:
    lines = f.readlines()

# Let's inspect from line 0 to line 1040 in dawn_signon_asm.txt
# We want to reconstruct the exact fields written.

# Let's look at lines around each tag candidate:
tag_lines = [26, 79, 130, 181, 228, 262, 296, 358, 443, 524, 573, 608, 661, 712, 745, 791, 824, 875, 911, 960]

for tl in tag_lines:
    print(f"=== TAG AROUND LINE {tl} ===")
    for k in range(max(0, tl - 8), min(len(lines), tl + 20)):
        print(f"{k:4d}: {lines[k].rstrip()}")
