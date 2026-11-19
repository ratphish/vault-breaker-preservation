import re

data = open(r'D:\Marathon-live\mem_bootflow_table.bin', 'rb').read()

terms = [b'sos', b'direct', b'setting', b'global', b'manifest', b'content', b'checking', b'bap', b'action']
for term in terms:
    matches = [m.start() for m in re.finditer(re.escape(term), data, re.IGNORECASE)]
    print(f"Term '{term.decode()}': {len(matches)} occurrences")
    for m in matches[:10]:
        snippet = data[max(0, m-20):min(len(data), m+40)]
        print(f"    0x{m:04X} (RVA 0x{0x32DA1690+m:X}): {snippet}")
