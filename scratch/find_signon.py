import re

with open(r'D:\Marathon-live\Marathon.exe', 'rb') as f:
    chunk_size = 64 * 1024 * 1024
    offset = 0
    pattern = re.compile(b'(?i)signon')
    
    matches = 0
    while True:
        chunk = f.read(chunk_size)
        if not chunk: break
        for m in pattern.finditer(chunk):
            matches += 1
            if matches <= 20:
                print(f"Match at 0x{offset + m.start():X}: {chunk[max(0, m.start()-10):min(len(chunk), m.start()+30)]}")
        offset += len(chunk)
print(f"Total matches: {matches}")
