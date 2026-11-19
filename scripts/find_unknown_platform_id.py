import glob

target = b"unknown platform account id"

# Search in all dumped mem_*.bin files
for fn in glob.glob("D:/Marathon-live/mem_*.bin"):
    data = open(fn, 'rb').read()
    if target in data:
        off = data.find(target)
        print(f"Found '{target.decode()}' in {fn} at offset 0x{off:X}")

# Search in Marathon.exe if possible
try:
    with open("D:/Marathon-live/Marathon.exe", "rb") as f:
        # Search in chunks
        chunk_size = 1024 * 1024 * 16
        pos = 0
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            if target in chunk:
                off = chunk.find(target)
                print(f"Found in Marathon.exe at file offset 0x{pos + off:X}")
            pos += len(chunk)
except Exception as e:
    print(f"Error reading Marathon.exe: {e}")
