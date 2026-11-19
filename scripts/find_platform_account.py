target = b"platform_account"

with open("D:/Marathon-live/Marathon.exe", "rb") as f:
    pos = 0
    while True:
        chunk = f.read(1024 * 1024 * 16)
        if not chunk:
            break
        idx = chunk.find(target)
        while idx != -1:
            print(f"Found '{target.decode()}' in Marathon.exe at file offset 0x{pos + idx:X}")
            print("Context:", chunk[max(0, idx-10):idx+50])
            idx = chunk.find(target, idx + 1)
        pos += len(chunk)
