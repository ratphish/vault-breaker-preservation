with open(r"C:\Users\marra\AppData\Local\Temp\Marathon\crash_folder\crash_folder_34864_20261107_224438\minidump.dmp", "rb") as f:
    dmp = f.read()

import re
matches = [m.start() for m in re.finditer(b"libcurl", dmp, re.IGNORECASE)]
print("libcurl matches in minidump:", len(matches))
