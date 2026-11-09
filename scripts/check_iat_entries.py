import sys
sys.path.insert(0, r"D:\Marathon-preservation\tools\python")
import pefile

pe = pefile.PE(r"D:\Marathon-live\Marathon.exe", fast_load=True)
pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']])

for entry in pe.DIRECTORY_ENTRY_IMPORT:
    if entry.dll.decode().lower() == "ws2_32.dll":
        for imp in entry.imports:
            if imp.name and imp.name.decode() in ["getaddrinfo", "gethostbyname", "connect", "send", "recv"]:
                print(f"WS2_32 import: {imp.name.decode()} at IAT RVA 0x{imp.address - pe.OPTIONAL_HEADER.ImageBase:X}")
