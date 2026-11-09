import struct
from pathlib import Path

dmp_path = Path(r"C:\Users\marra\AppData\Local\Temp\Marathon\crash_folder\crash_folder_34864_20261107_224438\minidump.dmp")
with open(dmp_path, "rb") as f:
    data = f.read()

sig, ver, num_streams, stream_dir_rva = struct.unpack_from("<4sIIII", data, 0)[:4]
print(f"Minidump: sig={sig}, streams={num_streams}, dir_rva=0x{stream_dir_rva:X}")

for i in range(num_streams):
    st_type, data_sz, rva = struct.unpack_from("<III", data, stream_dir_rva + i * 12)
    if st_type == 4: # ModuleList
        num_mods = struct.unpack_from("<I", data, rva)[0]
        print(f"ModuleList: {num_mods} modules")
        for m in range(min(num_mods, 20)):
            m_rva = rva + 4 + m * 108
            base_addr, mod_sz = struct.unpack_from("<QI", data, m_rva)
            name_rva = struct.unpack_from("<I", data, m_rva + 64)[0]
            name_len = struct.unpack_from("<I", data, name_rva)[0]
            name = data[name_rva + 4:name_rva + 4 + name_len].decode("utf-16le", errors="ignore").rstrip("\x00")
            print(f"  0x{base_addr:X} - 0x{base_addr+mod_sz:X}: {name.encode('ascii', errors='replace').decode()}")
    elif st_type == 6: # ExceptionStream
        th_id, ex_code, ex_flags, ex_record, ex_addr = struct.unpack_from("<IIQQQ", data, rva)
        print(f"ExceptionStream: Thread {th_id}, code 0x{ex_code:X}, addr 0x{ex_addr:X}")
