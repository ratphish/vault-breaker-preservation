"""Install a minimal synthetic Windows loader list; never execute mapped DLLs."""
import hashlib
import struct
from pathlib import Path
import pefile
from unicorn import UC_PROT_READ, UC_PROT_WRITE


def install_user32(uc):
    """Map an additional local PE as data for a previously simulated load."""
    name = 'user32.dll'
    raw = (Path('C:/Windows/System32') / name).read_bytes()
    image = pefile.PE(data=raw, fast_load=True)
    base, size = 0x7e0030000000, image.OPTIONAL_HEADER.SizeOfImage
    if size > 0x10000000:
        raise ValueError('system image too large')
    uc.mem_map(base, (size + 4095) & ~4095, UC_PROT_READ)
    uc.mem_write(base, raw[:image.OPTIONAL_HEADER.SizeOfHeaders])
    for section in image.sections:
        if section.SizeOfRawData:
            uc.mem_write(base + section.VirtualAddress,
                         raw[section.PointerToRawData:section.PointerToRawData + section.SizeOfRawData])
    return {'name': name, 'base': hex(base), 'size': size,
            'sha256': hashlib.sha256(raw).hexdigest(), 'execution': 'disabled',
            'assumption': 'post-checkpoint data-only image for previously simulated load; not in loader list'}


def link_user32(uc, teb, module):
    """Append a synthetic loader entry without moving the pre-existing entries."""
    storage = 0x7e1000000000
    uc.mem_map(storage, 0x1000, UC_PROT_READ | UC_PROT_WRITE)
    entry, full_name, base_name = storage + 0x100, storage + 0x400, storage + 0x500
    uc.mem_write(entry + 0x30, struct.pack('<Q', int(module['base'], 16)))
    uc.mem_write(entry + 0x40, struct.pack('<I', module['size']))
    for field, buffer, value in ((0x48, full_name, r'C:\Windows\System32\user32.dll'),
                                 (0x58, base_name, 'user32.dll')):
        encoded = value.encode('utf-16le')
        uc.mem_write(buffer, encoded + b'\0\0')
        uc.mem_write(entry + field, struct.pack('<HH4xQ', len(encoded), len(encoded) + 2, buffer))
    ldr = teb + 0x1200
    for off in (0x10, 0x20, 0x30):
        head, link = ldr + off, entry + off - 0x10
        tail = struct.unpack('<Q', bytes(uc.mem_read(head + 8, 8)))[0]
        uc.mem_write(link, struct.pack('<QQ', head, tail))
        uc.mem_write(tail, struct.pack('<Q', link))
        uc.mem_write(head + 8, struct.pack('<Q', link))
    return {'entry': hex(entry), 'assumption': 'synthetic user32 appended to three loader lists'}


def install_loaded_modules(uc, teb, names):
    """Model prior successful loads as local, data-only PE images and loader entries."""
    storage = 0x7e1100000000
    if not names or len(names) > 32 or len(set(names)) != len(names):
        raise ValueError('invalid synthetic module list')
    uc.mem_map(storage, 0x10000, UC_PROT_READ | UC_PROT_WRITE)
    evidence = []
    for i, name in enumerate(names):
        if not name.isascii() or not name.endswith('.dll') or Path(name).name != name:
            raise ValueError('invalid synthetic module name')
        raw = (Path('C:/Windows/System32') / name).read_bytes()
        image = pefile.PE(data=raw, fast_load=True)
        base, size = 0x7e0030000000 + i * 0x10000000, image.OPTIONAL_HEADER.SizeOfImage
        if size > 0x10000000:
            raise ValueError('system image too large')
        uc.mem_map(base, (size + 4095) & ~4095, UC_PROT_READ)
        uc.mem_write(base, raw[:image.OPTIONAL_HEADER.SizeOfHeaders])
        for section in image.sections:
            if section.SizeOfRawData:
                uc.mem_write(base + section.VirtualAddress,
                             raw[section.PointerToRawData:section.PointerToRawData + section.SizeOfRawData])
        entry, full_name, base_name = storage + i * 0x400, storage + i * 0x400 + 0x100, storage + i * 0x400 + 0x300
        uc.mem_write(entry + 0x30, struct.pack('<Q', base))
        uc.mem_write(entry + 0x40, struct.pack('<I', size))
        for field, buffer, value in ((0x48, full_name, 'C:\\Windows\\System32\\' + name), (0x58, base_name, name)):
            encoded = value.encode('utf-16le')
            if len(encoded) >= 0x100:
                raise ValueError('module name too long')
            uc.mem_write(buffer, encoded + b'\0\0')
            uc.mem_write(entry + field, struct.pack('<HH4xQ', len(encoded), len(encoded) + 2, buffer))
        for off in (0x10, 0x20, 0x30):
            head, link = teb + 0x1200 + off, entry + off - 0x10
            tail = struct.unpack('<Q', bytes(uc.mem_read(head + 8, 8)))[0]
            uc.mem_write(link, struct.pack('<QQ', head, tail))
            uc.mem_write(tail, struct.pack('<Q', link))
            uc.mem_write(head + 8, struct.pack('<Q', link))
        evidence.append({'name': name, 'base': hex(base), 'size': size,
                         'sha256': hashlib.sha256(raw).hexdigest(), 'execution': 'disabled',
                         'assumption': 'data-only local image for previously simulated successful load'})
    return evidence


def install(uc, teb, image_base, image_size):
    peb, ldr = teb + 0x1000, teb + 0x1200
    uc.mem_write(teb + 0x60, struct.pack('<Q', peb))
    uc.mem_write(peb + 0x10, struct.pack('<QQ', image_base, ldr))
    uc.mem_write(ldr, struct.pack('<I', 0x58))
    modules = [('Marathon.exe', image_base, image_size, r'C:\Preservation\Marathon.exe')]
    evidence = []
    for i, name in enumerate(('ntdll.dll', 'kernel32.dll', 'kernelbase.dll')):
        raw = (Path('C:/Windows/System32') / name).read_bytes()
        image = pefile.PE(data=raw, fast_load=True)
        base = 0x7e0000000000 + i * 0x10000000
        size = image.OPTIONAL_HEADER.SizeOfImage
        if size > 0x10000000:
            raise ValueError('system image too large')
        uc.mem_map(base, (size + 4095) & ~4095, UC_PROT_READ)
        uc.mem_write(base, raw[:image.OPTIONAL_HEADER.SizeOfHeaders])
        for section in image.sections:
            if section.SizeOfRawData:
                uc.mem_write(base + section.VirtualAddress,
                             raw[section.PointerToRawData:section.PointerToRawData + section.SizeOfRawData])
        modules.append((name, base, size, 'C:\\Windows\\System32\\' + name))
        evidence.append({'name': name, 'base': hex(base), 'size': size,
                         'sha256': hashlib.sha256(raw).hexdigest(), 'execution': 'disabled'})
    for i, (name, base, size, full) in enumerate(modules):
        entry, full_name = teb + 0x1300 + i * 0x100, teb + 0x1700 + i * 0x100
        uc.mem_write(entry + 0x30, struct.pack('<Q', base))
        uc.mem_write(entry + 0x40, struct.pack('<I', size))
        for field, buffer, value in ((0x48, full_name, full), (0x58, full_name + 0x80, name)):
            encoded = value.encode('utf-16le')
            if len(encoded) >= 0x80:
                raise ValueError('module name too long')
            uc.mem_write(buffer, encoded + b'\0\0')
            uc.mem_write(entry + field, struct.pack('<HH4xQ', len(encoded), len(encoded) + 2, buffer))
    for off in (0x10, 0x20, 0x30):
        head = ldr + off
        links = [teb + 0x1300 + i * 0x100 + off - 0x10 for i in range(len(modules))]
        uc.mem_write(head, struct.pack('<QQ', links[0], links[-1]))
        for i, link in enumerate(links):
            uc.mem_write(link, struct.pack('<QQ', links[i + 1] if i + 1 < len(links) else head,
                                           links[i - 1] if i else head))
    return evidence
