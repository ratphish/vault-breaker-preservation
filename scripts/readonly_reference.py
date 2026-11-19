"""Private decoding of a captured reference using read-only image pages."""
import hashlib
import struct


def decode_reference(read, base, image_size, reference, reference_rva):
    """Decode captured bytes privately; CPU execution never enters the client."""
    from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_MEM_UNMAPPED, UC_HOOK_MEM_WRITE
    from unicorn.x86_const import UC_X86_REG_RSP, UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_RAX, UC_X86_REG_RIP
    encoded, = struct.unpack_from('<Q', reference)
    codec, = struct.unpack_from('<I', reference, 20)
    if not encoded or not 0x1000 <= codec < 0x32C84000:
        raise ValueError('reference is not initialized')
    cpu = Uc(UC_ARCH_X86, UC_MODE_64)
    stack, marker = 0x700000000000, 0x710000000000
    cpu.mem_map(stack, 0x10000)
    cpu.mem_map(marker, 4096)
    cpu.mem_write(stack + 0xEFF8, struct.pack('<Q', marker))
    cpu.reg_write(UC_X86_REG_RSP, stack + 0xEFF8)
    cpu.reg_write(UC_X86_REG_RCX, encoded)
    cpu.reg_write(UC_X86_REG_RDX, base + reference_rva)
    pages, violations = {}, []

    def missing(uc, access, address, size, value, context):
        page = address & ~4095
        if page in pages or len(pages) >= 16 or not base <= page < page + 4096 <= base + image_size:
            return False
        raw = read(page, 4096)
        cpu.mem_map(page, 4096)
        cpu.mem_write(page, raw)
        pages[page] = raw
        return True

    def writes(uc, access, address, size, value, context):
        if not stack <= address < address + size <= stack + 0x10000:
            violations.append(hex(address))
            uc.emu_stop()

    cpu.hook_add(UC_HOOK_MEM_UNMAPPED, missing)
    cpu.hook_add(UC_HOOK_MEM_WRITE, writes)
    cpu.emu_start(base + codec, marker, count=20000, timeout=1000000)
    if violations or cpu.reg_read(UC_X86_REG_RIP) != marker:
        raise ValueError('private decoder did not return safely')
    obj = encoded ^ cpu.reg_read(UC_X86_REG_RAX)
    if not 0x10000 <= obj < 0x800000000000 - 0xC0 or obj & 15:
        raise ValueError('decoded object is not canonical/aligned')
    return obj, {'codec_rva': hex(codec), 'pages': {
        hex(address): hashlib.sha256(raw).hexdigest() for address, raw in pages.items()}}
