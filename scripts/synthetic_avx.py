"""Small, bounded AVX helpers for Unicorn versions lacking 256-bit moves.

This is not a general AVX emulator. Callers supply memory validation and mapping;
unsupported instructions return False and remain the caller's responsibility.
"""
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86_const import X86_OP_IMM, X86_OP_MEM, X86_OP_REG
from unicorn import x86_const as ureg

_cs = Cs(CS_ARCH_X86, CS_MODE_64)
_cs.detail = True


def try_avx(uc, address, size, memory):
    """Execute a supported instruction, returning a description or None.

    memory(address, length, writing) must validate and map the entire range.
    """
    # Unicorn can report a sentinel size for an instruction its decoder rejects.
    # Map/validate a cross-page candidate before reading its maximum x86 length.
    available = 15
    if not memory(address, available, False):
        return None
    raw = bytes(uc.mem_read(address, available))
    if raw[0] not in (0xc4, 0xc5):
        return None
    decoded = list(_cs.disasm(raw, address, count=1))
    if not decoded:
        return None
    ins = decoded[0]
    size = ins.size
    ops = ins.operands

    def name(op):
        return ins.reg_name(op.reg)

    def register(reg_name):
        return getattr(ureg, 'UC_X86_REG_' + reg_name.upper(), None)

    if ins.mnemonic == 'vpcmpeqd' and len(ops) == 3 and all(o.type == X86_OP_REG for o in ops):
        dst, left, right = map(name, ops)
        if all(x.startswith('ymm') for x in (dst, left, right)):
            target, a, b = map(register, (dst, left, right))
            if all(x is not None for x in (target, a, b)):
                av, bv = uc.reg_read(a), uc.reg_read(b)
                result = sum((0xffffffff if (av >> (i * 32)) & 0xffffffff == (bv >> (i * 32)) & 0xffffffff else 0) << (i * 32) for i in range(8))
                uc.reg_write(target, result)
                uc.reg_write(ureg.UC_X86_REG_RIP, address + size)
                return {'rip': hex(address), 'instruction': ins.mnemonic, 'register': dst, 'direction': 'register_compare'}

    if ins.mnemonic in ('vpxor', 'vxorps', 'vxorpd') and len(ops) == 3 and all(o.type == X86_OP_REG for o in ops):
        dst, left, right = map(name, ops)
        if dst.startswith('xmm') and dst == left == right:
            ymm = register('ymm' + dst[3:])
            if ymm is not None:
                uc.reg_write(ymm, 0)
                uc.reg_write(ureg.UC_X86_REG_RIP, address + size)
                return {'rip': hex(address), 'instruction': ins.mnemonic, 'zeroed': dst.replace('xmm', 'ymm')}

    if ins.mnemonic in ('vbroadcastss', 'vpbroadcastq') and len(ops) == 2 and all(o.type == X86_OP_REG for o in ops):
        dst, src = map(name, ops)
        if (dst.startswith('xmm') or dst.startswith('ymm')) and src.startswith('xmm'):
            target = register('ymm' + dst[3:])
            source = register(src)
            if target is not None and source is not None:
                bits = 32 if ins.mnemonic == 'vbroadcastss' else 64
                word = uc.reg_read(source) & ((1 << bits) - 1)
                lanes = (128 if dst.startswith('xmm') else 256) // bits
                result = sum(word << (bits * i) for i in range(lanes))
                uc.reg_write(target, result)
                uc.reg_write(ureg.UC_X86_REG_RIP, address + size)
                return {'rip': hex(address), 'instruction': ins.mnemonic, 'register': dst,
                        'direction': 'register_broadcast'}

    if ins.mnemonic == 'vblendvps' and len(ops) == 4 and all(o.type == X86_OP_REG for o in ops):
        dst, left, right, mask = map(name, ops)
        if all(x.startswith('xmm') for x in (dst, left, right, mask)):
            target = register('ymm' + dst[3:])
            sources = [register(x) for x in (left, right, mask)]
            if target is not None and all(x is not None for x in sources):
                a, b, select = (uc.reg_read(x) for x in sources)
                result = sum((((b if (select >> (32 * i + 31)) & 1 else a) >> (32 * i)) & 0xffffffff)
                             << (32 * i) for i in range(4))
                uc.reg_write(target, result)
                uc.reg_write(ureg.UC_X86_REG_RIP, address + size)
                return {'rip': hex(address), 'instruction': ins.mnemonic, 'register': dst,
                        'direction': 'register_blend'}

    if (ins.mnemonic == 'vpermilps' and len(ops) == 3 and ops[0].type == X86_OP_REG
            and ops[1].type == X86_OP_REG and ops[2].type == X86_OP_IMM):
        dst, src = name(ops[0]), name(ops[1])
        if dst.startswith('xmm') and src.startswith('xmm'):
            target, source = register('ymm' + dst[3:]), register(src)
            if target is not None and source is not None:
                value, mask = uc.reg_read(source), ops[2].imm & 0xff
                result = sum(((value >> (32 * ((mask >> (2 * i)) & 3))) & 0xffffffff)
                             << (32 * i) for i in range(4))
                uc.reg_write(target, result)
                uc.reg_write(ureg.UC_X86_REG_RIP, address + size)
                return {'rip': hex(address), 'instruction': ins.mnemonic, 'register': dst,
                        'direction': 'register_permutation', 'mask': hex(mask)}

    if (ins.mnemonic in ('vinsertf128', 'vinserti128') and len(ops) == 4
            and all(o.type == X86_OP_REG for o in ops[:3]) and ops[3].type == X86_OP_IMM):
        dst, first, second = map(name, ops[:3])
        if dst.startswith('ymm') and first.startswith('ymm') and second.startswith('xmm'):
            target, source, lane = register(dst), register(first), register(second)
            if target is not None and source is not None and lane is not None:
                value = uc.reg_read(source)
                part = uc.reg_read(lane) & ((1 << 128) - 1)
                shift = 128 * (ops[3].imm & 1)
                result = (value & ~(((1 << 128) - 1) << shift)) | (part << shift)
                uc.reg_write(target, result)
                uc.reg_write(ureg.UC_X86_REG_RIP, address + size)
                return {'rip': hex(address), 'instruction': ins.mnemonic, 'register': dst,
                        'direction': 'register_lane_insert', 'lane': shift // 128}

    if ins.mnemonic not in ('vmovups', 'vmovupd', 'vmovdqu', 'vmovaps', 'vmovapd', 'vmovdqa', 'vbroadcastf128', 'vbroadcasti128') or len(ops) != 2:
        return None
    if ops[0].type == X86_OP_REG and ops[1].type == X86_OP_MEM:
        reg, mem, loading = name(ops[0]), ops[1], True
    elif ops[0].type == X86_OP_MEM and ops[1].type == X86_OP_REG:
        reg, mem, loading = name(ops[1]), ops[0], False
    else:
        return None
    broadcast = ins.mnemonic in ('vbroadcastf128', 'vbroadcasti128')
    width = 16 if broadcast else 32
    if not reg.startswith('ymm') or mem.size != width or mem.mem.segment or broadcast and not loading:
        return None
    vector = register(reg)
    if vector is None:
        return None
    ptr = mem.mem.disp
    for identifier, scale in ((mem.mem.base, 1), (mem.mem.index, mem.mem.scale)):
        if identifier:
            reg_name = ins.reg_name(identifier)
            if reg_name == 'rip':
                value = address + size
            else:
                constant = register(reg_name)
                if constant is None:
                    return None
                value = uc.reg_read(constant)
            ptr += value * scale
    ptr &= (1 << 64) - 1
    if ins.mnemonic in ('vmovaps', 'vmovapd', 'vmovdqa') and ptr % 32:
        return None
    if not memory(ptr, width, not loading):
        return None
    if loading:
        value = bytes(uc.mem_read(ptr, width))
        uc.reg_write(vector, int.from_bytes(value * 2 if broadcast else value, 'little'))
    else:
        uc.mem_write(ptr, uc.reg_read(vector).to_bytes(32, 'little'))
    uc.reg_write(ureg.UC_X86_REG_RIP, address + size)
    return {'rip': hex(address), 'instruction': ins.mnemonic, 'register': reg,
            'address': hex(ptr), 'direction': 'load' if loading else 'store'}
