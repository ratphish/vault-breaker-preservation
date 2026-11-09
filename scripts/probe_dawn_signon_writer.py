"""Run the pinned Dawn 0.1.5.2 SignOn writer on synthetic input under Unicorn."""
import argparse
import hashlib
import json
from pathlib import Path
import struct

import pefile
from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE
from unicorn.x86_const import (
    UC_X86_REG_RAX, UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_R8,
    UC_X86_REG_R9, UC_X86_REG_RSP, UC_X86_REG_RIP,
)

from marathon_protobuf import ProtobufReader


DLL_SHA256 = "88c75ac8f411215a87a6e62758f9dcc34fb4bab903ebdec074c2e08164acc7c8"
ARG_REGISTERS = (UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_R8, UC_X86_REG_R9)
ENTITLEMENTS = (3065800, 3760193538, 3760193537)
OUTPUT_CAPACITY = 4096


def run_writer(dll_path: Path, config_key: bool) -> bytes:
    dll = dll_path.read_bytes()
    if hashlib.sha256(dll).hexdigest() != DLL_SHA256:
        raise ValueError("Writer RVAs are specific to Dawn 0.1.5.2. DLL hash differs.")
    pe = pefile.PE(data=dll, fast_load=True)
    base = pe.OPTIONAL_HEADER.ImageBase
    image = pe.get_memory_mapped_image()
    cpu = Uc(UC_ARCH_X86, UC_MODE_64)
    size = max(len(image), pe.OPTIONAL_HEADER.SizeOfImage)
    cpu.mem_map(base, (size + 4095) & ~4095)
    cpu.mem_write(base, image)

    scratch = 0x10000000
    cpu.mem_map(scratch, 0x60000)
    stack = scratch + 0xF008
    context = scratch + 0x10000
    entries = scratch + 0x30000
    output = scratch + 0x34000
    span = scratch + 0x39000
    length = span + 0x100
    return_address = span + 0x200

    cpu.mem_write(stack, struct.pack("<Q", return_address))
    cpu.mem_write(stack + 0x28, struct.pack("<QQ", span, length))
    cpu.mem_write(span, struct.pack("<QQ", output, OUTPUT_CAPACITY))
    cpu.mem_write(context, bytes(range(64)) + struct.pack("<IH", 0x7F000001, 7777))
    if config_key:
        cpu.mem_write(context + 0x4C, bytes(range(16)) + b"\x01")

    for index, entitlement in enumerate(ENTITLEMENTS):
        decimal = str(entitlement).encode("ascii")
        row = decimal.ljust(32, b"\0") + bytes([len(decimal), 2])
        cpu.mem_write(entries + index * 0x22, row)
    cpu.mem_write(entries + 0x1100, struct.pack("<Q", len(ENTITLEMENTS)))
    cpu.reg_write(UC_X86_REG_RSP, stack)
    for register, value in zip(ARG_REGISTERS, (context, entries, 86400, 1794257000)):
        cpu.reg_write(register, value)

    def emulate_library(machine, address, size, user_data):
        dest, second, third, fourth = (machine.reg_read(r) for r in ARG_REGISTERS)
        rsp = machine.reg_read(UC_X86_REG_RSP)
        offset = address - base
        if offset == 0x622AF0:  # memset
            machine.mem_write(dest, bytes([second & 255]) * third)
            machine.reg_write(UC_X86_REG_RAX, dest)
        elif offset == 0x623030:  # memcpy
            machine.mem_write(dest, bytes(machine.mem_read(second, third)))
            machine.reg_write(UC_X86_REG_RAX, dest)
        elif offset == 0x2640:  # snprintf, one five-argument format at this call site
            fmt = bytes(machine.mem_read(third, 64)).split(b"\0", 1)[0]
            args = [fourth]
            for slot in (0x28, 0x30, 0x38, 0x40):
                args.append(int.from_bytes(machine.mem_read(rsp + slot, 4), "little"))
            result = fmt % tuple(args)
            if len(result) >= second:
                raise ValueError("Formatted URL would exceed the writer's buffer")
            machine.mem_write(dest, result + b"\0")
            machine.reg_write(UC_X86_REG_RAX, len(result))
        # The fourth stub is the security-cookie check. The writer's own branches run.
        caller = int.from_bytes(machine.mem_read(rsp, 8), "little")
        machine.reg_write(UC_X86_REG_RIP, caller)
        machine.reg_write(UC_X86_REG_RSP, rsp + 8)

    for offset in (0x622AF0, 0x623030, 0x2640, 0x5E9560):
        cpu.hook_add(UC_HOOK_CODE, emulate_library, begin=base + offset, end=base + offset)

    cpu.emu_start(base + 0x4BDD70, return_address, count=500_000)
    count = int.from_bytes(cpu.mem_read(length, 8), "little")
    if cpu.reg_read(UC_X86_REG_RIP) != return_address or cpu.reg_read(UC_X86_REG_RAX) & 255 != 1:
        raise RuntimeError("Dawn writer did not return success")
    if not 0 < count <= OUTPUT_CAPACITY:
        raise ValueError("Dawn writer returned an invalid buffer length")
    return bytes(cpu.mem_read(output, count))


def describe(payload: bytes, path=()):
    fields = []
    for number, wire, value in ProtobufReader(payload).parse():
        child = path + (number,)
        if child in {(2,), (2, 12), (4,), (10,)}:
            value = describe(value, child)
        elif wire == 2:
            value = value.hex()
        fields.append([number, wire, value])
    return fields


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dll", type=Path)
    parser.add_argument("--config-key", action="store_true", help="Set Dawn's optional config-key flag")
    args = parser.parse_args()
    payload = run_writer(args.dll, args.config_key)
    print(json.dumps({"length": len(payload), "sha256": hashlib.sha256(payload).hexdigest(),
                      "fields": describe(payload)}))
