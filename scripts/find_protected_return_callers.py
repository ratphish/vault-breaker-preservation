"""Find direct calls whose bounded EAX return adjustment reaches a chosen address."""
import argparse
import hashlib
import json
import mmap
from pathlib import Path

from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86_const import X86_OP_IMM, X86_OP_REG, X86_REG_EAX


parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("text", type=Path)
parser.add_argument("target", type=lambda value: int(value, 0))
args = parser.parse_args()
with args.text.open("rb") as stream:
    digest = hashlib.file_digest(stream, "sha256").hexdigest()
if digest != "e003a16dc5e495ee9b0b1b3824a46c9553e0bcbd038b432eddb3a55d7d450dca":
    raise ValueError("unexpected reconstructed text image")

decoder = Cs(CS_ARCH_X86, CS_MODE_64)
decoder.detail = True
base = 0x140001000
signature = bytes.fromhex("9c5053ff742418b8")
tail = bytes.fromhex("4863c048010424c3")
mask = 0xffffffff
matched = []
wrapper_candidates = []
seen = 0
decoded = 0
with args.text.open("rb") as stream, mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as data:
    position = data.find(signature)
    while position >= 0:
        seen += 1
        value = int.from_bytes(data[position + 8:position + 12], "little")
        offset = position + 12
        operations = []
        for _ in range(12):
            if data[offset:offset + len(tail)] == tail:
                decoded += 1
                delta = value if value < 0x80000000 else value - 0x100000000
                caller = args.target - delta - 5
                caller_offset = caller - base
                if 0 <= caller_offset <= len(data) - 5 and data[caller_offset] == 0xe8:
                    displacement = int.from_bytes(data[caller_offset + 1:caller_offset + 5], "little", signed=True)
                    destination = caller + 5 + displacement
                    if destination == base + position:
                        matched.append({
                            "caller": hex(caller),
                            "stub": hex(destination),
                            "delta": delta,
                            "target": hex(args.target),
                            "operations": operations,
                        })
                    elif base <= destination < base + len(data):
                        wrapper_candidates.append({
                            "caller": hex(caller),
                            "call_target": hex(destination),
                            "arithmetic_stub": hex(base + position),
                            "delta": delta,
                        })
                break
            instruction = next(decoder.disasm(data[offset:offset + 15], base + offset, count=1), None)
            if instruction is None or not instruction.operands:
                break
            operands = instruction.operands
            if operands[0].type != X86_OP_REG or operands[0].reg != X86_REG_EAX:
                break
            name = instruction.mnemonic
            if name in ("neg", "not") and len(operands) == 1:
                value = (-value if name == "neg" else ~value) & mask
            elif len(operands) == 2 and operands[1].type == X86_OP_IMM:
                immediate = operands[1].imm
                if name == "add":
                    value = (value + immediate) & mask
                elif name == "sub":
                    value = (value - immediate) & mask
                elif name == "xor":
                    value = (value ^ immediate) & mask
                elif name in ("rol", "ror"):
                    shift = immediate & 31
                    if name == "rol":
                        value = ((value << shift) | (value >> (32 - shift))) & mask
                    else:
                        value = ((value >> shift) | (value << (32 - shift))) & mask
                else:
                    break
            else:
                break
            operations.append(instruction.mnemonic + " " + instruction.op_str)
            offset += instruction.size
        position = data.find(signature, position + 1)

print(json.dumps({
    "text_sha256": digest,
    "target": hex(args.target),
    "signature_candidates": seen,
    "decoded_stubs": decoded,
    "matches": matched,
    "unverified_wrapper_candidates": wrapper_candidates,
    "limitations": [
        "Only the exact stack/EAX template and listed scalar operations are evaluated.",
        "A matched call and computed destination do not prove runtime reachability.",
        "Wrapper candidates require proving control flow from call_target to arithmetic_stub.",
    ],
}, indent=2))
