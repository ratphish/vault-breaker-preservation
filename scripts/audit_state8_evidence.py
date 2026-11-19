"""Audit saved bytes and address mappings; never attach to or launch a process.

Requires Capstone. All table roles remain hypotheses until dispatch is traced.
"""
import argparse
from collections import deque
import hashlib
import json
import mmap
from pathlib import Path
import re
import struct

from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_GRP_CALL, CS_GRP_JUMP, CS_GRP_RET
from capstone.x86_const import X86_OP_IMM


def digest(data):
    return hashlib.sha256(data).hexdigest()


def flow(data, start_rva, entry_rva, image_size):
    """Decode reachable local branches, including targets after an earlier ret.

    Call fallthroughs are possibilities, not proof that callees return. Never
    recursively decode unknown call destinations or linear bytes after a ret.
    """
    decoder = Cs(CS_ARCH_X86, CS_MODE_64)
    decoder.detail = True
    queue, seen, rows = deque([entry_rva]), set(), []
    while queue and len(seen) < 128:
        pc = queue.popleft()
        if pc in seen:
            continue
        seen.add(pc)
        offset = pc - start_rva
        if not 0 <= offset < len(data):
            rows.append({"rva": hex(pc), "status": "outside_capture"})
            continue
        instruction = next(decoder.disasm(data[offset:offset + 15], pc, count=1), None)
        if instruction is None:
            rows.append({"rva": hex(pc), "status": "undecodable"})
            continue
        call = instruction.group(CS_GRP_CALL)
        jump = instruction.group(CS_GRP_JUMP)
        ret = instruction.group(CS_GRP_RET)
        target = (instruction.operands[0].imm if (call or jump) and instruction.operands
                  and instruction.operands[0].type == X86_OP_IMM else None)
        row = {"rva": hex(pc), "instruction": instruction.mnemonic + " " + instruction.op_str,
               "bytes": instruction.bytes.hex()}
        if target is not None:
            row["call_target" if call else "branch_target"] = hex(target)
            row["target_within_pe_image"] = 0 <= target < image_size
            if jump:
                queue.append(target)
        if not ret and instruction.mnemonic not in ("jmp", "int3", "ud2"):
            queue.append(pc + instruction.size)
        rows.append(row)
    return {"instructions": sorted(rows, key=lambda row: int(row["rva"], 16)),
            "budget_exhausted": bool(queue), "runtime_observed": False}


def image_size(path):
    with path.open("rb") as stream:
        if stream.read(2) != b"MZ":
            raise ValueError("not a PE file")
        stream.seek(0x3c)
        header = struct.unpack("<I", stream.read(4))[0]
        stream.seek(header)
        if stream.read(4) != b"PE\0\0":
            raise ValueError("invalid PE signature")
        stream.seek(header + 24)
        if stream.read(2) != b"\x0b\x02":
            raise ValueError("expected PE32+")
        stream.seek(header + 24 + 56)
        return struct.unpack("<I", stream.read(4))[0]


def text_candidates(path, size):
    """Bounded syntactic RIP candidates in an explicitly supplied .text image.

    This finds anchors, not proven instruction boundaries or runtime references.
    .text file offset zero maps to RVA 0x1000 in this build.
    """
    targets = {0x32da1d68, 0x32da1e70, 0x32da2ca0, 0x32da2e10,
               0x32da2728, 0x32da2a80, 0x32da8f28, 0x32d28fc8, 0x32d28f30}
    pattern = re.compile(rb'[\x48-\x4f][\x8d\x8b][\x05\x0d\x15\x1d\x25\x2d\x35\x3d][\s\S]{4}')
    rows = []
    with path.open('rb') as stream:
        sha256 = hashlib.file_digest(stream, 'sha256').hexdigest()
        with mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as data:
            for match in pattern.finditer(data):
                rva = match.start() + 0x1000
                target = rva + 7 + struct.unpack_from('<i', match.group(), 3)[0]
                if target in targets:
                    rows.append({'rva': hex(rva), 'rip_target': hex(target),
                                 'local_flow': flow(data[match.start():match.start() + 96], rva, rva, size)})
    return {'path': str(path.resolve()), 'sha256': sha256, 'file_offset_zero_rva': '0x1000',
            'authority': 'synthetic model; does not establish authentic runtime code',
            'candidates': rows}


def audit(directory, pe_path, base, text_image=None):
    size = image_size(pe_path)
    artifacts = {}
    manifest_path = directory / 'capture-manifest.json'
    manifest = json.loads(manifest_path.read_text(encoding='utf-8')) if manifest_path.exists() else None
    if manifest:
        if manifest['status'] != 'complete':
            raise ValueError('capture manifest is incomplete')
        if int(manifest['image_base'], 16) != base or int(manifest['image_size'], 16) != size:
            raise ValueError('capture base or image size differs')
        with pe_path.open('rb') as stream:
            if hashlib.file_digest(stream, 'sha256').hexdigest() != manifest['executable_sha256']:
                raise ValueError('PE digest differs from the captured executable')
    captured_ranges = {row['file']: row for row in manifest['ranges']} if manifest else {}

    def load(filename, start, required=True):
        path = directory / filename
        if not required and not path.exists():
            if filename in captured_ranges:
                raise ValueError('recorded capture file is missing: ' + filename)
            return None
        data = path.read_bytes()
        if manifest:
            recorded = captured_ranges.get(filename)
            if (recorded is None or int(recorded['rva'], 16) != start
                    or recorded['bytes'] != len(data) or recorded['sha256'] != digest(data)):
                raise ValueError('capture range or digest differs: ' + filename)
        artifacts[filename] = {"path": str(path.resolve()), "bytes": len(data),
                               "sha256": digest(data), "start_rva": hex(start)}
        return data

    area = load("mem_area_30280000.bin", 0x30280000)
    if len(area) < 0x11280:
        raise ValueError("truncated 0x30280000 capture")
    entry = load("mem_func_state8_2EF4C7E0.bin", 0x2ef4c7e0)
    table = load("mem_bootflow_table.bin", 0x32da1690)
    if len(table) < 0x1840:
        raise ValueError("truncated table capture")
    candidate_tables = []
    for rva in (0x32da1d68, 0x32da1e70, 0x32da2ca0, 0x32da2e10):
        values = []
        for index in range(21):
            offset = rva - 0x32da1690 + index * 8
            raw = table[offset:offset + 8]
            value = struct.unpack("<Q", raw)[0]
            relative = value - base
            values.append({"index": index, "pointer": hex(value), "rva": hex(relative),
                           "within_pe_image": 0 <= relative < size,
                           "printable_bytes": "".join(chr(b) for b in raw if 32 <= b < 127)})
        candidate_tables.append({"rva": hex(rva), "role": "unverified", "entries": values})
    strings = []
    for center in (0x32d28f30, 0x32da9b86, 0x32dc701c):
        filename = f"mem_direct_settings_{center:X}.bin"
        start = center - 0x200  # Verified in the existing dump writer.
        data = load(filename, start, required=False)
        if data is None:
            continue
        for match in re.finditer(rb"[ -~]{4,}", data):
            strings.append({"artifact": filename, "rva": hex(start + match.start()),
                            "value": match.group().decode("ascii")})
    callees = []
    for rva in (0x0ea73f44, 0x2ef4070b, 0x224a0999, 0x198b4bf8, 0x0c4e9e70):
        # These files are produced only by the new user-run capture tool.
        prefix = 'candidate_entry_call_' if rva in (0x0ea73f44, 0x2ef4070b) else 'candidate_check_call_'
        data = load(f'{prefix}{rva:08X}.bin', rva, required=False)
        if data is not None:
            callees.append({'rva': hex(rva), 'local_flow': flow(data, rva, rva, size)})
    result = {
        "format_version": 1, "authority": "saved-captures; capture provenance not independently verified",
        "manifest_integrity_checked": bool(manifest),
        "assumed_capture_image_base": hex(base), "pe_image_size": hex(size),
        "artifacts": artifacts,
        "candidate_entry": flow(entry[:16], 0x2ef4c7e0, 0x2ef4c7e0, size),
        "candidate_check": flow(area[0x11240:0x11280], 0x30291240, 0x30291240, size),
        "adjacent_xor_helper": flow(entry[16:49], 0x2ef4c7f0, 0x2ef4c7f0, size),
        "candidate_tables": candidate_tables, "direct_settings_strings": strings,
        "captured_candidate_callees": callees,
        "conclusions": {
            "stage8_dispatch_verified": False, "edx_is_task_count_verified": False,
            "stage_advance_target_verified": False, "xor_is_session_integrity_verified": False,
            "settings_schema_verified": False,
            "reason": "Names and adjacent pointer arrays do not establish dispatch. Register meaning and callee effects require caller/callee evidence.",
        },
    }
    if text_image:
        result['synthetic_text_candidates'] = text_candidates(text_image, size)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dump-dir", type=Path, required=True)
    parser.add_argument("--pe", type=Path, required=True)
    parser.add_argument("--image-base", type=lambda value: int(value, 0), required=True,
                        help="Base recorded for this capture, not the preferred on-disk base")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--synthetic-text", type=Path,
                        help="Optional prior model's .text section image; never treated as runtime evidence")
    args = parser.parse_args()
    report = json.dumps(audit(args.dump_dir, args.pe, args.image_base, args.synthetic_text), indent=2) + "\n"
    if args.output:
        with args.output.open("x", encoding="utf-8") as stream:
            stream.write(report)
    else:
        print(report, end="")


if __name__ == "__main__":
    main()
