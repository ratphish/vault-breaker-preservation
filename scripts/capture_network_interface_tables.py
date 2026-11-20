"""Read the preserved client's two networking interface tables."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import struct

from capture_http_state import Process
from observe_settings_startup import ANALYSIS, GAME, PINNED_EXE_SHA256


def capture(pid):
    process = Process(pid)
    try:
        modules = process.modules()
        image = modules[0]
        path = Path(image["path"]).resolve()
        isolated = ANALYSIS.parent / "client-248199-retail-packages" / "Marathon.exe"
        if path not in (GAME.resolve(), isolated.resolve()):
            raise ValueError(f"Unexpected executable: {path}")
        with path.open("rb") as stream:
            if hashlib.file_digest(stream, "sha256").hexdigest() != PINNED_EXE_SHA256:
                raise ValueError("Executable hash differs from the pinned build")
        base = int(image["base"], 16)

        def pointer(address):
            return struct.unpack("<Q", process.read(address, 8))[0]

        def location(address):
            for module in modules:
                start = int(module["base"], 16)
                if start <= address < start + module["size"]:
                    return {"module": module["path"], "rva": hex(address - start)}
            return {"address": hex(address)}

        result = {"pid": pid, "image": str(path), "utc": datetime.now(timezone.utc).isoformat()}
        for name, global_rva, last_slot in (
            ("sockets", 0x365C0140, 0x180), ("utils", 0x365C0148, 0xB8)
        ):
            receiver = pointer(base + global_rva)
            if not receiver:
                raise ValueError(f"{name} interface is not initialized")
            table = pointer(receiver)
            data = process.read(table, last_slot + 8)
            slots = {hex(offset): location(struct.unpack_from("<Q", data, offset)[0])
                     for offset in range(0, len(data), 8)}
            if pointer(base + global_rva) != receiver or pointer(receiver) != table:
                raise ValueError(f"{name} interface changed during capture")
            result[name] = {"receiver": hex(receiver), "vtable": location(table), "slots": slots}
        return result
    finally:
        process.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pid", required=True, type=int)
    result = capture(parser.parse_args().pid)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    output = ANALYSIS / f"network-interface-tables-{result['pid']}-{stamp}.json"
    with output.open("x", encoding="utf-8") as stream:
        json.dump(result, stream, indent=2)
    for name, slot in (("sockets", "0xa8"), ("utils", "0xb8")):
        print(name, slot, result[name]["slots"][slot])
    print("Saved to", output)
