"""Check the isolated client's mode-2 publication against the offline replay."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import time

from capture_http_state import Process
from observe_settings_startup import ANALYSIS, PINNED_EXE_SHA256
from readonly_reference import decode_reference
from unicorn import UcError


EXPECTED = "713023a45a38babcf72d57eb12b9e9021d5679c1da3108b025a7e7b1272e2741"
IMAGE = ANALYSIS.parent / "client-248199-retail-packages" / "Marathon.exe"


def capture_chain(process, image, pid, seconds):
    base = int(image["base"], 16)
    ref_rva = 0x3658D650
    ref_address = base + ref_rva
    sockets_address = base + 0x365C0140
    output_address = base + 0x365BFF19
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    output = ANALYSIS / f"identity-chain-{pid}-{stamp}.jsonl"
    previous_ref = None
    provider = None
    previous = None
    deadline = time.monotonic() + seconds
    matched = False

    def read_fields(sockets, provider):
        identity = process.read(sockets + 0x65C, 136) if sockets else None
        cache = process.read(provider + 0x1F, 86) if provider else None
        return identity, cache, process.read(output_address, 87)

    with output.open("x", encoding="utf-8") as stream:
        print("Sampling. Use normal sign-in. Evidence:", output, flush=True)
        while True:
            try:
                ref = process.read(ref_address, 24)
                if ref != previous_ref:
                    provider = None
                    if any(ref[:8]):
                        provider, _ = decode_reference(process.read, base, image["size"], ref, ref_rva)
                    previous_ref = ref
                pointer = process.read(sockets_address, 8)
                sockets = int.from_bytes(pointer, "little")
                fields = read_fields(sockets, provider)
                if (fields != read_fields(sockets, provider)
                        or ref != process.read(ref_address, 24)
                        or pointer != process.read(sockets_address, 8)):
                    row = {"status": "changed_during_read"}
                else:
                    identity, cache, pub = fields
                    kind = int.from_bytes(identity[:4], "little", signed=True) if identity else None
                    name = None
                    if kind == 2:
                        length = int.from_bytes(identity[4:8], "little")
                        name = identity[8:8+min(length, 128)].split(b"\0", 1)[0].decode("utf-8", "replace")
                    digest = hashlib.sha256(pub[1:]).hexdigest()
                    row = dict(status="sample", sockets=hex(sockets), identity_type=kind,
                               identity_name=name, provider=hex(provider) if provider else None,
                               cache_hex=cache.hex() if cache is not None else None,
                               cache_empty=not any(cache) if cache is not None else None,
                               cache_equals_output=cache == pub[1:] if cache is not None else None,
                               presence=pub[0], record_hex=pub[1:].hex(), record_sha256=digest,
                               matches_replay=bool(pub[0]) and digest == EXPECTED)
                    matched |= row["matches_replay"]
            except (OSError, ValueError, UcError) as exc:
                previous_ref = None
                row = {"status": "unreadable", "detail": str(exc)}
            if row != previous:
                entry = dict(pid=pid, utc=datetime.now(timezone.utc).isoformat(), **row)
                stream.write(json.dumps(entry) + "\n")
                stream.flush()
                print(entry["utc"], row["status"], "type", row.get("identity_type"),
                      "presence", row.get("presence"), "matches replay", row.get("matches_replay"), flush=True)
                previous = row
            if time.monotonic() >= deadline:
                return matched
            time.sleep(0.1)


def verify(pid, seconds, chain=False):
    process = Process(pid)
    try:
        image = process.modules()[0]
        if Path(image["path"]).resolve() != IMAGE.resolve():
            raise ValueError("Expected the isolated preserved client")
        with IMAGE.open("rb") as stream:
            if hashlib.file_digest(stream, "sha256").hexdigest() != PINNED_EXE_SHA256:
                raise ValueError("Unexpected client build")
        if chain:
            return capture_chain(process, image, pid, seconds)
        address = int(image["base"], 16) + 0x365BFF19
        deadline = time.monotonic() + seconds
        last = None
        while True:
            sample = process.read(address, 87)
            digest = hashlib.sha256(sample[1:]).hexdigest()
            matched = sample[0] != 0 and digest == EXPECTED
            if matched and process.read(address, 87) != sample:
                continue
            if sample != last:
                print(json.dumps(dict(pid=pid, presence=sample[0], record_sha256=digest,
                                      matches_replay=matched)), flush=True)
                last = sample
            if matched:
                return True
            if time.monotonic() >= deadline:
                return False
            time.sleep(0.1)
    finally:
        process.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pid", type=int, required=True)
    parser.add_argument("--seconds", type=int, default=90)
    parser.add_argument("--chain", action="store_true", help="Record identity, cache and output changes together")
    args = parser.parse_args()
    raise SystemExit(0 if verify(args.pid, args.seconds, args.chain) else 1)
