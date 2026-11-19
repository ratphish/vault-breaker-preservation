"""Search named offline evidence roots for Marathon manifest paths and field-5 GUIDs."""
import argparse
import base64
import json
import mmap
import os
import re
import sys
from pathlib import Path


GUID = re.compile(rb"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", re.I)
PATH = re.compile(
    r"/(?:[A-Za-z0-9._~-]+/)*content_manifest/[^\s\"'<>\\?#]+?/"
    r"(?P<build>[0-9]+)\.[^/\s\"'<>\\?#]+?_(?P<prefix>[0-9a-f]{16})\.pb"
    r"(?:\?[^\s\"'<>\\]*)?", re.I
)


def offsets(data, needle):
    pos = data.find(needle)
    while pos >= 0:
        yield pos
        pos = data.find(needle, pos + len(needle))


def scan(path, build):
    if path.suffix.lower() == ".har":
        with path.open(encoding="utf-8-sig") as stream:
            entries = json.load(stream)["log"]["entries"]
        for entry in entries:
            url = entry["request"]["url"]
            match = PATH.search(url)
            if not match or match["build"] != build:
                continue
            result = dict(kind="har_request", url=url, guid_prefix=match["prefix"].lower(),
                          status=entry["response"].get("status"))
            content = entry["response"].get("content", {})
            if content.get("encoding") == "base64":
                body = base64.b64decode(content.get("text", ""))
                if len(body) >= 302 and body[:8] == b"\x01" + bytes(7) and body[-38:-36] == b"\x2a\x24" and GUID.fullmatch(body[-36:]):
                    result["response_guid"] = body[-36:].decode().lower()
            yield result
        return
    with path.open("rb") as stream:
        if os.fstat(stream.fileno()).st_size == 0:
            return
        with mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as data:
            for encoding, width in (("ascii", 1), ("utf-16-le", 2)):
                marker = "/content_manifest/".encode(encoding)
                for pos in offsets(data, marker):
                    start = max(0, pos - 256 * width)
                    context = data[start:pos + 2048 * width].decode(encoding, errors="replace")
                    for match in PATH.finditer(context):
                        if match["build"] == build and match.start() <= (pos-start)//width < match.end():
                            yield dict(kind="request_path", offset=pos, path=match[0],
                                       guid_prefix=match["prefix"].lower())
            for pos in offsets(data, b"\x2a\x24"):
                match = GUID.fullmatch(data[pos+2:pos+38])
                if match:
                    # A wire marker inside an arbitrary file is a lead, not build attribution.
                    yield dict(kind="field5_candidate", offset=pos, guid=match[0].decode().lower(),
                               header_at_file_start=data[:8] == b"\x01" + bytes(7),
                               field_ends_at_eof=pos+38 == len(data))


def report_error(error):
    print(error, file=sys.stderr)


def files(root):
    if root.is_file():
        yield root
    elif root.is_dir():
        for folder, _, names in os.walk(root, onerror=report_error, followlinks=False):
            for name in names:
                yield Path(folder, name)
    else:
        report_error(f"Missing root: {root}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build", default="248199")
    parser.add_argument("roots", nargs="+", type=Path)
    args = parser.parse_args()
    count = hits = 0
    for root in args.roots:
        for file in files(root):
            try:
                for hit in scan(file, args.build):
                    print(json.dumps(dict(file=str(file.resolve()), **hit)), flush=True)
                    hits += 1
                count += 1
            except (OSError, ValueError, OverflowError, KeyError, TypeError) as error:
                report_error(f"{file}: {error}")
    print(f"Scanned {count} files; {hits} matches.", file=sys.stderr)
