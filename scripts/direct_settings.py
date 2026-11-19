"""Local Direct Settings transport. This does not implement Tiger's unknown schema."""
import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import unquote, urlsplit


DEFAULT_DIRECTORY = Path(__file__).resolve().parents[1] / "config" / "direct_settings"


@dataclass(frozen=True)
class SettingsResponse:
    status: int
    body: bytes
    document: str = ""
    source: str = ""
    sha256: str = ""


def _error(status, message):
    return SettingsResponse(status, (json.dumps({"error": message}) + "\n").encode())


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON member: " + key)
        result[key] = value
    return result


def _invalid_constant(value):
    raise ValueError("non-JSON constant: " + value)


def load_settings(request_target: str, directory: Path):
    """Return None outside settings routes; never search a second directory.

    JSON syntax is checked, but document shape and client acceptance are unknown.
    Preserve valid bytes verbatim for reproducible experiments.
    """
    path = urlsplit(request_target).path
    if re.match(r"^/cfg_[abc]//", path):
        path = re.sub(r"^(/cfg_[abc])//+", r"\1/", path)
    if not (re.match(r"^/cfg_[abc]/", path) or path.startswith("/direct_settings/")
            or path.startswith("/GolRetail/direct_settings/")):
        return None
    decoded = unquote(path)
    parts = decoded.split("/")[1:]
    if any(part in ("", ".", "..") or "\\" in part for part in parts):
        return _error(400, "invalid_settings_path")
    filename = parts[-1]
    if not re.fullmatch(r"[A-Za-z0-9_-]+\.json", filename):
        return _error(404, "settings_document_not_found")
    root = Path(directory).resolve()
    source = (root / filename).resolve()
    if not source.is_relative_to(root):
        return _error(400, "invalid_settings_path")
    try:
        body = source.read_bytes()
    except FileNotFoundError:
        return _error(404, "settings_document_not_found")
    except OSError:
        return _error(500, "settings_document_unreadable")
    try:
        json.loads(body.decode("utf-8-sig"), object_pairs_hook=_unique_object,
                   parse_constant=_invalid_constant)
    except (UnicodeError, ValueError):
        return _error(500, "settings_document_invalid_json")
    return SettingsResponse(200, body, filename, str(source), hashlib.sha256(body).hexdigest())
