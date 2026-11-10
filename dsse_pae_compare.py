"""Compare the signing-input bytes of two saved DSSE fixtures."""
import base64
import json
import os
import posixpath
import re
import stat
import sys
from typing import NamedTuple

MAX_FILE = 256 * 1024
MAX_PAYLOAD = 128 * 1024
MAX_TYPE = 4096
BASE64 = re.compile(r"[A-Za-z0-9+/_-]*={0,2}")
DEVICE = re.compile(r"CON|PRN|AUX|NUL|CONIN\$|CONOUT\$|(?:COM|LPT)[0-9¹²³]")
NATIVE_ROOTS = {"??", "device", "dosdevices", "global??", "systemroot", "globalroot"}


class Fixture(NamedTuple):
    type_utf8: bytes
    legacy_type: bytes
    payload: bytes


def check_path(path):
    spelling = path.replace("\\", "/")
    if not spelling or spelling == "-" or spelling.startswith("//") or spelling.endswith("/"):
        raise ValueError
    if any(ord(char) < 32 for char in spelling):
        raise ValueError
    if spelling.startswith("/"):
        for form in (spelling, posixpath.normpath(spelling)):
            if form[1:].partition("/")[0].rstrip(" .").lower() in NATIVE_ROOTS:
                raise ValueError
    tail = spelling[2:] if re.match(r"^[A-Za-z]:/", spelling) else spelling
    if ":" in tail:
        raise ValueError
    for part in tail.split("/"):
        if part in {"", ".", ".."}:
            continue
        stem = part.partition(".")[0].rstrip(" ").upper()
        if part.endswith((" ", ".")) or DEVICE.fullmatch(stem):
            raise ValueError


def check_file(info):
    if not stat.S_ISREG(info.st_mode) or not 0 <= info.st_size <= MAX_FILE:
        raise ValueError


def read_fixture(path):
    check_file(os.stat(path))
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NONBLOCK", 0)
    descriptor = os.open(path, flags)
    try:
        check_file(os.fstat(descriptor))
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            data = stream.read(MAX_FILE + 1)
    finally:
        os.close(descriptor)
    if len(data) > MAX_FILE:
        raise ValueError
    return parse_fixture(data)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        key.encode("utf-8")
        if key in result:
            raise ValueError
        result[key] = value
    return result


def invalid_constant(_text):
    raise ValueError


def ignored_number(_text):
    # Neither selected field can be numeric. Other fields need syntax only.
    return None


def decode_payload(value):
    if not isinstance(value, str) or BASE64.fullmatch(value) is None:
        raise ValueError
    url_safe = "-" in value or "_" in value
    if url_safe and ("+" in value or "/" in value):
        raise ValueError
    padded = value + "=" * (-len(value) % 4) if "=" not in value else value
    alphabet = b"-_" if url_safe else None
    payload = base64.b64decode(padded, altchars=alphabet, validate=True)
    canonical = base64.b64encode(payload, altchars=alphabet).decode("ascii")
    if len(payload) > MAX_PAYLOAD or value not in (canonical, canonical.rstrip("=")):
        raise ValueError
    return payload


def parse_fixture(data):
    document = json.loads(data.decode("utf-8"), object_pairs_hook=unique_object,
                          parse_constant=invalid_constant, parse_int=ignored_number, parse_float=ignored_number)
    pending = [document]
    while pending:
        value = pending.pop()
        if isinstance(value, dict):
            pending.extend(value.values())
        elif isinstance(value, list):
            pending.extend(value)
        elif isinstance(value, str):
            value.encode("utf-8")
    if not isinstance(document, dict) or not isinstance(document.get("payloadType"), str):
        raise ValueError
    type_text = document["payloadType"]
    type_utf8 = type_text.encode("utf-8")
    if len(type_utf8) > MAX_TYPE:
        raise ValueError
    legacy_type = type_text.encode("utf-16-le")[::2]
    return Fixture(type_utf8, legacy_type, decode_payload(document.get("payload")))


def pae(type_bytes, payload):
    return b" ".join((b"DSSEv1", str(len(type_bytes)).encode("ascii"), type_bytes,
                      str(len(payload)).encode("ascii"), payload))


def compare(left, right):
    same = pae(left.type_utf8, left.payload) == pae(right.type_utf8, right.payload)
    legacy_collision = not same and pae(left.legacy_type, left.payload) == pae(right.legacy_type, right.payload)
    return {"status": "same" if same else "different", "type_same": left.type_utf8 == right.type_utf8,
            "payload_same": left.payload == right.payload, "legacy_collision": legacy_collision,
            "type_utf8_bytes": [len(left.type_utf8), len(right.type_utf8)]}


def emit(data, code):
    remaining = memoryview(data)
    try:
        while remaining:
            written = os.write(1, remaining)
            if written <= 0:
                return 2
            remaining = remaining[written:]
    except OSError:
        return 2
    return code


def main(args):
    if args in (["--help"], ["-h"]):
        return emit(b"Usage: python dsse_pae_compare.py LEFT.json RIGHT.json\n", 0)
    try:
        left, right = args
        for path in args:
            check_path(path)
        report = compare(read_fixture(left), read_fixture(right))
        code = int(report["status"] == "different")
    except (ValueError, OSError, RecursionError):
        report, code = {"status": "invalid"}, 2
    return emit(json.dumps(report, separators=(",", ":")).encode("ascii") + b"\n", code)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
