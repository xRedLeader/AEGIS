"""Fixed bounded pipe protocol for the staging relay; contains no network code."""
import json
import os
import struct

PROFILE = "nuclei-passive-http-v3.3.8"
MAX_FRAME = 128 * 1024
MAX_HEADER = 8192
MAX_BODY = 65536


def encode_frame(value):
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("ascii")
    if not 0 < len(raw) <= MAX_FRAME:
        raise ValueError("staging frame exceeds bound")
    return struct.pack("!I", len(raw)) + raw


def write_frame(fd, value):
    view = memoryview(encode_frame(value))
    while view:
        size = os.write(fd, view)
        if size <= 0:
            raise OSError("staging pipe closed")
        view = view[size:]


def decode_frame(raw):
    def number(value):
        if len(value) > 11 or not -(2**31) <= int(value) < 2**31:
            raise ValueError("staging integer exceeds bound")
        return int(value)
    def invalid_number(_):
        raise ValueError("invalid staging number")
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate staging frame field")
            result[key] = value
        return result
    if not 0 < len(raw) <= MAX_FRAME:
        raise ValueError("staging frame exceeds bound")
    try:
        value = json.loads(raw.decode("ascii"), object_pairs_hook=unique, parse_int=number,
                           parse_float=invalid_number, parse_constant=invalid_number)
    except RecursionError as exc:
        raise ValueError("staging frame nesting denied") from exc
    if (not isinstance(value, dict) or len(value) > 8 or
            any(not key.isascii() or len(key) > 32 or type(item) not in (str,int,bool) for key,item in value.items())):
        raise ValueError("staging frame must contain bounded flat scalar fields")
    return value


def read_frame(fd):
    def exact(size):
        parts = bytearray()
        while len(parts) < size:
            chunk = os.read(fd, size - len(parts))
            if not chunk:
                raise EOFError("staging parent pipe closed")
            parts.extend(chunk)
        return bytes(parts)
    size = struct.unpack("!I", exact(4))[0]
    if not 0 < size <= MAX_FRAME:
        raise ValueError("staging frame exceeds bound")
    return decode_frame(exact(size))
