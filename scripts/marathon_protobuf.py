"""Minimal, pure-Python Google Protobuf encoder and decoder matching Project Dawn's Writer.

Implements varints (wire type 0) and length-delimited records (wire type 2)
used by Bungie Tiger Engine SignOn and web service envelopes.
Zero external dependencies.
"""
from typing import List, Tuple, Dict, Any, Union
import struct

WIRE_VARINT = 0
WIRE_FIXED64 = 1
WIRE_LENGTH_DELIMITED = 2
WIRE_FIXED32 = 5

def encode_varint(value: int) -> bytes:
    """Encode an integer into unsigned LEB128 varint bytes."""
    if value < 0:
        # Standard Protobuf two's complement for 64-bit int
        value = (1 << 64) + value
    out = bytearray()
    while True:
        bits = value & 0x7F
        value >>= 7
        if value:
            out.append(bits | 0x80)
        else:
            out.append(bits)
            break
    return bytes(out)

def decode_varint(buffer: bytes, offset: int = 0) -> Tuple[int, int]:
    """Decode an unsigned LEB128 varint from buffer at offset.
    Returns (value, new_offset).
    """
    result = 0
    shift = 0
    pos = offset
    while pos < len(buffer):
        b = buffer[pos]
        pos += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            return result, pos
        shift += 7
        if shift > 64:
            raise ValueError("Varint exceeds 64-bit bounds")
    raise ValueError("Truncated varint in buffer")

class ProtobufWriter:
    """Encodes protobuf fields matching Dawn's Writer."""
    def __init__(self):
        self.buf = bytearray()

    def tag(self, field_number: int, wire_type: int) -> None:
        self.buf.extend(encode_varint((field_number << 3) | wire_type))

    def varint(self, field_number: int, value: int) -> "ProtobufWriter":
        self.tag(field_number, WIRE_VARINT)
        self.buf.extend(encode_varint(value))
        return self

    def bytes(self, field_number: int, data: Union[bytes, bytearray, memoryview]) -> "ProtobufWriter":
        self.tag(field_number, WIRE_LENGTH_DELIMITED)
        self.buf.extend(encode_varint(len(data)))
        self.buf.extend(data)
        return self

    def string(self, field_number: int, text: str) -> "ProtobufWriter":
        return self.bytes(field_number, text.encode("utf-8"))

    def fixed64(self, field_number: int, value: int) -> "ProtobufWriter":
        self.tag(field_number, WIRE_FIXED64)
        self.buf.extend(struct.pack("<Q", value))
        return self

    def fixed32(self, field_number: int, value: int) -> "ProtobufWriter":
        self.tag(field_number, WIRE_FIXED32)
        self.buf.extend(struct.pack("<I", value))
        return self

    def message(self, field_number: int, sub_writer: "ProtobufWriter") -> "ProtobufWriter":
        return self.bytes(field_number, sub_writer.build())

    def build(self) -> bytes:
        return bytes(self.buf)

class ProtobufReader:
    """Simple parser for decoding protobuf wire fields."""
    def __init__(self, data: bytes):
        self.data = data

    def parse(self) -> List[Tuple[int, int, Any]]:
        """Parse into list of (field_number, wire_type, raw_value)."""
        fields = []
        pos = 0
        length = len(self.data)
        while pos < length:
            tag, pos = decode_varint(self.data, pos)
            field_num = tag >> 3
            wire_type = tag & 0x07
            if wire_type == WIRE_VARINT:
                val, pos = decode_varint(self.data, pos)
                fields.append((field_num, wire_type, val))
            elif wire_type == WIRE_LENGTH_DELIMITED:
                size, pos = decode_varint(self.data, pos)
                if pos + size > length:
                    raise ValueError(f"Length delimited field {field_num} extends beyond buffer: {pos + size} > {length}")
                raw_bytes = self.data[pos:pos+size]
                pos += size
                fields.append((field_num, wire_type, raw_bytes))
            elif wire_type == WIRE_FIXED64:
                if pos + 8 > length:
                    raise ValueError(f"Fixed64 field {field_num} extends beyond buffer: {pos + 8} > {length}")
                raw_bytes = self.data[pos:pos+8]
                pos += 8
                fields.append((field_num, wire_type, raw_bytes))
            elif wire_type == WIRE_FIXED32:
                if pos + 4 > length:
                    raise ValueError(f"Fixed32 field {field_num} extends beyond buffer: {pos + 4} > {length}")
                raw_bytes = self.data[pos:pos+4]
                pos += 4
                fields.append((field_num, wire_type, raw_bytes))
            else:
                raise NotImplementedError(f"Unsupported wire type {wire_type} for field {field_num}")
        return fields
