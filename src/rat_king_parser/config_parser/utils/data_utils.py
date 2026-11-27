#!/usr/bin/env python3
#
# data_utils.py
#
# Author: jeFF0Falltrades
#
# Provides various utility functions for working with binary data
#
# MIT License
#
# Copyright (c) 2024 Jeff Archer
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
from ..config_parser_exception import ConfigParserException


# Converts a bytes object to an int object using the specified byte order
def bytes_to_int(
    data: bytes, order: str = "little", signed: bool = False
) -> int:
    try:
        return int.from_bytes(data, byteorder=order, signed=signed)
    except Exception as e:
        raise ConfigParserException(f"Error parsing int from value: {data}") from e


def _has_invalid_control_chars(text: str) -> bool:
    for ch in text:
        code = ord(ch)
        if (code < 0x20 and ch not in ("\t", "\n", "\r")) or 0x7F <= code <= 0x9F:
            return True
    return False


# Decodes a bytes object to a Unicode string, using UTF-16LE for byte values
# with null bytes still embedded in them, and UTF-8 for all other values
def decode_bytes(byte_str: bytes | str) -> str:
    if isinstance(byte_str, str):
        return byte_str
    if not isinstance(byte_str, (bytes, bytearray)):
        raise ConfigParserException(
            f"Error decoding bytes object to Unicode: {byte_str}"
        )
    try:
        if b"\x00" in byte_str:
            # Distinguish genuine UTF-16LE (even length, predominantly zero high
            # bytes for BMP/ASCII text) from null-padded UTF-8 or random
            # wrong-key ciphertext containing an accidental 0x00 byte.
            utf8_candidate = byte_str.rstrip(b"\x00")
            trailing_null_only = len(utf8_candidate) > 1 and b"\x00" not in utf8_candidate
            is_even = len(byte_str) >= 2 and len(byte_str) % 2 == 0
            odd_nulls = byte_str[1::2].count(0) if is_even else 0
            if (
                is_even
                and not trailing_null_only
                and odd_nulls >= max(1, len(byte_str) // 4)
            ):
                result = byte_str.decode("utf-16le").rstrip("\x00")
                if _has_invalid_control_chars(result):
                    raise ValueError("Decoded UTF-16LE contains control characters")
                return result
            # Fall back to UTF-8 (stripping trailing null terminators)
            if b"\x00" not in utf8_candidate:
                result = utf8_candidate.decode("utf-8")
                if _has_invalid_control_chars(result):
                    raise ValueError("Decoded UTF-8 contains control characters")
                return result
            raise ValueError("Embedded null bytes in non-UTF-16LE buffer")
        result = byte_str.decode("utf-8")
        if _has_invalid_control_chars(result):
            raise ValueError("Decoded UTF-8 contains control characters")
        return result
    except Exception as e:
        raise ConfigParserException(
            f"Error decoding bytes object to Unicode: {byte_str}"
        ) from e


# Converts an int to a bytes object, with the specified length and order
def int_to_bytes(value: int, length: int = 4, order: str = "little") -> bytes:
    try:
        return value.to_bytes(length, order)
    except Exception as e:
        raise ConfigParserException(f"Error parsing bytes from value: {value}") from e
