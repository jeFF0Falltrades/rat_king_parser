#!/usr/bin/env python3
#
# config_item.py
#
# Author: jeFF0Falltrades
#
# Provides a utility class for parsing field names and values of various types
# from raw RAT config data
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
from abc import ABC, abstractmethod
from collections.abc import Callable
from logging import getLogger
from re import DOTALL, Pattern, compile, findall
from typing import Any, Tuple

from .data_utils import bytes_to_int
from .dotnet_constants import (
    MDT_FIELD_DEF,
    MDT_STRING,
    OPCODE_LDC_I4_0,
    SpecialFolder,
)

logger = getLogger(__name__)

# ECMA-335 FieldSig primitive integer element types (I1, U1, I2, U2, I4, U4, I8, U8)
_PRIMITIVE_INT_ELEMENT_TYPES = frozenset({0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B})


def _build_cil_operand_sizes() -> tuple[dict[int, int], dict[int, int]]:
    """Build ECMA-335 Partition III single-byte and 0xFE-prefixed CIL operand byte sizes."""
    single: dict[int, int] = {}
    # 0-byte operand ranges
    for op in range(0x00, 0x0E):  # nop..stloc.3
        single[op] = 0
    for op in range(0x14, 0x1F):  # ldnull, ldc.i4.m1..ldc.i4.8
        single[op] = 0
    for op in (0x25, 0x26, 0x2A):  # dup, pop, ret
        single[op] = 0
    for op in range(0x46, 0x6F):  # ldind.*, stind.*, add..conv.u8
        single[op] = 0
    single[0x76] = 0  # conv.r.un
    single[0x7A] = 0  # throw
    for op in range(0x82, 0x8C):  # conv.ovf.*
        single[op] = 0
    for op in range(0x8E, 0xA3):  # ldlen, ldelem.*, stelem.* (excluding 0x8F ldelema)
        single[op] = 0
    single[0x8F] = 4  # ldelema <typeTok>
    for op in range(0xB3, 0xC6):  # conv.ovf.*.un, ckfinite
        single[op] = 0
    for op in range(0xD1, 0xDD):  # conv.u2..endfinally, conv.i..conv.u
        single[op] = 0
    single[0xDC] = 0  # endfinally / endfault
    single[0xDF] = 0  # stind.i
    single[0xE0] = 0  # conv.u

    # 1-byte operand opcodes
    for op in range(0x0E, 0x14):  # ldarg.s..stloc.s
        single[op] = 1
    single[0x1F] = 1  # ldc.i4.s
    for op in range(0x2B, 0x38):  # br.s..blt.un.s
        single[op] = 1
    single[0xDE] = 1  # leave.s

    # 4-byte operand opcodes
    single[0x20] = 4  # ldc.i4
    single[0x22] = 4  # ldc.r4
    for op in (0x27, 0x28, 0x29):  # jmp, call, calli
        single[op] = 4
    for op in range(0x38, 0x45):  # br..blt.un
        single[op] = 4
    for op in (0x6F, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75):  # callvirt..isinst
        single[op] = 4
    for op in range(0x7B, 0x82):  # ldfld..stobj
        single[op] = 4
    for op in (0x8C, 0x8D):  # box, newarr
        single[op] = 4
    for op in (0xA3, 0xA4, 0xA5):  # ldelem, stelem, unbox.any
        single[op] = 4
    for op in (0xC2, 0xC6, 0xD0, 0xDD):  # refanyval, mkrefany, ldtoken, leave
        single[op] = 4
    single[0x79] = 4  # unbox

    # 8-byte operand opcodes
    single[0x21] = 8  # ldc.i8
    single[0x23] = 8  # ldc.r8

    # 0xFE two-byte opcodes
    two_byte: dict[int, int] = {
        0x00: 0,  # arglist
        0x01: 0,  # ceq
        0x02: 0,  # cgt
        0x03: 0,  # cgt.un
        0x04: 0,  # clt
        0x05: 0,  # clt.un
        0x06: 4,  # ldftn
        0x07: 4,  # ldvirtftn
        0x09: 2,  # ldarg
        0x0A: 2,  # ldarga
        0x0B: 2,  # starg
        0x0C: 2,  # ldloc
        0x0D: 2,  # ldloca
        0x0E: 2,  # stloc
        0x0F: 0,  # localloc
        0x11: 0,  # endfilter
        0x12: 1,  # unaligned.
        0x13: 0,  # volatile.
        0x14: 0,  # tail.
        0x15: 4,  # initobj
        0x16: 4,  # constrained.
        0x17: 0,  # cpblk
        0x18: 0,  # initblk
        0x19: 1,  # no.
        0x1A: 0,  # rethrow
        0x1C: 4,  # sizeof
        0x1D: 0,  # refanytype
        0x1E: 0,  # readonly.
    }
    return single, two_byte


_CIL_OP_SIZES, _CIL_FE_OP_SIZES = _build_cil_operand_sizes()


def _extract_cil_il_bytes(method_body: bytes) -> bytes | None:
    """Strip the tiny or fat CIL method header and return the IL byte stream."""
    if not method_body:
        return None
    flags = method_body[0]
    fmt = flags & 0x03
    if fmt == 2:  # Tiny header: 1 byte
        code_size = flags >> 2
        if 1 + code_size <= len(method_body):
            return method_body[1 : 1 + code_size]
        return None
    if fmt == 3 and len(method_body) >= 12:  # Fat header
        flags16 = int.from_bytes(method_body[0:2], "little")
        header_size = ((flags16 >> 12) & 0x0F) * 4
        if header_size < 12:
            return None
        code_size = int.from_bytes(method_body[4:8], "little")
        if header_size <= len(method_body) and header_size + code_size <= len(method_body):
            return method_body[header_size : header_size + code_size]
        return None
    return None


def _decode_cil_instructions(il: bytes) -> list[tuple[int, bytes]] | None:
    """Decode CIL IL bytes into a list of (opcode, operand_bytes) tuples.

    Returns None if an unknown or truncated instruction is encountered so the
    caller can fall back to regex-based extraction.
    """
    instructions: list[tuple[int, bytes]] = []
    pos = 0
    end = len(il)
    while pos < end:
        op = il[pos]
        pos += 1
        if op == 0xFE:
            if pos >= end:
                return None
            op2 = il[pos]
            pos += 1
            size = _CIL_FE_OP_SIZES.get(op2)
            if size is None or pos + size > end:
                return None
            instructions.append((0xFE00 | op2, il[pos : pos + size]))
            pos += size
        elif op == 0x45:  # switch <uint32 count> <int32 targets[count]>
            if pos + 4 > end:
                return None
            count = int.from_bytes(il[pos : pos + 4], "little")
            total = 4 + count * 4
            if pos + total > end:
                return None
            instructions.append((op, il[pos : pos + total]))
            pos += total
        else:
            size = _CIL_OP_SIZES.get(op)
            if size is None or pos + size > end:
                return None
            instructions.append((op, il[pos : pos + size]))
            pos += size
    return instructions


def _ldc_i4_value(op: int, operand: bytes) -> int | None:
    if op == 0x15:  # ldc.i4.m1
        return -1
    if 0x16 <= op <= 0x1E:  # ldc.i4.0 .. ldc.i4.8
        return op - 0x16
    if op == 0x1F:  # ldc.i4.s
        return int.from_bytes(operand, "little", signed=True)
    if op == 0x20:  # ldc.i4
        return int.from_bytes(operand, "little", signed=True)
    return None


def _is_primitive_int_field(field_sig: bytes | None) -> bool:
    return bool(
        field_sig
        and len(field_sig) >= 2
        and field_sig[0] == 0x06
        and field_sig[1] in _PRIMITIVE_INT_ELEMENT_TYPES
    )


# Provides an abstract class for config items
class ConfigItem(ABC):
    _compiled_pattern: Pattern[bytes]

    def __init__(self, label: str, pattern: bytes) -> None:
        self._label = label
        self._pattern = compile(pattern, flags=DOTALL)

    # Should be overridden by children to provide a meaningful value
    @abstractmethod
    def _derive_item_value(self, raw_value: bytes) -> Any:
        pass

    # Derives config Field RVAs and values from data using the specified
    # ConfigItem's pattern
    def parse_from(self, data: bytes) -> dict[int, Any]:
        logger.debug("Parsing %s values from data...", self._label)
        fields = {}
        raw_data = findall(self._pattern, data)
        found_items = 0
        for obj, bytes_rva in raw_data:
            try:
                field_value = self._derive_item_value(obj)
                field_rva = bytes_to_int(bytes_rva)
            except Exception:
                logger.debug(
                    "Could not parse value from %r at %s", obj, bytes_rva.hex()
                )
                continue
            if field_rva not in fields:
                fields[field_rva] = field_value
                found_items += 1
            else:
                logger.debug(
                    "Overlapping Field RVAs detected in config at %s", hex(field_rva)
                )
        logger.debug("Parsed %d %s values", found_items, self._label)
        return fields


class BoolConfigItem(ConfigItem):
    def __init__(self) -> None:
        super().__init__("boolean", b"(\x16|\x17)\x80(.{3}\x04)")

    # Boolean values are derived by examing if the opcode is "ldc.i4.0" (False)
    # or "ldc.i4.1" (True)
    def _derive_item_value(self, opcode: bytes) -> bool:
        return bool(bytes_to_int(opcode) - bytes_to_int(OPCODE_LDC_I4_0))


class ByteArrayConfigItem(ConfigItem):
    def __init__(self) -> None:
        super().__init__(
            "byte array",
            rb"\x1f(.\x8d.{3}\x01\x25\xd0.{3}\x04)\x28.{3}\x0a\x80(.{3}\x04)",
        )

    # Byte array size and RVA are returned, as these are needed to
    # extract the value of the bytes from the payload
    def _derive_item_value(self, byte_data: bytes) -> Tuple[int, int]:
        arr_size = byte_data[0]
        arr_rva = bytes_to_int(byte_data[-4:])
        return (arr_size, arr_rva)


class IntConfigItem(ConfigItem):
    def __init__(self) -> None:
        super().__init__("int", b"(\x20.{4}|[\x15\x18-\x1e])\x80(.{3}\x04)")

    def _derive_item_value(self, int_bytes: bytes) -> int:
        # If single byte, handle ldc.i4.m1 (0x15) and ldc.i4.2-8 (0x18-0x1e)
        # Subtract 0x16 to get the int value, e.g.:
        # ldc.i4.8 == 0x1e - 0x16 == 8
        if len(int_bytes) == 1:
            return bytes_to_int(int_bytes) - 0x16
        # Else, look for which signed int32 was loaded by "ldc.i4"
        return bytes_to_int(int_bytes[1:], signed=True)


class NullConfigItem(ConfigItem):
    def __init__(self) -> None:
        super().__init__("null", b"(\x14\x80)(.{3}\x04)")

    # If "ldnull" is being used, simply return "null"
    def _derive_item_value(self, _: bytes) -> str:
        return "null"


class SpecialFolderConfigItem(ConfigItem):
    def __init__(self) -> None:
        super().__init__("special folder", b"\x1f(.)\x80(.{3}\x04)")

    # Translates SpecialFolder ID to name
    def _derive_item_value(self, folder_id: bytes) -> str:
        folder_val = bytes_to_int(folder_id)
        try:
            return SpecialFolder(folder_val).name
        except ValueError:
            return f"UnknownFolder({folder_val})"


class EncryptedStringConfigItem(ConfigItem):
    def __init__(self) -> None:
        super().__init__(
            "encrypted string",
            rb"(?<!\x72.{3}\x70)\x72(.{3}\x70)(?:\x28.{4})?\x80(.{3}\x04)",
        )

    # Returns the encrypted string's RVA
    def _derive_item_value(self, enc_str_rva: bytes) -> int:
        return bytes_to_int(enc_str_rva)


SUPPORTED_CONFIG_ITEMS = [
    BoolConfigItem,
    ByteArrayConfigItem,
    IntConfigItem,
    NullConfigItem,
    SpecialFolderConfigItem,
    EncryptedStringConfigItem,
]

# Pre-instantiated stateless singletons (avoids per-method re.compile overhead)
SUPPORTED_CONFIG_ITEM_INSTANCES = [item_cls() for item_cls in SUPPORTED_CONFIG_ITEMS]


def parse_config_items(
    method_body: bytes,
    field_sig_lookup: Callable[[int], bytes | None] | None = None,
) -> list[tuple[ConfigItem, dict[int, Any]]]:
    """Parse config items from a CIL method body in SUPPORTED_CONFIG_ITEMS order.

    Walks real CIL instruction boundaries when a valid tiny/fat header and
    instruction stream are present (eliminating unaligned regex false matches).
    Falls back to the regex ConfigItem parsers for non-standard/headerless data.
    """
    il = _extract_cil_il_bytes(method_body)
    instructions = _decode_cil_instructions(il) if il is not None else None
    if instructions is None:
        return [
            (item, item.parse_from(method_body))
            for item in SUPPORTED_CONFIG_ITEM_INSTANCES
        ]

    bool_fields: dict[int, bool] = {}
    byte_array_fields: dict[int, tuple[int, int]] = {}
    int_fields: dict[int, int] = {}
    null_fields: dict[int, str] = {}
    folder_fields: dict[int, str] = {}
    string_fields: dict[int, int] = {}

    for i, (op, operand) in enumerate(instructions):
        if op != 0x80:  # stsfld <field_token>
            continue
        field_rva = int.from_bytes(operand, "little")
        if (field_rva & 0xFF000000) != MDT_FIELD_DEF or i == 0:
            continue

        prev_op, prev_operand = instructions[i - 1]

        # ByteArray: ldc.i4* ; newarr ; dup ; ldtoken <field> ; call <InitializeArray> ; stsfld
        if (
            prev_op == 0x28  # call
            and i >= 5
            and instructions[i - 2][0] == 0xD0  # ldtoken
            and instructions[i - 3][0] == 0x25  # dup
            and instructions[i - 4][0] == 0x8D  # newarr
        ):
            arr_size = _ldc_i4_value(*instructions[i - 5])
            arr_rva = int.from_bytes(instructions[i - 2][1], "little")
            if (
                arr_size is not None
                and arr_size >= 0
                and (arr_rva & 0xFF000000) == MDT_FIELD_DEF
            ):
                byte_array_fields.setdefault(field_rva, (arr_size, arr_rva))
                continue

        # EncryptedString: [not ldstr] ldstr [optional call] ; stsfld
        if prev_op == 0x72:  # ldstr ; stsfld
            str_rva = int.from_bytes(prev_operand, "little")
            if (str_rva & 0xFF000000) == MDT_STRING and not (
                i >= 2 and instructions[i - 2][0] == 0x72
            ):
                string_fields.setdefault(field_rva, str_rva)
                continue
        elif prev_op == 0x28 and i >= 2 and instructions[i - 2][0] == 0x72:  # ldstr ; call ; stsfld
            str_rva = int.from_bytes(instructions[i - 2][1], "little")
            if (str_rva & 0xFF000000) == MDT_STRING and not (
                i >= 3 and instructions[i - 3][0] == 0x72
            ):
                string_fields.setdefault(field_rva, str_rva)
                continue

        # Bool: ldc.i4.0 / ldc.i4.1 ; stsfld
        if prev_op in (0x16, 0x17):
            bool_fields.setdefault(field_rva, prev_op == 0x17)
            continue

        # Null: ldnull ; stsfld
        if prev_op == 0x14:
            null_fields.setdefault(field_rva, "null")
            continue

        # SpecialFolder vs small int: ldc.i4.s ; stsfld
        if prev_op == 0x1F:
            field_sig = field_sig_lookup(field_rva) if field_sig_lookup else None
            if _is_primitive_int_field(field_sig):
                int_fields.setdefault(
                    field_rva, int.from_bytes(prev_operand, "little", signed=True)
                )
            else:
                folder_val = prev_operand[0]
                try:
                    folder_name = SpecialFolder(folder_val).name
                except ValueError:
                    folder_name = f"UnknownFolder({folder_val})"
                folder_fields.setdefault(field_rva, folder_name)
            continue

        # Int: ldc.i4 / ldc.i4.m1 / ldc.i4.2..8 ; stsfld
        if prev_op == 0x20 or prev_op == 0x15 or (0x18 <= prev_op <= 0x1E):
            int_val = _ldc_i4_value(prev_op, prev_operand)
            if int_val is not None:
                int_fields.setdefault(field_rva, int_val)
                continue

    buckets = (
        bool_fields,
        byte_array_fields,
        int_fields,
        null_fields,
        folder_fields,
        string_fields,
    )
    return list(zip(SUPPORTED_CONFIG_ITEM_INSTANCES, buckets, strict=True))
