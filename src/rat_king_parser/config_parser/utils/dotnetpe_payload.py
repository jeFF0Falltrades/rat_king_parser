#!/usr/bin/env python3
#
# dotnetpe_payload.py
#
# Authors: jeFF0Falltrades, doomedraven
#
# Provides a wrapper class for accessing metadata from a DotNetPE object and
# performing data conversions
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
from bisect import bisect_right
from dataclasses import dataclass
from hashlib import sha256
from logging import getLogger

from dnfile import dnPE
from pefile import DIRECTORY_ENTRY
from yara_x import Rules

from ..config_parser_exception import ConfigParserException
from .data_utils import bytes_to_int
from .dotnet_constants import MDT_FIELD_DEF, MDT_METHOD_DEF, MDT_STRING

logger = getLogger(__name__)

_CLR_DIRECTORY_ONLY = (DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR"],)


# Helper class representing a single Method
@dataclass
class DotNetPEMethod:
    name: str
    offset: int
    rva: int
    size: int
    token: int


def _decode_serstring_from_ca_blob(blob_data: bytes) -> str | None:
    """Decode a single SerString fixed argument from an ECMA-335 CustomAttribute blob."""
    if len(blob_data) < 3 or blob_data[:2] != b"\x01\x00":
        return None
    pos = 2
    first = blob_data[pos]
    if first == 0xFF:  # null string
        return None
    if (first & 0x80) == 0:
        str_len = first
        pos += 1
    elif (first & 0xC0) == 0x80 and pos + 1 < len(blob_data):
        str_len = ((first & 0x3F) << 8) | blob_data[pos + 1]
        pos += 2
    elif (first & 0xE0) == 0xC0 and pos + 3 < len(blob_data):
        str_len = (
            ((first & 0x1F) << 24)
            | (blob_data[pos + 1] << 16)
            | (blob_data[pos + 2] << 8)
            | blob_data[pos + 3]
        )
        pos += 4
    else:
        return None
    if pos + str_len > len(blob_data):
        return None
    return blob_data[pos : pos + str_len].decode("utf-8")


class DotNetPEPayload:
    def __init__(
        self, file_path: str, yara_rule: Rules | None = None, data: bytes | None = None
    ) -> None:
        self.file_path = file_path
        self.data = data
        if self.data is None:
            self.data = self._get_file_data()

        # Calculate SHA256
        sha256_obj = sha256()
        sha256_obj.update(self.data)
        self.sha256 = sha256_obj.hexdigest()

        self.dotnetpe: dnPE | None = None
        try:
            if self.data is not None:
                self.dotnetpe = dnPE(
                    data=self.data, fast_load=True, clr_lazy_load=True
                )
            else:
                self.dotnetpe = dnPE(
                    self.file_path, fast_load=True, clr_lazy_load=True
                )
            self.dotnetpe.parse_data_directories(directories=_CLR_DIRECTORY_ONLY)
            if not self.dotnetpe.net or not self.dotnetpe.net.mdtables:
                raise ConfigParserException(
                    "Failed to load project as dotnet executable (missing Metadata)"
                )
        except ConfigParserException:
            raise
        except Exception as e:
            raise ConfigParserException(
                "Failed to load project as dotnet executable"
            ) from e

        self.yara_match = ""
        if yara_rule is not None:
            self.yara_match = self._match_yara(yara_rule)

        # Cache Field metadata table for fast lookups
        self._field_table = getattr(self.dotnetpe.net.mdtables, "Field", None)

        # Pre-sort Method table for efficient lookups
        # Note: _generate_method_list() yields methods in monotonic token order,
        # so _methods is already sorted by token without an extra sort pass.
        self._methods = self._generate_method_list()
        self._methods_by_offset = sorted(self._methods, key=lambda m: m.offset)
        self._methods_by_token = self._methods
        self._offsets = [m.offset for m in self._methods_by_offset]
        self._tokens = [m.token for m in self._methods_by_token]

        # Pre-compute FieldRva mapping for O(1) lookups
        self._field_rva_map = {}
        if getattr(self.dotnetpe.net.mdtables, "FieldRva", None):
            self._field_rva_map = {
                row.struct.Field_Index: row.struct.Rva
                for row in self.dotnetpe.net.mdtables.FieldRva
            }

    # Given a byte array's size and RVA, translates the RVA to the offset of
    # the byte array and returns the bytes of the array as a byte string
    def byte_array_from_size_and_rva(self, arr_size: int, arr_rva: int) -> bytes:
        arr_field_rva = self.fieldrva_from_rva(arr_rva)
        arr_offset = self.offset_from_rva(arr_field_rva)
        if arr_offset < 0 or arr_size < 0 or arr_offset + arr_size > len(self.data):
            raise ConfigParserException(
                f"Byte array out of bounds at offset {hex(arr_offset)} (size {arr_size})"
            )
        return self.data[arr_offset : arr_offset + arr_size]

    # Given an offset, and either a terminating offset or delimiter, extracts
    # the byte string
    def byte_string_from_offset(
        self, offset_start: int, offstart_end: int = -1, delimiter: bytes = b"\0"
    ) -> bytes:
        if not isinstance(offset_start, int) or offset_start < 0 or offset_start > len(self.data):
            raise ConfigParserException(
                f"Could not extract string value from invalid offset {offset_start!r}"
            )
        if offstart_end != -1:
            if not isinstance(offstart_end, int) or offstart_end < offset_start:
                raise ConfigParserException(
                    f"Could not extract string value from offset range [{hex(offset_start)}:{offstart_end!r}]"
                )
            return self.data[offset_start:offstart_end]
        try:
            end = self.data.find(delimiter, offset_start)
            return self.data[offset_start:end] if end != -1 else self.data[offset_start:]
        except Exception as e:
            raise ConfigParserException(
                f"Could not extract string value from offset {hex(offset_start)} with delimiter {delimiter!r}"
            ) from e

    # Given an RVA, derives the corresponding Field name
    def field_name_from_rva(self, rva: int) -> str:
        if not self._field_table:
            raise ConfigParserException(f"Could not find Field table for RVA {rva}")
        if (rva & 0xFF000000) != MDT_FIELD_DEF:
            raise ConfigParserException(f"Invalid Field token for RVA {hex(rva)}")
        field_idx = (rva & 0x00FFFFFF) - 1
        if field_idx < 0 or field_idx >= len(self._field_table.rows):
            raise ConfigParserException(f"Could not find Field for RVA {rva}")
        try:
            return self._field_table.rows[field_idx].Name.value
        except Exception as e:
            raise ConfigParserException(f"Could not find Field for RVA {rva}") from e

    # Given a FieldDef token/RVA, returns its raw metadata signature bytes if available
    def field_signature_from_rva(self, rva: int) -> bytes | None:
        if not self._field_table or (rva & 0xFF000000) != MDT_FIELD_DEF:
            return None
        field_idx = (rva & 0x00FFFFFF) - 1
        if field_idx < 0 or field_idx >= len(self._field_table.rows):
            return None
        try:
            sig = self._field_table.rows[field_idx].Signature
            return sig.value if sig is not None else None
        except Exception:
            return None

    # Given an RVA, derives the corresponding FieldRVA value
    def fieldrva_from_rva(self, rva: int) -> int:
        if (rva & 0xFF000000) != MDT_FIELD_DEF:
            raise ConfigParserException(f"Invalid Field token for FieldRVA {hex(rva)}")
        field_id = rva & 0x00FFFFFF
        if field_id in self._field_rva_map:
            return self._field_rva_map[field_id]
        raise ConfigParserException(f"Could not find FieldRVA for RVA {rva}")

    # Generates a list of DotNetPEMethod objects for efficient lookups of method
    # metadata in other operations
    def _generate_method_list(
        self,
    ) -> list[DotNetPEMethod]:
        method_objs = []
        method_def_table = getattr(self.dotnetpe.net.mdtables, "MethodDef", None)
        if not method_def_table:
            return method_objs

        data = self.data
        data_len = len(data)
        for idx, method in enumerate(method_def_table.rows):
            # Skip abstract, P/Invoke, and runtime methods with no IL body
            if not method.Rva:
                continue
            try:
                method_offset = self.offset_from_rva(method.Rva)
            except Exception:
                continue
            if method_offset < 0 or method_offset >= data_len:
                continue

            # Parse size from flags (ECMA-335 II.25.4.2 / II.25.4.3)
            flags = data[method_offset]
            method_size = 0
            if flags & 3 == 2:  # Tiny format (1-byte header + 6-bit code size)
                method_size = 1 + (flags >> 2)
            elif flags & 3 == 3 and method_offset + 12 <= data_len:  # Fat format
                flags16 = bytes_to_int(data[method_offset : method_offset + 2])
                header_size = ((flags16 >> 12) & 0x0F) * 4 or 12
                code_size = bytes_to_int(data[method_offset + 4 : method_offset + 8])
                method_size = header_size + code_size

            if method_offset + method_size > data_len:
                method_size = data_len - method_offset

            method_objs.append(
                DotNetPEMethod(
                    method.Name.value,
                    method_offset,
                    method.Rva,
                    method_size,
                    MDT_METHOD_DEF | (idx + 1),
                )
            )
        return method_objs

    # Returns payload binary content
    def _get_file_data(self) -> bytes:
        logger.debug("Reading contents from: %s", self.file_path)
        try:
            with open(self.file_path, "rb") as fp:
                data = fp.read()
        except Exception as e:
            raise ConfigParserException(
                f"Error reading from path: {self.file_path}"
            ) from e
        logger.debug("Successfully read %d bytes", len(data))
        return data

    # Tests a given YARA-X (or legacy yara-python) rule object against the file
    # content, returning the matching rule's name, or "No match"
    def _match_yara(self, rule: Rules) -> str:
        try:
            if hasattr(rule, "scan"):
                matches = rule.scan(self.data).matching_rules
                return str(matches[0].identifier) if matches else "No match"
            match = rule.match(data=self.data)
            return str(match[0]) if len(match) > 0 else "No match"
        except Exception as e:
            logger.exception(e)
            return f"Exception encountered: {e}"

    # Given a DotNetPEMethod, returns its body as raw bytes
    def method_body_from_method(self, method: DotNetPEMethod) -> bytes:
        return self.byte_string_from_offset(method.offset, method.offset + method.size)

    # Given a Method name, returns a list of DotNetPEMethods matching that name
    def methods_from_name(self, name: str) -> list[DotNetPEMethod]:
        return [method for method in self._methods if method.name == name]

    # Given the offset to an instruction, reverses the instruction to its
    # parent Method, optionally returning an adjacent Method using step to
    # signify the direction of adjacency, and using by_token to determine
    # whether to calculate adjacency by token or offset
    def method_from_instruction_offset(
        self, ins_offset: int, step: int = 0, by_token: bool = False
    ) -> DotNetPEMethod:
        idx = bisect_right(self._offsets, ins_offset) - 1
        while idx >= 0:
            method = self._methods_by_offset[idx]
            if method.offset <= ins_offset < method.offset + method.size:
                if step == 0:
                    return method
                if by_token:
                    token_idx = bisect_right(self._tokens, method.token) - 1 + step
                    if 0 <= token_idx < len(self._methods_by_token):
                        return self._methods_by_token[token_idx]
                    raise ConfigParserException(
                        f"Adjacent method out of bounds (token step {step}) for offset {hex(ins_offset)}"
                    )
                target_idx = idx + step
                if 0 <= target_idx < len(self._methods_by_offset):
                    return self._methods_by_offset[target_idx]
                raise ConfigParserException(
                    f"Adjacent method out of bounds (offset step {step}) for offset {hex(ins_offset)}"
                )
            # Only continue scanning backwards if preceding methods share the exact same offset
            if idx > 0 and self._methods_by_offset[idx - 1].offset == method.offset:
                idx -= 1
            else:
                break
        raise ConfigParserException(
            f"Could not find method from instruction offset {hex(ins_offset)}"
        )

    # Given an RVA, returns a data/file offset
    def offset_from_rva(self, rva: int) -> int:
        return self.dotnetpe.get_offset_from_rva(rva)

    # Given an RVA, derives the corresponding User String
    def user_string_from_rva(self, rva: int) -> str:
        if (rva & 0xFF000000) != MDT_STRING:
            raise ConfigParserException(f"Invalid UserString token for RVA {hex(rva)}")
        user_strings = getattr(self.dotnetpe.net, "user_strings", None)
        if user_strings is None:
            raise ConfigParserException(
                f"No UserStrings heap present for RVA {hex(rva)}"
            )
        result = user_strings.get(rva & 0x00FFFFFF)
        if result is None:
            raise ConfigParserException(
                f"Could not find user string for RVA {hex(rva)}"
            )
        return result.value

    def custom_attribute_from_type(self, typespacename: str, typename: str) -> dict:
        """
        Ex:
            typespacename: Server.Properties
            typenaem: Settings

        dnspy view
            // Server.Properties.Settings
            // Token: 0x17000077 RID: 119
            // (get) Token: 0x06000913 RID: 2323 RVA: 0x00009FED File Offset: 0x000081ED
            // (set) Token: 0x06000914 RID: 2324 RVA: 0x0000A004 File Offset: 0x00008204
            [DebuggerNonUserCode]
            [DefaultSettingValue("3128")]
            [UserScopedSetting]
            public decimal ReverseProxyPort

        returns: dict.
            Ex: {"ReverseProxyPort": "3128"}
        """
        config = {}
        try:
            ca_map: dict[int, list] = {}
            ca_table = getattr(self.dotnetpe.net.mdtables, "CustomAttribute", None)
            if ca_table:
                for ca in ca_table.rows:
                    parent = getattr(ca, "Parent", None)
                    parent_table = getattr(parent, "table", None)
                    if parent_table is None or getattr(parent_table, "name", None) != "Property":
                        continue
                    idx = parent.row_index
                    ca_map.setdefault(idx, []).append(ca)

            td_table = getattr(self.dotnetpe.net.mdtables, "TypeDef", None)
            prop_table = getattr(self.dotnetpe.net.mdtables, "Property", None)
            if not td_table or not prop_table:
                return config

            # Map 1-based TypeDef row index -> 1-based (start, end_exclusive) Property indices
            prop_map_table = getattr(self.dotnetpe.net.mdtables, "PropertyMap", None)
            td_prop_ranges: dict[int, tuple[int, int]] = {}
            if prop_map_table:
                pm_rows = prop_map_table.rows
                for i, pm in enumerate(pm_rows):
                    start_idx = pm.PropertyList.row_index
                    end_idx = (
                        pm_rows[i + 1].PropertyList.row_index
                        if i + 1 < len(pm_rows)
                        else len(prop_table.rows) + 1
                    )
                    td_prop_ranges[pm.Parent.row_index] = (start_idx, end_idx)

            for td_idx, td in enumerate(td_table.rows, start=1):
                if (
                    td.TypeNamespace.value != typespacename
                    or td.TypeName.value != typename
                ):
                    continue
                if td_prop_ranges:
                    if td_idx not in td_prop_ranges:
                        continue
                    start_p, end_p = td_prop_ranges[td_idx]
                    prop_indices = range(start_p, min(end_p, len(prop_table.rows) + 1))
                else:
                    prop_indices = range(1, len(prop_table.rows) + 1)

                for target_index in prop_indices:
                    pd = prop_table.rows[target_index - 1]
                    if pd.Name.value.startswith(
                        (
                            "Boolean_",
                            "BorderStyle_",
                            "Color_",
                            "Byte",
                            "Int32_",
                            "SizeF_",
                            "String_",
                        )
                    ):
                        continue
                    if target_index in ca_map:
                        for ca in ca_map[target_index]:
                            # Extract the value from the CustomAttribute blob
                            blob_data = ca.Value.value
                            if blob_data and blob_data != b"\x01\x00\x00\x00":
                                try:
                                    value = _decode_serstring_from_ca_blob(blob_data)
                                    if value is not None:
                                        config.setdefault(pd.Name.value, value)
                                except UnicodeDecodeError:
                                    logger.debug(
                                        "Warning: Could not decode blob data for %s",
                                        pd.Name.value,
                                    )
        except Exception as e:
            logger.debug("An error occurred in custom_attribute_from_type: %s", str(e))
        return config
