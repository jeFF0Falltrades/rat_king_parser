#!/usr/bin/env python3
#
# dotnetpe_payload.py
#
# Author: jeFF0Falltrades
#
# Provides a wrapper class for accessing metadata from a DotNetPE object and
# performing RVA to data offset conversions
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
from .config_parser_exception import ConfigParserException
from .data_utils import bytes_to_int
from .dotnet_constants import RVA_STRINGS_BASE, RVA_US_BASE
from dotnetfile import DotNetPE
from logging import getLogger
from struct import pack

logger = getLogger(__name__)


class DotNetPEPayload:
    def __init__(self, file_path):
        self.file_path = file_path
        self.data = self.get_file_data()
        self.dotnetpe = DotNetPE(self.file_path)
        self.text_section_rva, self.text_section_offset = (
            self.get_text_section_rva_offset()
        )

    # Given an RVA, derives the corresponding Field name from the RVA
    def field_name_from_rva(self, rva):
        field_addr = bytes_to_int(
            self.dotnetpe.metadata_tables_lookup["Field"]
            .table_rows[rva - RVA_STRINGS_BASE - 1]
            .Name._BinaryStructureField__value_bytes
        )
        return self.dotnetpe.get_string(field_addr)

    # Given an RVA, derives the corresponding FieldRVA value from the RVA
    def fieldrva_from_rva(self, rva):
        field_id = pack("<H", rva - RVA_STRINGS_BASE)
        for row in self.dotnetpe.metadata_tables_lookup["FieldRVA"].table_rows:
            if row.Field._BinaryStructureField__value_bytes == field_id:
                return bytes_to_int(row.RVA._BinaryStructureField__value_bytes)
        raise ConfigParserException(f"Could not find FieldRVA for address {rva}")

    # Reads in payload binary content
    def get_file_data(self):
        logger.debug(f"Reading contents from: {self.file_path}")
        try:
            with open(self.file_path, "rb") as fp:
                data = fp.read()
        except Exception as e:
            raise ConfigParserException(
                f"Error reading from path: {self.file_path}"
            ) from e
        logger.debug("Successfully read data")
        return data

    # Returns the RVA and offset of the .text section of the payload, which are
    # both used in RVA/offset translations
    def get_text_section_rva_offset(self):
        text_section_metadata_offset = self.data.find(b".text")
        if text_section_metadata_offset == -1:
            raise ConfigParserException("Could not identify .text section metadata")
        text_section_rva = bytes_to_int(
            self.data[
                text_section_metadata_offset + 12 : text_section_metadata_offset + 16
            ]
        )
        text_section_offset = bytes_to_int(
            self.data[
                text_section_metadata_offset + 20 : text_section_metadata_offset + 24
            ]
        )
        return text_section_rva, text_section_offset

    # Given the offset to an instruction, reverses the instruction to its
    # parent Method, and then finds the subsequent Method in the MethodDef
    # table and returns its offset
    def next_method_offset_from_instruction_offset(self, ins_offset):
        ins_rva = self.rva_from_offset(ins_offset)
        for method in self.dotnetpe.metadata_tables_lookup["MethodDef"].table_rows:
            method_rva = bytes_to_int(method.RVA._BinaryStructureField__value_bytes)
            if method_rva > ins_rva:
                return self.offset_from_rva(method_rva)
        raise ConfigParserException(
            f"Could not find next method from instruction offset {ins_offset}"
        )

    # Given an RVA, calculates the data offset of the RVA by subtracting the
    # relative virtual address of the .text section and adding the data offset
    # of the .text section, e.g.
    #
    # RVA: 0x2050
    # Text section RVA: 0x2000
    # Text section data offset: 0x0200
    # Field offset = 0x2050 - 0x2000 + 0x0200
    #              = 0x0250
    def offset_from_rva(self, rva):
        return rva - self.text_section_rva + self.text_section_offset

    # Inverse of offset_from_rva
    def rva_from_offset(self, offset):
        return offset + self.text_section_rva - self.text_section_offset

    # Given a string offset, and, optionally, a delimiter, extracts the string
    def string_from_offset(self, str_offset, delimiter=b"\0"):
        try:
            result = self.data[str_offset:].partition(delimiter)[0]
        except Exception as e:
            raise ConfigParserException(
                f"Could not extract string value from offset {hex(str_offset)} with delimiter {delimiter}"
            ) from e
        return result

    # Given an RVA, derives the corresponding User String
    def user_string_from_rva(self, rva):
        return self.dotnetpe.get_user_string(rva - RVA_US_BASE)
