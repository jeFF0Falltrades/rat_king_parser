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
from .dotnet_constants import MDT_FIELD_DEF, MDT_STRING
from dnfile import dnPE
from hashlib import sha256
from logging import getLogger

logger = getLogger(__name__)


class DotNetPEPayload:
    def __init__(self, file_path, yara_rule=None):
        self.file_path = file_path
        self.data = self.get_file_data()
        self.sha256 = self.calculate_sha256()
        self.dotnetpe = None
        try:
            self.dotnetpe = dnPE(self.file_path, clr_lazy_load=True)
        except Exception as e:
            logger.exception(e)
        self.yara_match = ""
        if yara_rule is not None:
            self.yara_match = self.match_yara(yara_rule)

    # Calculates the SHA256 hash of file data
    def calculate_sha256(self):
        sha256_hash = sha256()
        sha256_hash.update(self.data)
        return sha256_hash.hexdigest()

    # Given an RVA, derives the corresponding Field name from the RVA
    def field_name_from_rva(self, rva):
        return self.dotnetpe.net.mdtables.Field.rows[
            (rva ^ MDT_FIELD_DEF) - 1
        ].Name.value

    # Given an RVA, derives the corresponding FieldRVA value from the RVA
    def fieldrva_from_rva(self, rva):
        field_id = rva ^ MDT_FIELD_DEF
        for row in self.dotnetpe.net.mdtables.FieldRva:
            if row.struct.Field_Index == field_id:
                return row.struct.Rva
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

    # Tests a given YARA rule object against the file at file_path
    def match_yara(self, rule):
        try:
            match = rule.match(self.file_path)
            return str(match[0]) if len(match) > 0 else "No match"
        except Exception as e:
            logger.exception(e)
            return f"Exception encountered: {e}"

    # Given the offset to an instruction, reverses the instruction to its
    # parent Method, and then finds the subsequent Method in the MethodDef
    # table and returns its offset
    def next_method_offset_from_instruction_offset(self, ins_offset):
        ins_rva = self.dotnetpe.get_rva_from_offset(ins_offset)
        for method in self.dotnetpe.net.mdtables.MethodDef:
            if method.Rva > ins_rva:
                return self.offset_from_rva(method.Rva)
        raise ConfigParserException(
            f"Could not find next method from instruction offset {ins_offset}"
        )

    # Given an RVA, returns a data/file offset
    def offset_from_rva(self, rva):
        return self.dotnetpe.get_offset_from_rva(rva)

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
        return self.dotnetpe.net.user_strings.get(rva ^ MDT_STRING).value
