#!/usr/bin/env python3
#
# rat_config_parser.py
#
# Author: jeFF0Falltrades
#
# Provides the primary functionality for parsing configurations from the
# AsyncRAT, DcRAT, QuasarRAT, VenomRAT, etc. RAT families
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
from .utils import config_item
from .utils.dotnet_constants import OPCODE_RET
from .utils.dotnetpe_payload import DotNetPEPayload
from .utils.config_aes_decryptor import ConfigAESDecryptor
from .utils.config_parser_exception import ConfigParserException
from logging import getLogger
from re import DOTALL, search

logger = getLogger(__name__)


class RATConfigParser:
    CONFIG_ITEM_TYPES = [
        config_item.BoolConfigItem(),
        config_item.IntConfigItem(),
        config_item.NullConfigItem(),
        config_item.SpecialFolderConfigItem(),
        config_item.EncryptedStringConfigItem(),
    ]
    PATTERN_VERIFY_HASH = (
        rb"(?:\x7e.{3}\x04(?:\x6f.{3}\x0a){2}\x74.{3}\x01.+?\x2a.+?\x00{6,})"
    )

    def __init__(self, file_path):
        self.dnpp = DotNetPEPayload(file_path)
        self.aes_decryptor = None  # Created in decrypt_and_decode_config()
        self.config = {}
        self.encrypted_config = self.get_encrypted_config()
        self.decrypt_and_decode_config()

    # Decrypts/decodes values from an encrypted config
    def decrypt_and_decode_config(self):
        for item in self.CONFIG_ITEM_TYPES:
            item_data = item.parse_from(self.encrypted_config)
            if type(item) is config_item.EncryptedStringConfigItem:
                # Translate encrypted string RVAs to encrypted values
                for k in item_data:
                    item_data[k] = self.dnpp.user_string_from_rva(item_data[k])
                # Decrypt the values
                self.aes_decryptor = ConfigAESDecryptor(self.dnpp, item_data)
                item_data = self.aes_decryptor.decrypt_encrypted_strings()
            self.config.update(item_data)
        # Translate field name RVAs to string values
        self.translate_config_field_names()

    # Search for the RAT configuration in the Settings module
    def get_encrypted_config(self):
        logger.debug("Extracting encrypted config...")
        # Identify the VerifyHash() Method code
        hit = search(self.PATTERN_VERIFY_HASH, self.dnpp.data, DOTALL)
        if hit is None:
            raise ConfigParserException("Could not identify VerifyHash() marker method")

        # Reverse the VerifyHash() instruction offset, look up VerifyHash() in
        # the MethodDef metadata table, and then get the offset to the
        # subsequent function, which should be our config constructor
        config_start = self.dnpp.next_method_offset_from_instruction_offset(hit.start())
        # Configuration ends with ret operation, so use that as our terminator
        encrypted_config = self.dnpp.string_from_offset(config_start, OPCODE_RET)
        logger.debug(f"Encrypted config found at offset {hex(config_start)}...")
        return encrypted_config

    # Sorts the config by field name RVA prior to replacing RVAs with field
    # name strings (this is done last to preserve config ordering)
    def translate_config_field_names(self):
        translated_config = {}
        for field_rva, field_value in sorted(self.config.items()):
            key = self.dnpp.field_name_from_rva(field_rva)
            translated_config[key] = field_value
            logger.debug(f"Config item parsed {key}: {field_value}")
        self.config = translated_config

    # Returns the metadata and the decrypted configuration for a payload
    def report(self):
        result_dict = {
            "file_path": self.dnpp.file_path,
            "aes_key": self.aes_decryptor.key.hex()
            if self.aes_decryptor.key is not None
            else "None",
            "aes_salt": self.aes_decryptor.salt.hex()
            if self.aes_decryptor is not None
            else "None",
            "config": self.config,
        }
        return result_dict
