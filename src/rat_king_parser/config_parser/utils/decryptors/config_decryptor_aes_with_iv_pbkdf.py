#!/usr/bin/env python3
#
# config_decryptor_aes_with_iv_bpkdf2
#
# Author: doomedraven
#
# MIT License
#
# Copyright (c) 2025 Jeff Archer
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
import re
from base64 import b64decode
from logging import getLogger

from Cryptodome.Cipher import AES
from Cryptodome.Cipher.AES import MODE_CBC as CBC
from Cryptodome.Protocol.KDF import PBKDF2
from Cryptodome.Util.Padding import unpad

from ...config_parser_exception import ConfigParserException
from ..data_utils import bytes_to_int, decode_bytes
from ..dotnetpe_payload import DotNetPEPayload
from .config_decryptor import ConfigDecryptor, IncompatibleDecryptorException

logger = getLogger(__name__)


class ConfigDecryptorAESWithIV_pbkdf(ConfigDecryptor):
    # Minimum length of valid ciphertext
    _MIN_CIPHERTEXT_LEN = 16

    # Do not re.compile in-line replacement patterns
    _PATTERN_AES_SALT_ITER = re.compile(rb"\x72(.{4})\x1f(.)\x8d.{4}\x25\xd0(.{4})\x28")

    def __init__(self, payload: DotNetPEPayload) -> None:
        super().__init__(payload)
        try:
            self.iv = False
            self._get_aes_metadata()
            if not self.iv:
                raise IncompatibleDecryptorException("IV not found")
        except Exception as e:
            raise IncompatibleDecryptorException(e)

    # Given an initialization vector and ciphertext, creates a Cipher
    # object with the AES key and specified IV and decrypts the ciphertext
    def _decrypt(self, iv: bytes, ciphertext: bytes) -> bytes:
        logger.debug(
            f"Decrypting {ciphertext} with key {self.key.hex()} and IV {iv.hex()}..."
        )

        cipher = AES.new(self.key, mode=CBC, iv=iv)
        unpadded_text = ""

        try:
            unpadded_text = cipher.decrypt(ciphertext)
            unpadded_text = unpad(unpadded_text, AES.block_size)
        except Exception as e:
            logger.debug(ciphertext)
            raise ConfigParserException(
                f"Error decrypting ciphertext with IV {iv.hex()} and key {self.key.hex()} : {e}"
            )
        logger.debug(f"Decryption result: {unpadded_text}")
        return unpadded_text

    # Decrypts encrypted config values with the provided cipher data
    def decrypt_encrypted_strings(
        self, encrypted_strings: dict[str, str]
    ) -> dict[str, str]:
        logger.debug("Decrypting encrypted strings...")
        decrypted_config_strings = {}
        for k, v in encrypted_strings.items():
            # Leave empty strings as they are
            if len(v) == 0:
                logger.debug(f"Key: {k}, Value: {v}")
                decrypted_config_strings[k] = v
                continue

            # Check if base64-encoded string
            b64_exception = False
            try:
                decoded_val = b64decode(v)
            except Exception:
                b64_exception = True
            # If it was not base64-encoded, or if it is less than our min length
            # for ciphertext, leave the value as it is
            if b64_exception or len(decoded_val) < self._MIN_CIPHERTEXT_LEN:
                logger.debug(f"Key: {k}, Value: {v}")
                decrypted_config_strings[k] = v
                continue

            result, last_exc = None, None
            # Run through key candidates until suitable one found or failure

            try:
                result = decode_bytes(self._decrypt(self.iv, decoded_val))
            except ConfigParserException as e:
                last_exc = e
                print("error", e)

            if result is None:
                logger.debug(
                    f"Decryption failed for item {v}: {last_exc}; Leaving as original value..."
                )
                result = v

            logger.debug(f"Key: {k}, Value: {result}")
            decrypted_config_strings[k] = result

        logger.debug("Successfully decrypted strings")
        return decrypted_config_strings

    # Identifies the initialization of the AES256 object in the payload and
    # sets the necessary values needed for decryption
    def _get_aes_metadata(self) -> None:
        logger.debug("Extracting AES metadata...")
        # Some payloads have multiple embedded salt values:
        # Find the one that is actually used for initialization
        for candidate in re.finditer(self._PATTERN_AES_SALT_ITER, self._payload.data):
            password, size, salt_rva = candidate.groups()

            try:
                self.salt = self._get_aes_salt(salt_rva, int.from_bytes(size, byteorder="little"))
                password = self._payload.user_string_from_rva(bytes_to_int(password))
                key = PBKDF2(password, self.salt, dkLen=48)
                self.iv = key[32:]
                self.key = key[:32]
            except ConfigParserException as cfe:
                logger.info(
                    f"Initialization using salt candidate {hex(bytes_to_int(candidate.groups()[0]))} failed: {cfe}"
                )
                continue

    # Extracts the AES salt from the payload, accounting for both hardcoded
    # salt byte arrays, and salts derived from hardcoded strings
    def _get_aes_salt(self, salt_rva: int, salt_size: int) -> bytes:
        logger.debug("Extracting AES salt value...")
        salt_strings_rva = bytes_to_int(salt_rva)
        salt = self._payload.byte_array_from_size_and_rva(salt_size, salt_strings_rva)
        logger.debug(f"Found salt value: {salt.hex()}")
        return salt
