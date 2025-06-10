#!/usr/bin/env python3
#
# config_decryptor_rijndael.py
#
# Author: jeFF0Falltrades
#
# Provides a custom AES decryptor for RAT payloads utilizing CBC mode
#
# Example Hash: 0653c325ba9705b001920ecb44f5730de003ea04ce5398fdfbd114493f8b4c63
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
import logging
from base64 import b64decode
from hashlib import md5
from re import DOTALL, compile, search

from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad

from ...config_parser_exception import ConfigParserException
from ..data_utils import bytes_to_int, decode_bytes
from ..dotnetpe_payload import DotNetPEPayload
from .config_decryptor import ConfigDecryptor, IncompatibleDecryptorException

logger = logging.getLogger(__name__)


# Is old AES - specifically Rijndael in CBC mode with MD5 hashing for key derivation
class ConfigDecryptorRijndael(ConfigDecryptor):
    _ALGO_MAP = {
        b"\x17": AES.MODE_CBC,
        b"\x1a": AES.MODE_CFB,
        b"\x18": AES.MODE_ECB,
    }
    # MD5 hash pattern used to detect AES key
    _PATTERN_MD5_HASH = compile(rb"\x7e(.{3}\x04)\x6f.{4}\x11\x06\x0c", DOTALL)
    _PATTERN_MD5_HASH2 = compile(rb"\x7e(.{3}\x04)\x28.{3}\x06\x6f.{4}\x13\x04", DOTALL)
    _KEY_AS_ARG = compile(rb"\x7e(.{3}\x04)\x28.{3}\x06\x7e.{3}\x04\x28.{3}\x06\x80.{3}\x04", DOTALL)

    # key size 16 and 1 = CBC, 2 = ECB
    # https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.ciphermode?view=net-9.0
    # _PATTERN_AES_MODE = compile(rb"[\x06-\x09]\x6f.{4}\x21(.)\x00{8}\x59\x21(.)\x00{8}\x58\xd4\x8d.{4}\x13\x05")
    # check AES mode
    _AES_MODE = compile(rb"\x06\x09\x6f.{4}\x06(.)\x6f.{4}\x06\x6f.{4}\x13", DOTALL)
    _SIMPLE_MD5 = compile(rb"\x11\x04\x16\x09\x16\x1f\x10\x28.{4}\x11\x04\x16\x09\x1f\x0f\x1f\x10\x28", DOTALL)
    _PATTERNS_MD5 = (_PATTERN_MD5_HASH, _PATTERN_MD5_HASH2)
    _KEY_PATTERNS = (_KEY_AS_ARG,)

    def __init__(self, payload: DotNetPEPayload) -> None:
        super().__init__(payload)
        self.mode = AES.MODE_CBC
        try:
            self._key_rva = self._get_key_rva()
        except Exception as e:
            logger.debug("Incompatible Decryptor")
            raise IncompatibleDecryptorException(e)

    # Given ciphertext, creates a Cipher object with the AES key and decrypts
    # the ciphertext
    def _decrypt(self, ciphertext: bytes) -> bytes:
        unpadded_text = ""
        cipher = AES.new(self.key, mode=self.mode)
        block_size = AES.block_size
        try:
            padded_text = cipher.decrypt(ciphertext)
            if self.mode == AES.MODE_CBC:
                # Remove the first 16 bytes of the decrypted text as they are the IV
                padded_text = padded_text[16:]
        except ValueError:
            padded_text = cipher.decrypt(pad(ciphertext, block_size))
        try:
            unpadded_text = unpad(padded_text, block_size)
        except ValueError as e:
            # Might be not padded
            logger.debug("error unpadding: %s", e)
            return None
        logger.debug(f"Decryption result: {unpadded_text}")
        return unpadded_text

    # Decrypts encrypted config values with the provided cipher data
    def decrypt_encrypted_strings(self, encrypted_strings: dict[str, str]) -> dict[str, str]:
        logger.debug("Decrypting encrypted strings...")
        if not self.key:
            try:
                #
                raw_key_field = self._payload.field_name_from_rva(self._key_rva)
                if raw_key_field in encrypted_strings:
                    key = encrypted_strings[raw_key_field]
                    self.key = self._derive_key(key)
                else:
                    for key_pattern in self._KEY_PATTERNS:
                        key_hit = search(key_pattern, self._payload.data)
                        key_rva = bytes_to_int(key_hit.groups()[0])
                        raw_key_field = self._payload.field_name_from_rva(key_rva)
                        key = encrypted_strings[raw_key_field]
                        self.key = self._derive_key(key)
                        break
            except Exception as e:
                raise ConfigParserException(f"Failed to derive AES key: {e}")

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
            # If it was not base64-encoded, leave the value as it is
            if b64_exception:
                logger.debug(f"Key: {k}, Value: {v}")
                decrypted_config_strings[k] = v
                continue

            ciphertext = decoded_val
            result, last_exc = None, None
            try:
                result = decode_bytes(self._decrypt(ciphertext))
            except ConfigParserException as e:
                last_exc = e

            if result is None:
                logger.debug(f"Decryption failed for item {v}: {last_exc}")
                result = v

            logger.debug(f"Key: {k}, Value: {result}")
            decrypted_config_strings[k] = result

        logger.debug("Successfully decrypted strings")
        return decrypted_config_strings

    # Given the raw bytes that will become the key value, derives the AES/3DES key
    def _derive_key(self, key_unhashed: str) -> bytes:
        # Generate the MD5 hash
        md5_hash = md5()
        md5_hash.update(key_unhashed.encode("utf-8"))
        key = md5_hash.digest()

        if search(self._SIMPLE_MD5, self._payload.data):
            # check if simple md5
            logger.debug("Simple MD5 detected")
            key = key[:15] + key[:16] + b"\x00"
        logger.debug("Key derived: %s, from key: %s", key.hex(), key_unhashed)
        return key

    # Extracts the AES/3DES key RVA from the payload
    def _get_key_rva(self) -> int:
        logger.debug("Extracting AES key value...")
        key_hit = None
        for pattern in self._PATTERNS_MD5:
            key_hit = search(pattern, self._payload.data)
            if key_hit:
                break
        if not key_hit:
            raise ConfigParserException("Could not find AES key pattern")

        # check if AES mode is different from CBC:
        _AES_MODE = search(self._AES_MODE, self._payload.data)
        if _AES_MODE:
            self.mode = self._ALGO_MAP[_AES_MODE.groups()[0]]
            logger.debug(f"AES mode: {self.mode}")

        key_rva = bytes_to_int(key_hit.groups()[0])
        logger.debug(f"AES key RVA: {hex(key_rva)}")
        return key_rva
