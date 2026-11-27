#!/usr/bin/env python3
#
# config_decryptor_ecb.py
#
# Author: jeFF0Falltrades & doomedraven
#
# Provides a custom AES decryptor for RAT payloads utilizing ECB mode
#
# Example Hash: d5028e10a756f2df677f32ebde105d7de8df37e253c431837c8f810260f4428e
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
from hashlib import md5
from logging import getLogger
from re import DOTALL, compile, search

from Cryptodome.Cipher import AES, DES3
from Cryptodome.Util.Padding import unpad

from ...config_parser_exception import ConfigParserException
from ..data_utils import bytes_to_int, decode_bytes
from ..dotnet_constants import MDT_STRING
from ..dotnetpe_payload import DotNetPEPayload
from .config_decryptor import (
    ConfigDecryptor,
    IncompatibleDecryptorException,
    strict_b64decode,
)

logger = getLogger(__name__)


class ConfigDecryptorECB(ConfigDecryptor):
    # MD5 hash pattern used to detect AES key
    _PATTERN_MD5_HASH = compile(rb"\x7e(.{3}\x04)\x28.{3}\x06\x6f", DOTALL)
    _PATTERN_HARDCODED_KEY = compile(rb"\x00\x72(.{3}\x70)\x0A\x28.{4}", DOTALL)
    # Detect AES vs 3DES
    _IS_3DES = compile(rb"(\x28|\x73).{3}\x0A\x13\x04\x11\x04", DOTALL)
    # Patterns for identifying AES metadata
    _IS_AES = compile(
        b"[\x06-\x09]\x20(.{4})\x6f.{4}[\x06-\x09]\x20(.{4})\x6f.{4}[\x06-\x09](.)\x6f.{4}|[\x06-\x09]\x11\x05\x6f.{4}[\x06-\x09].\x6f.{4}[\x06-\x09]\x6f.{4}\x13",
        DOTALL,
    )

    def __init__(self, payload: DotNetPEPayload) -> None:
        super().__init__(payload)

        self.is_AES = search(self._IS_AES, self._payload.data)
        self.is_3DES = search(self._IS_3DES, self._payload.data)
        if not self.is_AES and not self.is_3DES:
            raise IncompatibleDecryptorException(
                "Neither AES nor 3DES ECB pattern detected"
            )
        try:
            self._key_rva = self._get_key_rva()
        except Exception as e:
            raise IncompatibleDecryptorException(e) from e

    def reset_per_config_state(self) -> None:
        self.key = None

    def _build_cipher(self):
        try:
            if self.is_AES:
                return AES.new(self.key, mode=AES.MODE_ECB), AES.block_size
            if self.is_3DES:
                adjusted_key = DES3.adjust_key_parity(self.key)
                return DES3.new(adjusted_key, mode=DES3.MODE_ECB), DES3.block_size
        except Exception as e:
            raise ConfigParserException(
                f"Error initializing ECB cipher with key {self.key.hex()}: {e}"
            ) from e
        raise ConfigParserException("Neither AES nor 3DES mode selected")

    # Given ciphertext, creates a Cipher object with the AES/3DES key and decrypts
    # the ciphertext
    def _decrypt(self, ciphertext: bytes, cipher=None, block_size: int | None = None) -> bytes:
        if cipher is None or block_size is None:
            cipher, block_size = self._build_cipher()

        if len(ciphertext) == 0 or len(ciphertext) % block_size != 0:
            raise ConfigParserException(
                f"Invalid ECB ciphertext length {len(ciphertext)} (block size {block_size})"
            )

        try:
            padded_text = cipher.decrypt(ciphertext)
            try:
                # Attempt to unpad first
                unpadded_text = unpad(padded_text, block_size)
            except ValueError:
                # If unpadding fails, it might be unpadded
                # Remove trailing null bytes (common in some implementations)
                unpadded_text = padded_text.rstrip(b"\x00")
        except Exception as e:
            raise ConfigParserException(
                f"Error decrypting ciphertext {ciphertext} with key {self.key.hex()}: {e}"
            ) from e

        logger.debug("Decryption result: %r", unpadded_text)
        return unpadded_text

    # Decrypts encrypted config values with the provided cipher data
    def decrypt_encrypted_strings(
        self, encrypted_strings: dict[str, str]
    ) -> dict[str, str]:
        logger.debug("Decrypting encrypted strings...")
        if self.key is None:
            try:
                if (self._key_rva & 0xFF000000) == MDT_STRING:
                    raw_key_str = self._payload.user_string_from_rva(self._key_rva)
                else:
                    raw_key_field = self._payload.field_name_from_rva(self._key_rva)
                    raw_key_str = encrypted_strings[raw_key_field]
                self.key = self._derive_key(raw_key_str)
            except Exception as e:
                raise ConfigParserException(f"Failed to derive AES/3DES key: {e}") from e

        cipher, block_size = self._build_cipher()

        decrypted_config_strings = {}
        successfully_decrypted_count = 0
        for k, v in encrypted_strings.items():
            # Leave empty strings as they are
            if len(v) == 0:
                logger.debug("Key: %s, Value: %s", k, v)
                decrypted_config_strings[k] = v
                continue

            # Strictly check if base64-encoded string and block-aligned
            decoded_val = strict_b64decode(v)
            if (
                decoded_val is None
                or len(decoded_val) == 0
                or len(decoded_val) % block_size != 0
            ):
                logger.debug("Key: %s, Value: %s", k, v)
                decrypted_config_strings[k] = v
                continue

            ciphertext = decoded_val
            result, last_exc = None, None
            try:
                result = decode_bytes(
                    self._decrypt(ciphertext, cipher=cipher, block_size=block_size)
                )
            except ConfigParserException as e:
                last_exc = e

            if result is None:
                logger.debug("Decryption failed for item %s: %s", v, last_exc)
                result = v
            else:
                successfully_decrypted_count += 1

            logger.debug("Key: %s, Value: %s", k, result)
            decrypted_config_strings[k] = result

        if successfully_decrypted_count == 0:
            raise ConfigParserException(
                "No strings could be decrypted with the derived AES/3DES ECB key"
            )

        logger.debug("Successfully decrypted strings")
        return decrypted_config_strings

    # Given the raw bytes that will become the key value, derives the key
    def _derive_key(self, key_unhashed: str) -> bytes:
        # Generate the MD5 hash
        md5_hash = md5()
        md5_hash.update(key_unhashed.encode("utf-8"))
        md5_digest = md5_hash.digest()

        # AES key is a 32-byte value made up of the MD5 hash overlaying itself,
        # tailed with one null byte
        key = md5_digest[:15] + md5_digest[:16] + b"\x00" if self.is_AES else md5_digest
        logger.debug("Key derived: %s", key.hex())
        return key

    # Extracts the AES/3DES key RVA from the payload
    def _get_key_rva(self) -> int:
        logger.debug("Extracting AES/3DES key value...")
        key_hit = search(self._PATTERN_MD5_HASH, self._payload.data)
        if key_hit is None:
            key_hit = search(self._PATTERN_HARDCODED_KEY, self._payload.data)
        if key_hit is None:
            raise ConfigParserException("Could not find AES/3DES key pattern")

        key_rva = bytes_to_int(key_hit.groups()[0])
        logger.debug("AES/3DES key RVA: %s", hex(key_rva))
        return key_rva
