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
from hashlib import pbkdf2_hmac
from logging import getLogger

from Cryptodome.Cipher import AES
from Cryptodome.Cipher.AES import MODE_CBC as CBC
from Cryptodome.Util.Padding import unpad

from ...config_parser_exception import ConfigParserException
from ..data_utils import bytes_to_int, decode_bytes
from ..dotnetpe_payload import DotNetPEPayload
from .config_decryptor import (
    ConfigDecryptor,
    IncompatibleDecryptorException,
    strict_b64decode,
)

logger = getLogger(__name__)


class ConfigDecryptorAESWithIV_pbkdf(ConfigDecryptor):
    # Minimum length of valid ciphertext
    _MIN_CIPHERTEXT_LEN = 16
    _DEFAULT_ITERATIONS = 1000

    # Do not re.compile in-line replacement patterns
    _PATTERN_AES_SALT_ITER = re.compile(
        rb"\x72(.{4})\x1f(.)\x8d.{4}\x25\xd0(.{4})\x28", re.DOTALL
    )

    def __init__(self, payload: DotNetPEPayload) -> None:
        super().__init__(payload)
        self.iv: bytes | None = None
        self._candidates: list[tuple[bytes, bytes, bytes]] = []
        try:
            self._get_aes_metadata()
            if not self._candidates:
                raise IncompatibleDecryptorException("IV not found")
        except IncompatibleDecryptorException:
            raise
        except Exception as e:
            raise IncompatibleDecryptorException(e) from e

    def reset_per_config_state(self) -> None:
        if self._candidates:
            self.key, self.iv, self.salt = self._candidates[0]

    # Given an initialization vector and ciphertext, creates a Cipher
    # object with the AES key and specified IV and decrypts the ciphertext
    def _decrypt(self, iv: bytes, ciphertext: bytes) -> bytes:
        logger.debug(
            "Decrypting %d bytes with key %s and IV %s...",
            len(ciphertext),
            self.key.hex(),
            iv.hex(),
        )

        cipher = AES.new(self.key, mode=CBC, iv=iv)
        try:
            padded_text = cipher.decrypt(ciphertext)
            unpadded_text = unpad(padded_text, AES.block_size)
        except Exception as e:
            logger.debug("Ciphertext decryption error: %s", e)
            raise ConfigParserException(
                f"Error decrypting ciphertext with IV {iv.hex()} and key {self.key.hex()} : {e}"
            ) from e
        logger.debug("Decryption result: %r", unpadded_text)
        return unpadded_text

    # Decrypts encrypted config values with the provided cipher data
    def decrypt_encrypted_strings(
        self, encrypted_strings: dict[str, str]
    ) -> dict[str, str]:
        logger.debug("Decrypting encrypted strings...")
        decrypted_config_strings = {}
        successfully_decrypted_count = 0
        successful_candidate: tuple[bytes, bytes, bytes] | None = None

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
                or len(decoded_val) < self._MIN_CIPHERTEXT_LEN
                or len(decoded_val) % AES.block_size != 0
            ):
                logger.debug("Key: %s, Value: %s", k, v)
                decrypted_config_strings[k] = v
                continue

            result, last_exc = None, None
            # Try previously successful candidate first
            if successful_candidate is not None:
                self.key, self.iv, self.salt = successful_candidate
                try:
                    result = decode_bytes(self._decrypt(self.iv, decoded_val))
                except (ValueError, ConfigParserException) as e:
                    last_exc = e
                    result = None

            # Run through key candidates until suitable one found or failure
            if result is None:
                for candidate in self._candidates:
                    if candidate == successful_candidate:
                        continue
                    self.key, self.iv, self.salt = candidate
                    try:
                        result = decode_bytes(self._decrypt(self.iv, decoded_val))
                        successful_candidate = candidate
                        break
                    except (ValueError, ConfigParserException) as e:
                        last_exc = e

            if result is None:
                logger.debug(
                    "Decryption failed for item %s: %s; Leaving as original value...",
                    v,
                    last_exc,
                )
                result = v
            else:
                successfully_decrypted_count += 1

            logger.debug("Key: %s, Value: %s", k, result)
            decrypted_config_strings[k] = result

        if successfully_decrypted_count == 0:
            raise ConfigParserException(
                "No strings could be decrypted with PBKDF2 key/IV candidates"
            )

        if successful_candidate is not None:
            self.key, self.iv, self.salt = successful_candidate

        logger.debug("Successfully decrypted strings")
        return decrypted_config_strings

    # Identifies the initialization of the AES256 object in the payload and
    # sets the necessary values needed for decryption
    def _get_aes_metadata(self) -> None:
        logger.debug("Extracting AES metadata...")
        seen: set[tuple[bytes, bytes]] = set()
        # Some payloads have multiple embedded salt values:
        # Find all valid ones that can be used for initialization
        for candidate in re.finditer(self._PATTERN_AES_SALT_ITER, self._payload.data):
            password_rva, size, salt_rva = candidate.groups()

            try:
                salt = self._get_aes_salt(
                    salt_rva, int.from_bytes(size, byteorder="little")
                )
                password = self._payload.user_string_from_rva(bytes_to_int(password_rva))
                derived = pbkdf2_hmac(
                    "sha1",
                    password.encode("utf-8"),
                    salt,
                    self._DEFAULT_ITERATIONS,
                    48,
                )
                key, iv = derived[:32], derived[32:]
                if (key, iv) not in seen:
                    seen.add((key, iv))
                    self._candidates.append((key, iv, salt))
            except ConfigParserException as cfe:
                logger.info(
                    "Initialization using salt candidate %s failed: %s",
                    hex(bytes_to_int(salt_rva)),
                    cfe,
                )
                continue

        if self._candidates:
            self.key, self.iv, self.salt = self._candidates[0]

    # Extracts the AES salt from the payload, accounting for both hardcoded
    # salt byte arrays, and salts derived from hardcoded strings
    def _get_aes_salt(self, salt_rva: bytes, salt_size: int) -> bytes:
        logger.debug("Extracting AES salt value...")
        salt_strings_rva = bytes_to_int(salt_rva)
        salt = self._payload.byte_array_from_size_and_rva(salt_size, salt_strings_rva)
        logger.debug("Found salt value: %s", salt.hex())
        return salt
