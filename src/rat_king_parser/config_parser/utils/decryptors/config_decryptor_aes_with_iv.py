#!/usr/bin/env python3
#
# config_decryptor_aes_cbc.py
#
# Author: jeFF0Falltrades
#
# Provides a custom AES decryptor for RAT payloads utilizing CBC mode
#
# Example Hash: 6b99acfa5961591c39b3f889cf29970c1dd48ddb0e274f14317940cf279a4412
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
import re
from contextlib import suppress
from hashlib import pbkdf2_hmac
from logging import getLogger
from typing import Iterator, Tuple

from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import unpad

from ...config_parser_exception import ConfigParserException
from ..data_utils import bytes_to_int, decode_bytes, int_to_bytes
from ..dotnet_constants import OPCODE_LDSTR, OPCODE_LDTOKEN
from ..dotnetpe_payload import DotNetPEPayload
from .config_decryptor import (
    ConfigDecryptor,
    IncompatibleDecryptorException,
    strict_b64decode,
)

logger = getLogger(__name__)


class ConfigDecryptorAESWithIV(ConfigDecryptor):
    # Minimum length of valid ciphertext (32-byte HMAC + 16-byte IV + >=16-byte block)
    _MIN_CIPHERTEXT_LEN = 48
    # Upper bound on PBKDF2 iterations to guard against CPU DoS in crafted binaries
    _MAX_PBKDF2_ITERATIONS = 1_000_000
    _VALID_KEY_SIZES = frozenset({16, 24, 32})
    _ALGO_MAP = {
        b"\x17": AES.MODE_CBC,
        b"\x1a": AES.MODE_CFB,
    }

    # Patterns for identifying AES metadata
    _PATTERN_AES_KEY_AND_BLOCK_SIZE_AND_ALGO = re.compile(
        rb"[\x06-\x09]\x20(.{4})\x6f.{4}[\x06-\x09]\x20(.{4})\x6f.{4}[\x06-\x09](.)\x6f.{4}|\x11\x01\x20(.{4})\x28.{4}\x11\x01\x20(.{4})\x6f.{4}\x11\x01(.)\x6f.{4}",
        re.DOTALL,
    )
    # Do not re.compile in-line replacement patterns
    _PATTERN_AES_KEY_BASE = b"(.{3}\x04).%b"
    _PATTERN_AES_SALT_INIT = b"\x80%b\x2a"
    _PATTERN_AES_SALT_ITER = re.compile(b"[\x02-\x05]\x7e(.{4})\x20(.{4})\x73", re.DOTALL)

    def __init__(self, payload: DotNetPEPayload) -> None:
        super().__init__(payload)
        self._block_size: int | None = None
        self._iterations: int | None = None
        self._key_candidates: list[tuple[bytes, bytes]] | None = None
        self._key_size: int | None = None
        self._key_rva: int | None = None
        self._aes_algo = AES.MODE_CBC
        try:
            self._get_aes_metadata()
        except Exception as e:
            raise IncompatibleDecryptorException(e) from e

    def reset_per_config_state(self) -> None:
        self.key = None
        self.salt = self._metadata_candidates[0]["salt"]
        self._key_candidates = None

    # Given an initialization vector and ciphertext, creates a Cipher
    # object with the AES key and specified IV and decrypts the ciphertext
    def _decrypt(self, iv: bytes, ciphertext: bytes) -> bytes:
        logger.debug(
            "Decrypting %d bytes with key %s and IV %s...",
            len(ciphertext),
            self.key.hex(),
            iv.hex(),
        )
        cipher = AES.new(self.key, mode=self._aes_algo, iv=iv)

        padded_text = cipher.decrypt(ciphertext)
        try:
            # Attempt to unpad
            unpadded_text = unpad(padded_text, AES.block_size)
        except Exception as e:
            raise ConfigParserException(
                f"Error decrypting ciphertext {ciphertext} with IV {iv.hex()} and key {self.key.hex()} : {e}"
            ) from e
        logger.debug("Decryption result: %r", unpadded_text)
        return unpadded_text

    # Derives AES passphrase candidates from a config
    #
    # If a passphrase is base64-encoded, both its raw value and decoded value
    # will be added as candidates
    def _derive_aes_passphrase_candidates(self, key_val: str) -> list[bytes]:
        passphrase_candidates = [key_val.encode()]
        with suppress(Exception):
            decoded = strict_b64decode(key_val)
            if decoded is not None and decoded not in passphrase_candidates:
                passphrase_candidates.append(decoded)
        logger.debug("AES passphrase candidates found: %d", len(passphrase_candidates))
        return passphrase_candidates

    # Lazily derives (key, salt) candidates so PBKDF2 stops as soon as one works
    def _iter_aes_key_candidates(
        self,
        passphrase_specs: list[tuple[dict, bytes]],
        derived_cache: list[tuple[bytes, bytes]],
        seen_keys: set[bytes],
        next_spec_idx: list[int],
    ) -> Iterator[tuple[bytes, bytes]]:
        yield from derived_cache
        while next_spec_idx[0] < len(passphrase_specs):
            meta, candidate = passphrase_specs[next_spec_idx[0]]
            next_spec_idx[0] += 1
            try:
                key = pbkdf2_hmac(
                    "sha1",
                    candidate,
                    meta["salt"],
                    meta["iterations"],
                    self._key_size,
                )
            except Exception as e:
                logger.debug("Error in key generation: %s", e)
                continue
            if key not in seen_keys:
                seen_keys.add(key)
                pair = (key, meta["salt"])
                derived_cache.append(pair)
                logger.debug("AES key derived: %s", key.hex())
                yield pair

    # Decrypts encrypted config values with the provided cipher data
    def decrypt_encrypted_strings(
        self, encrypted_strings: dict[str, str]
    ) -> dict[str, str]:
        logger.debug("Decrypting encrypted strings...")
        # Collect candidate (meta, passphrase) specs upfront in O(1) without
        # running PBKDF2 yet; fail fast if no metadata key field is present.
        passphrase_specs: list[tuple[dict, bytes]] = []
        for meta in self._metadata_candidates:
            try:
                field_name = self._payload.field_name_from_rva(meta["key_rva"])
            except ConfigParserException:
                continue
            if field_name not in encrypted_strings:
                continue
            key_raw_value = encrypted_strings[field_name]
            for candidate in self._derive_aes_passphrase_candidates(key_raw_value):
                passphrase_specs.append((meta, candidate))

        if not passphrase_specs:
            raise ConfigParserException(
                "Could not derive key from any metadata candidate"
            )

        derived_cache: list[tuple[bytes, bytes]] = []
        seen_keys: set[bytes] = set()
        next_spec_idx = [0]

        decrypted_config_strings = {}
        attempted_decryptions = 0
        successfully_decrypted_count = 0
        successful_key: bytes | None = None
        successful_salt: bytes | None = None

        for k, v in encrypted_strings.items():
            # Leave empty strings as they are
            if len(v) == 0:
                logger.debug("Key: %s, Value: %s", k, v)
                decrypted_config_strings[k] = v
                continue

            # Strictly check if base64-encoded string and meets minimum length
            decoded_val = strict_b64decode(v)
            if (
                decoded_val is None
                or len(decoded_val) < self._MIN_CIPHERTEXT_LEN + AES.block_size
            ):
                logger.debug("Key: %s, Value: %s", k, v)
                decrypted_config_strings[k] = v
                continue

            # Extract the IV from the 16 bytes after the HMAC (first 32 bytes)
            # and the ciphertext from the rest of the data after the IV
            iv, ciphertext = decoded_val[32:48], decoded_val[48:]
            if len(ciphertext) % AES.block_size != 0:
                logger.debug("Key: %s, Value: %s", k, v)
                decrypted_config_strings[k] = v
                continue

            # Past this point we are actually attempting a decryption
            attempted_decryptions += 1
            result, last_exc = None, None

            # Try the successful key first if we found one
            if successful_key is not None:
                try:
                    self.key = successful_key
                    result = decode_bytes(self._decrypt(iv, ciphertext))
                except (ValueError, ConfigParserException) as e:
                    last_exc = e
                    result = None

            # Run through key candidates lazily until suitable one found or failure
            if result is None:
                for candidate_key, candidate_salt in self._iter_aes_key_candidates(
                    passphrase_specs, derived_cache, seen_keys, next_spec_idx
                ):
                    if candidate_key == successful_key:
                        continue
                    try:
                        self.key = candidate_key
                        result = decode_bytes(self._decrypt(iv, ciphertext))
                        successful_key = candidate_key
                        successful_salt = candidate_salt
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

        # Only raise if we actually tried to decrypt at least one string and
        # none succeeded. Template/builder samples have 0 attempts (all values
        # are placeholders that fail the b64/length filter above), and should
        # fall through cleanly so this AES decryptor remains the active one
        # and its salt is still reported.
        if attempted_decryptions > 0 and successfully_decrypted_count == 0:
            raise ConfigParserException(
                "No strings could be decrypted with the available keys"
            )

        # Set the key and matching salt to the successful candidate for reporting
        if successful_key is not None:
            self.key = successful_key
            if successful_salt is not None:
                self.salt = successful_salt
        else:
            self.key = None

        self._key_candidates = derived_cache
        logger.debug("Successfully decrypted strings")
        return decrypted_config_strings

    # Extracts AES key candidates from the payload
    def _get_aes_key_candidates(
        self, encrypted_strings: dict[str, str]
    ) -> list[bytes]:
        logger.debug("Extracting AES key candidates...")
        keys = []

        # We need to try all combinations of metadata candidates and their passphrase candidates
        for meta in self._metadata_candidates:
            field_name = self._payload.field_name_from_rva(meta["key_rva"])
            if field_name not in encrypted_strings:
                continue

            key_raw_value = encrypted_strings[field_name]
            passphrase_candidates = self._derive_aes_passphrase_candidates(key_raw_value)

            for candidate in passphrase_candidates:
                try:
                    key = pbkdf2_hmac(
                        "sha1",
                        candidate,
                        meta["salt"],
                        meta["iterations"],
                        self._key_size,
                    )
                    if key not in keys:
                        keys.append(key)
                        logger.debug("AES key derived: %s", key.hex())
                except Exception as e:
                    logger.debug("Error in key generation: %s", e)
                    continue
        if len(keys) == 0:
            raise ConfigParserException(
                "Could not derive key from any metadata candidate"
            )
        return keys

    # Extracts the AES key and block size from the payload
    def _get_aes_key_and_block_size_and_algo(self) -> Tuple[int, int, int]:
        logger.debug("Extracting AES key and block size...")
        hit = re.search(self._PATTERN_AES_KEY_AND_BLOCK_SIZE_AND_ALGO, self._payload.data)
        if hit is None:
            raise ConfigParserException("Could not extract AES key or block size")

        groups = hit.groups()
        if groups[0] is not None:
            raw_key_size, raw_block_size, algo_id = groups[0], groups[1], groups[2]
        else:
            raw_key_size, raw_block_size, algo_id = groups[3], groups[4], groups[5]

        # Convert key size from bits to bytes by dividing by 8
        # Note use of // instead of / to ensure integer output, not float
        key_size = bytes_to_int(raw_key_size) // 8
        if key_size not in self._VALID_KEY_SIZES:
            raise ConfigParserException(f"Invalid AES key size: {key_size}")
        block_size = bytes_to_int(raw_block_size)
        if algo_id not in self._ALGO_MAP:
            raise ConfigParserException("Could not extract AES algorithm ID byte")
        logger.debug("Found key size %d and block size %d", key_size, block_size)
        return key_size, block_size, self._ALGO_MAP[algo_id]

    # Given an offset to an instruction within the Method that sets up the
    # Cipher, extracts the AES key RVA from the payload
    def _get_aes_key_rva(self, metadata_ins_offset: int) -> int:
        logger.debug("Extracting AES key RVA...")

        # Get the RVA of the method that sets up AES256 metadata
        metadata_method_token = self._payload.method_from_instruction_offset(
            metadata_ins_offset
        ).token
        # Insert this RVA into the KEY_BASE pattern to find where the AES key
        # is initialized
        key_hit = re.search(
            self._PATTERN_AES_KEY_BASE % re.escape(int_to_bytes(metadata_method_token)),
            self._payload.data,
            re.DOTALL,
        )
        if key_hit is None:
            raise ConfigParserException("Could not find AES key pattern")

        key_rva = bytes_to_int(key_hit.groups()[0])
        logger.debug("AES key RVA: %s", hex(key_rva))
        return key_rva

    # Identifies the initialization of the AES256 object in the payload and
    # sets the necessary values needed for decryption
    def _get_aes_metadata(self) -> None:
        logger.debug("Extracting AES metadata...")
        self._metadata_candidates = []
        # Some payloads have multiple embedded salt values:
        # Find the ones that are actually used for initialization
        for hit in re.finditer(self._PATTERN_AES_SALT_ITER, self._payload.data):
            try:
                iterations = bytes_to_int(hit.groups()[1])
                if not (1 <= iterations <= self._MAX_PBKDF2_ITERATIONS):
                    raise ConfigParserException(
                        f"PBKDF2 iteration count out of bounds: {iterations}"
                    )
                salt = self._get_aes_salt(hit.groups()[0])
                key_rva = self._get_aes_key_rva(hit.start())
                self._metadata_candidates.append(
                    {"salt": salt, "key_rva": key_rva, "iterations": iterations}
                )
            except ConfigParserException as cfe:
                logger.info(
                    "Initialization using salt candidate %s failed: %s",
                    hex(bytes_to_int(hit.groups()[0])),
                    cfe,
                )
                continue
        if not self._metadata_candidates:
            raise ConfigParserException("Could not identify AES metadata")

        # Key size, block size, and algo are properties of the embedded AES
        # class definition, not of any single salt/iter candidate, so they are
        # extracted once and shared across all metadata candidates
        self._key_size, self._block_size, self._aes_algo = (
            self._get_aes_key_and_block_size_and_algo()
        )

        # Legacy fields for backward compatibility, use first valid candidate
        self.salt = self._metadata_candidates[0]["salt"]
        self._key_rva = self._metadata_candidates[0]["key_rva"]
        self._iterations = self._metadata_candidates[0]["iterations"]

    # Extracts the AES salt from the payload, accounting for both hardcoded
    # salt byte arrays, and salts derived from hardcoded strings
    def _get_aes_salt(self, salt_rva: bytes) -> bytes:
        logger.debug("Extracting AES salt value...")

        # Use % to insert our salt RVA into our match pattern
        # This pattern will then find the salt initialization ops,
        # specifically:
        #
        # stsfld	uint8[] Client.Algorithm.Aes256::Salt
        # ret
        needle = self._PATTERN_AES_SALT_INIT % salt_rva
        search_pos = 0
        last_error = "Could not identify AES salt initialization"
        while True:
            aes_salt_initialization = self._payload.data.find(needle, search_pos)
            if aes_salt_initialization == -1:
                raise ConfigParserException(last_error)
            search_pos = aes_salt_initialization + 1

            # Look at the opcode used to initialize the salt to decide how to
            # proceed with extracting the salt value (start of pattern - 10 bytes)
            salt_op_offset = aes_salt_initialization - 10
            if salt_op_offset < 0:
                last_error = "Salt initialization offset out of bounds"
                continue
            # Need to use bytes([int]) here to properly convert from int to byte
            # string for our comparison below
            salt_op = bytes([self._payload.data[salt_op_offset]])

            # Get the salt RVA from the 4 bytes following the initialization op
            salt_strings_rva_packed = self._payload.data[
                salt_op_offset + 1 : salt_op_offset + 5
            ]
            salt_strings_rva = bytes_to_int(salt_strings_rva_packed)

            # If the op is a ldstr op, just get the bytes value of the string being
            # used to initialize the salt
            if salt_op == OPCODE_LDSTR:
                try:
                    salt_encoded = self._payload.user_string_from_rva(salt_strings_rva)
                    salt = salt_encoded.encode("utf-8")
                    logger.debug("Found salt value: %s", salt.hex())
                    return salt
                except ConfigParserException as e:
                    last_error = str(e)
                    continue
            # If the op is a ldtoken (0xd0) operation, we need to get the salt
            # byte array value from the FieldRVA table
            if salt_op == OPCODE_LDTOKEN:
                if salt_op_offset - 7 < 0:
                    last_error = "Salt size offset out of bounds"
                    continue
                try:
                    salt_size = self._payload.data[salt_op_offset - 7]
                    salt = self._payload.byte_array_from_size_and_rva(
                        salt_size, salt_strings_rva
                    )
                    logger.debug("Found salt value: %s", salt.hex())
                    return salt
                except ConfigParserException as e:
                    last_error = str(e)
                    continue
            last_error = f"Unknown salt opcode found: {salt_op.hex()}"
