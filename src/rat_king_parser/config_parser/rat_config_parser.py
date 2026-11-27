#!/usr/bin/env python3
#
# rat_config_parser.py
#
# Author: jeFF0Falltrades
#
# Provides the primary functionality for parsing configurations from RATs
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
from logging import getLogger
from os.path import isfile
from re import DOTALL, compile, search
from typing import Any, Tuple

from yara import Rules

from .config_parser_exception import ConfigParserException
from .utils import config_item
from .utils.config_normalization import check_key_n_value
from .utils.decryptors import (
    SUPPORTED_DECRYPTORS,
    ConfigDecryptor,
    IncompatibleDecryptorException,
)
from .utils.decryptors.config_decryptor_plaintext import (
    KNOWN_CONFIG_FIELD_NAMES_NORMALIZED,
)
from .utils.dotnetpe_payload import DotNetPEPayload

logger = getLogger(__name__)


class RATConfigParser:
    # Min and max number of items in a potential config section
    _MIN_CONFIG_LEN_FLOOR = 5
    _MIN_CONFIG_LEN_CEILING = 9

    # Pattern to find the VerifyHash() method
    _PATTERN_VERIFY_HASH = compile(
        rb"\x7e.{3}\x04(?:\x6f.{3}\x0a){2}\x74.{3}\x01", DOTALL
    )

    def __init__(
        self,
        file_path: str = "",
        yara_rule: Rules | None = None,
        data: bytes | None = None,
        remap_config: bool = False,
        preserve_obfuscated_keys: bool = False,
    ) -> None:
        self.report = {
            "file_path": file_path,
            "sha256": "",
            "yara_possible_family": "",
            "key": "",
            "salt": "",
            "config": {},
        }
        self.error: str | None = None
        self.remap_config = remap_config
        self.preserve_obfuscated_keys = preserve_obfuscated_keys
        self._dnpp: DotNetPEPayload | None = None
        self._decryptor: ConfigDecryptor | None = None
        # Binary-level decryptor cache so metadata regexes run once per payload
        self._decryptor_cache: dict[type[ConfigDecryptor], ConfigDecryptor] = {}
        self._incompatible_decryptors: set[type[ConfigDecryptor]] = set()
        try:
            if data is None and not isfile(file_path):
                raise ConfigParserException("File not found")
            self._dnpp = DotNetPEPayload(file_path, yara_rule, data)
            self.report["sha256"] = self._dnpp.sha256
            self.report["yara_possible_family"] = self._dnpp.yara_match

            # Assigned in _decrypt_and_decode_config()
            self.report["config"] = self._get_config()
            key_hex = "None"
            if self._decryptor is not None and self._decryptor.key is not None:
                if isinstance(self._decryptor.key, bytes):
                    key_hex = self._decryptor.key.hex()
                else:
                    key_hex = str(self._decryptor.key)
            self.report["key"] = key_hex
            self.report["salt"] = (
                self._decryptor.salt.hex()
                if self._decryptor is not None and self._decryptor.salt is not None
                else "None"
            )
        except Exception as e:
            self.error = f"Exception encountered for {file_path}: {e}"
            self.report["config"] = self.error

    # Extracts raw config items (without running decryption) once per method body
    def _extract_raw_config_items(
        self, encrypted_config: bytes
    ) -> tuple[list[tuple[config_item.ConfigItem, dict[str, Any]]], dict[int, str], int]:
        parsed_buckets = config_item.parse_config_items(
            encrypted_config,
            field_sig_lookup=self._dnpp.field_signature_from_rva,
        )
        extracted: list[tuple[config_item.ConfigItem, dict[str, Any]]] = []
        config_fields_map: dict[int, str] = {}
        raw_field_names: set[str] = set()

        for item, raw_entries in parsed_buckets:
            if not raw_entries:
                continue
            item_data: dict[str, Any] = {}
            for k, v in raw_entries.items():
                try:
                    field_name = self._dnpp.field_name_from_rva(k)
                except ConfigParserException as e:
                    logger.debug(
                        "Skipping invalid Field RVA %s in method body: %s",
                        hex(k),
                        e,
                    )
                    continue
                if isinstance(item, config_item.EncryptedStringConfigItem):
                    try:
                        v = self._dnpp.user_string_from_rva(v)
                    except ConfigParserException as e:
                        logger.debug(
                            "Skipping invalid UserString RVA %s for field %s: %s",
                            hex(v),
                            field_name,
                            e,
                        )
                        continue
                elif isinstance(item, config_item.ByteArrayConfigItem):
                    arr_size, arr_rva = v
                    try:
                        v = self._dnpp.byte_array_from_size_and_rva(
                            arr_size, arr_rva
                        ).hex()
                    except ConfigParserException as e:
                        logger.debug(
                            "Skipping invalid ByteArray for field %s: %s",
                            field_name,
                            e,
                        )
                        continue
                config_fields_map[k] = field_name
                item_data[field_name] = v
                raw_field_names.add(field_name)
            if item_data:
                extracted.append((item, item_data))

        return extracted, config_fields_map, len(raw_field_names)

    # Decrypts/decodes values from pre-extracted raw config items
    def _decode_extracted_config(
        self,
        extracted: list[tuple[config_item.ConfigItem, dict[str, Any]]],
        config_fields_map: dict[int, str],
        raw_count: int,
        min_config_len: int,
    ) -> dict[str, Any]:
        # Fast-reject before running expensive decryptors (allow +1 for
        # decryptors that append a dynamic field such as hardcoded_hosts or
        # xor_decoded_strings).
        has_url_host = any("UrlHost" in item_data for _, item_data in extracted)
        if raw_count + 1 < min_config_len and not has_url_host:
            raise ConfigParserException(
                f"Minimum threshold of config items not met: {raw_count}/{min_config_len}"
            )

        decoded_config: dict[str, Any] = {}
        self._decryptor = None
        for item, item_data in extracted:
            if isinstance(item, config_item.EncryptedStringConfigItem):
                item_data = self._attempt_decryption(item_data)
            decoded_config.update(item_data)

        # UrlHost is a marker of a special case until this can be standardized
        if len(decoded_config) < min_config_len and "UrlHost" not in decoded_config:
            self._decryptor = None
            raise ConfigParserException(
                f"Minimum threshold of config items not met: {len(decoded_config)}/{min_config_len}"
            )
        if self.remap_config:
            return self._remap_config(decoded_config, config_fields_map)
        return decoded_config

    # Decrypts/decodes values from an encrypted config and returns the
    # decrypted/decoded config
    def _decrypt_and_decode_config(
        self, encrypted_config: bytes, min_config_len: int
    ) -> dict[str, Any]:
        extracted, config_fields_map, raw_count = self._extract_raw_config_items(
            encrypted_config
        )
        return self._decode_extracted_config(
            extracted, config_fields_map, raw_count, min_config_len
        )

    def _attempt_decryption(self, item_data: dict[str, Any]) -> dict[str, Any]:
        # Always evaluate decryptors in priority order without leaking state
        # from any previous failed .cctor candidate.
        self._decryptor = None
        for decryptor_cls in SUPPORTED_DECRYPTORS:
            if decryptor_cls in self._incompatible_decryptors:
                continue

            decryptor_instance = self._decryptor_cache.get(decryptor_cls)
            if decryptor_instance is None:
                # Try to instantiate the selected decryptor once per payload;
                # mark incompatible on failure so we never re-scan the binary.
                try:
                    decryptor_instance = decryptor_cls(self._dnpp)
                except IncompatibleDecryptorException as ide:
                    logger.debug(
                        "Decryptor incompatible %s : %s", decryptor_cls, ide
                    )
                    self._incompatible_decryptors.add(decryptor_cls)
                    continue
                self._decryptor_cache[decryptor_cls] = decryptor_instance
            else:
                decryptor_instance.reset_per_config_state()

            try:
                # Try to decrypt the encrypted strings; continue to next
                # compatible decryptor on failure
                decrypted = decryptor_instance.decrypt_encrypted_strings(item_data)
                self._decryptor = decryptor_instance
                return decrypted
            except Exception as e:
                logger.debug(
                    "Decryption failed with decryptor %s : %s", decryptor_cls, e
                )

        # If we exit the loop without returning, no decryptor succeeded
        raise ConfigParserException("All decryptors failed")

    @staticmethod
    def _merge_remapped_value(existing_val: Any, value: Any) -> Any:
        if isinstance(existing_val, list):
            if isinstance(value, list):
                return existing_val + value
            if value not in ("", None):
                return [*existing_val, value]
            return existing_val

        if isinstance(existing_val, str):
            if not value:
                return existing_val
            new_val = ",".join(map(str, value)) if isinstance(value, list) else str(value)
            if not existing_val:
                return new_val
            return f"{existing_val},{new_val}"

        # Preserve non-str/non-list collisions (e.g. int + str/list) as a list
        if value in ("", None, []):
            return existing_val
        if isinstance(value, list):
            return [existing_val, *value]
        return [existing_val, value]

    def _remap_config(
        self, decoded_config: dict[str, Any], config_fields_map: dict[int, str]
    ) -> dict[str, Any]:
        remapped_config: dict[str, Any] = {}
        processed_keys: set[str] = set()

        for k in sorted(config_fields_map.keys()):
            key_name = config_fields_map[k]
            if key_name in processed_keys or key_name not in decoded_config:
                continue
            processed_keys.add(key_name)
            value = decoded_config[key_name]

            # Run normalization (e.g. converting HostsFE -> Hosts)
            key_normalized, value = check_key_n_value(key_name, value)

            # --- LOGIC TO APPEND INSTEAD OF OVERWRITE ---
            if key_normalized in remapped_config:
                remapped_config[key_normalized] = self._merge_remapped_value(
                    remapped_config[key_normalized], value
                )
            else:
                # Key does not exist yet, create it
                remapped_config[key_normalized] = value

        # Ensure config items added by decryptors dynamically (e.g. hardcoded_hosts,
        # xor_decoded_strings) are also normalized and preserved
        for key, val in decoded_config.items():
            if key in processed_keys:
                continue
            key_normalized, norm_val = check_key_n_value(key, val)
            if key_normalized in remapped_config:
                remapped_config[key_normalized] = self._merge_remapped_value(
                    remapped_config[key_normalized], norm_val
                )
            else:
                remapped_config[key_normalized] = norm_val

        return remapped_config

    # Searches for the RAT configuration section, using the VerifyHash() marker
    # or brute-force, returning the decrypted config on success
    def _get_config(self) -> dict[str, Any]:
        logger.debug("Extracting config...")
        try:
            config_start, decrypted_config = self._get_config_verify_hash_method()
        except Exception:
            logger.debug("VerifyHash() method failed; Attempting .cctor brute force...")
            # If the VerifyHash() method does not work, move to brute-forcing
            # static constructors
            try:
                config_start, decrypted_config = self._get_config_cctor_brute_force()
            except Exception as e:
                raise ConfigParserException(f"Could not identify config: {e}") from e
        logger.debug("Config found at RVA %s...", hex(config_start))
        if not self.preserve_obfuscated_keys and self._is_likely_obfuscated_config(
            decrypted_config
        ):
            logger.debug(
                "Preserve keys set to False and possible obfuscation detected; Translating keys..."
            )
            decrypted_config = {
                f"obfuscated_key_{idx}": v
                for idx, (_, v) in enumerate(decrypted_config.items(), 1)
            }

        return decrypted_config

    # Attempts to retrieve the config via brute-force, looking through every
    # static constructor (.cctor) and attempting to decode/decrypt a valid
    # config from that constructor, returning the config RVA and decrypted
    # config on success
    def _get_config_cctor_brute_force(self) -> Tuple[int, dict[str, Any]]:
        candidates = self._dnpp.methods_from_name(".cctor")
        if len(candidates) == 0:
            raise ConfigParserException("No .cctor method could be found")

        # Pre-extract raw config items once per .cctor method and bucket by
        # raw item count (highest priority first) so each .cctor is parsed and
        # decrypted at most once instead of repeating across min_config_len.
        extracted_candidates: list[
            tuple[
                int,
                list[tuple[config_item.ConfigItem, dict[str, Any]]],
                dict[int, str],
                int,
                bool,
            ]
        ] = []
        for method in candidates:
            method_body = self._dnpp.method_body_from_method(method)
            extracted, fields_map, raw_count = self._extract_raw_config_items(
                method_body
            )
            has_url_host = any("UrlHost" in item_data for _, item_data in extracted)
            if raw_count + 1 < self._MIN_CONFIG_LEN_FLOOR and not has_url_host:
                continue
            extracted_candidates.append(
                (method.rva, extracted, fields_map, raw_count, has_url_host)
            )

        # Preserve original priority: >= CEILING first, then descending down to
        # FLOOR, preserving original .cctor order within each bucket.
        def _priority_bucket(entry: tuple) -> int:
            raw_count, has_url_host = entry[3], entry[4]
            if has_url_host or raw_count >= self._MIN_CONFIG_LEN_CEILING:
                return self._MIN_CONFIG_LEN_CEILING
            return raw_count

        extracted_candidates.sort(key=_priority_bucket, reverse=True)

        for method_rva, extracted, fields_map, raw_count, _ in extracted_candidates:
            logger.debug(
                "Attempting brute force at .cctor method at %s", hex(method_rva)
            )
            try:
                decrypted_config = self._decode_extracted_config(
                    extracted,
                    fields_map,
                    raw_count,
                    self._MIN_CONFIG_LEN_FLOOR,
                )
                return method_rva, decrypted_config
            except Exception as e:
                logger.debug(
                    "Brute force failed for method at %s: %s", hex(method_rva), e
                )
                continue

        raise ConfigParserException(
            "No valid configuration could be parsed from any .cctor methods"
        )

    # Attempts to retrieve the config via looking for a config section preceded
    # by the VerifyHash() method typically found in a Settings module,
    # returning the config RVA and decrypted config on success
    def _get_config_verify_hash_method(self) -> Tuple[int, dict[str, Any]]:
        # Identify the VerifyHash() Method code
        verify_hash_hit = search(self._PATTERN_VERIFY_HASH, self._dnpp.data)
        if verify_hash_hit is None:
            raise ConfigParserException("Could not identify VerifyHash() marker")

        # Reverse the hit to find the VerifyHash() method, then grab the
        # subsequent function
        config_method = self._dnpp.method_from_instruction_offset(
            verify_hash_hit.start(), 1
        )
        encrypted_config = self._dnpp.method_body_from_method(config_method)
        decrypted_config = self._decrypt_and_decode_config(
            encrypted_config, self._MIN_CONFIG_LEN_FLOOR
        )
        return config_method.rva, decrypted_config

    def _is_likely_obfuscated_config(self, config: dict[str, Any]) -> bool:
        # Order-independent check: any non-ASCII key signals obfuscation;
        # otherwise check whether any key matches a known config field name
        # (including underscore-stripped normalized forms).
        has_known_key = False
        for key in config.keys():
            if not key.isascii():
                return True
            if key.replace("_", "") in KNOWN_CONFIG_FIELD_NAMES_NORMALIZED:
                has_known_key = True
        return not has_known_key
