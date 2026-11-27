#!/usr/bin/env python3
"""Unit tests covering parser, CIL decoding, decryptors, normalization, CLI, and MACO wrapper."""

from __future__ import annotations

import hashlib
import importlib
import io
import logging
import struct
import sys
import types
from base64 import b64encode
from types import SimpleNamespace

import pytest
from Cryptodome.Cipher import AES, DES3
from Cryptodome.Util.Padding import pad

from rat_king_parser import rkp
from rat_king_parser.config_parser import RATConfigParser
from rat_king_parser.config_parser.config_parser_exception import ConfigParserException
from rat_king_parser.config_parser.utils import config_item
from rat_king_parser.config_parser.utils.config_normalization import check_key_n_value
from rat_king_parser.config_parser.utils.data_utils import bytes_to_int, decode_bytes
from rat_king_parser.config_parser.utils.decryptors import (
    ConfigDecryptorAESWithIV,
    ConfigDecryptorAESWithIV_pbkdf,
    ConfigDecryptorDecryptXOR,
    ConfigDecryptorECB,
    ConfigDecryptorRandomHardcoded,
    ConfigDecryptorRijndael,
    IncompatibleDecryptorException,
)
from rat_king_parser.config_parser.utils.decryptors.config_decryptor import (
    strict_b64decode,
)
from rat_king_parser.config_parser.utils.dotnet_constants import (
    MDT_FIELD_DEF,
    MDT_METHOD_DEF,
    MDT_STRING,
)
from rat_king_parser.config_parser.utils.dotnetpe_payload import (
    DotNetPEMethod,
    DotNetPEPayload,
)


def _tiny_method(il: bytes) -> bytes:
    assert len(il) < 64
    return bytes([(len(il) << 2) | 0x02]) + il


def _fat_method(il: bytes, header_dwords: int = 3) -> bytes:
    flags16 = 0x0003 | ((header_dwords & 0x0F) << 12)
    header = struct.pack("<HHII", flags16, 8, len(il), 0)
    extra = b"\x00" * max(0, header_dwords * 4 - 12)
    return header + extra + il


def _token(table_prefix: int, rid: int) -> bytes:
    return struct.pack("<I", table_prefix | rid)


class _StubPayload:
    """Minimal DotNetPEPayload stand-in for testing decryptors and RATConfigParser."""

    def __init__(
        self,
        data: bytes = b"",
        fields: dict[int, str] | None = None,
        field_sigs: dict[int, bytes] | None = None,
        strings: dict[int, str] | None = None,
        field_rvas: dict[int, int] | None = None,
        methods: list[DotNetPEMethod] | None = None,
    ) -> None:
        self.data = data
        self.sha256 = hashlib.sha256(data).hexdigest()
        self.yara_match = "No match"
        self._fields = fields or {}
        self._field_sigs = field_sigs or {}
        self._strings = strings or {}
        self._field_rvas = field_rvas or {}
        self._methods = methods or []
        self._methods_by_offset = sorted(self._methods, key=lambda m: m.offset)
        self._methods_by_token = sorted(self._methods, key=lambda m: m.token)

    def field_name_from_rva(self, rva: int) -> str:
        if rva not in self._fields:
            raise ConfigParserException(f"Field not found: {hex(rva)}")
        return self._fields[rva]

    def field_signature_from_rva(self, rva: int) -> bytes | None:
        return self._field_sigs.get(rva)

    def user_string_from_rva(self, rva: int) -> str:
        if rva not in self._strings:
            raise ConfigParserException(f"User string not found: {hex(rva)}")
        return self._strings[rva]

    def fieldrva_from_rva(self, rva: int) -> int:
        if rva not in self._field_rvas:
            raise ConfigParserException(f"FieldRVA not found: {hex(rva)}")
        return self._field_rvas[rva]

    def offset_from_rva(self, rva: int) -> int:
        return rva

    def byte_array_from_size_and_rva(self, arr_size: int, arr_rva: int) -> bytes:
        off = self.fieldrva_from_rva(arr_rva)
        return self.data[off : off + arr_size]

    def method_body_from_method(self, method: DotNetPEMethod) -> bytes:
        return self.data[method.offset : method.offset + method.size]

    def methods_from_name(self, name: str) -> list[DotNetPEMethod]:
        return [m for m in self._methods if m.name == name]

    def method_from_instruction_offset(
        self, ins_offset: int, step: int = 0, by_token: bool = False
    ) -> DotNetPEMethod:
        for idx, m in enumerate(self._methods_by_offset):
            if m.offset <= ins_offset < m.offset + m.size:
                if step == 0:
                    return m
                if by_token:
                    t_idx = next(
                        i
                        for i, tm in enumerate(self._methods_by_token)
                        if tm.token == m.token
                    )
                    target = t_idx + step
                    if 0 <= target < len(self._methods_by_token):
                        return self._methods_by_token[target]
                    raise ConfigParserException("Out of bounds")
                target = idx + step
                if 0 <= target < len(self._methods_by_offset):
                    return self._methods_by_offset[target]
                raise ConfigParserException("Out of bounds")
        raise ConfigParserException(f"Method not found at {hex(ins_offset)}")


# ---------------------------------------------------------------------------
# 1. Package __all__ exports
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "module_name",
    [
        "rat_king_parser",
        "rat_king_parser.config_parser",
        "rat_king_parser.config_parser.utils.decryptors",
        "rat_king_parser.yara_utils",
    ],
)
def test_package_all_contains_valid_strings(module_name: str) -> None:
    mod = importlib.import_module(module_name)
    assert hasattr(mod, "__all__")
    for name in mod.__all__:
        assert isinstance(name, str), f"{module_name}.__all__ has non-str entry: {name!r}"
        assert hasattr(mod, name), f"{module_name} missing exported symbol {name}"


# ---------------------------------------------------------------------------
# 2. data_utils & strict_b64decode
# ---------------------------------------------------------------------------


def test_bytes_to_int_signed_and_unsigned() -> None:
    assert bytes_to_int(b"\xff\xff\xff\xff", signed=False) == 0xFFFFFFFF
    assert bytes_to_int(b"\xff\xff\xff\xff", signed=True) == -1
    assert bytes_to_int(b"\xec\xff\xff\xff", signed=True) == -20


def test_decode_bytes_preserves_whitespace_and_avoids_mojibake() -> None:
    # Must not silently strip whitespace from string inputs (e.g. string AES salts)
    assert decode_bytes(" 1.0.7") == " 1.0.7"
    assert decode_bytes(" mySalt ") == " mySalt "
    # Standard UTF-8
    assert decode_bytes(b" 1.0.7") == " 1.0.7"
    # Genuine UTF-16LE (ASCII and accented Latin)
    assert decode_bytes("127.0.0.1".encode("utf-16le")) == "127.0.0.1"
    assert decode_bytes("Ingresá".encode("utf-16le")) == "Ingresá"
    assert decode_bytes("A".encode("utf-16le")) == "A"
    # Even-length null-terminated / null-padded UTF-8 must NOT decode as CJK mojibake
    assert decode_bytes(b"127.0.0.1\x00") == "127.0.0.1"
    assert decode_bytes(b"80\x00\x00") == "80"
    assert decode_bytes(b"1234\x00\x00\x00\x00") == "1234"
    # Non-null control bytes (e.g. wrong-key ECB fallback) must raise
    with pytest.raises(ConfigParserException):
        decode_bytes(b"\x01\x02\x03\x04\x05\x06\x07\x08")
    # Wrong-key random block containing a stray 0x00 and control bytes must raise
    with pytest.raises(ConfigParserException):
        decode_bytes(b"\x01\x02\x00\x04\x05\x06\x07\x08\x09\x0b\x0c\x0e\x0f\x10\x11\x12")


def test_strict_b64decode_rejects_plaintext_with_spaces_or_placeholders() -> None:
    assert strict_b64decode("%Serversignature%") is None
    assert (
        strict_b64decode(
            "Venom RAT + HVNC + Stealer + Grabber v6.0.3 with lots of words here"
        )
        is None
    )
    payload = b"hello world!" * 6
    encoded = b64encode(payload).decode()
    assert strict_b64decode(encoded) == payload
    assert strict_b64decode(encoded[:16] + "\r\n" + encoded[16:]) == payload


# ---------------------------------------------------------------------------
# 3. config_item & CIL instruction walker
# ---------------------------------------------------------------------------


def test_cil_walker_avoids_unaligned_collisions_and_preserves_order() -> None:
    # Build a Fat CIL method containing:
    # - ldc.i4 0x14000000 -> stsfld 1 (operand byte 0x14 must NOT match NullConfigItem!)
    # - ldc.i4 0x17000000 -> stsfld 2 (operand byte 0x17 must NOT match BoolConfigItem!)
    # - ldc.i4.m1         -> stsfld 3 (-1)
    # - ldc.i4.s 26       -> stsfld 4 (SpecialFolder enum -> APPLICATIONDATA)
    # - ldc.i4.s 26       -> stsfld 5 (primitive int32 -> 26)
    # - ldc.i4.1          -> stsfld 6 (True)
    # - ldnull            -> stsfld 7 ("null")
    # - ldstr 0x70000001  -> stsfld 8
    # - ldc.i4 200; newarr; dup; ldtoken 0x0400000A; call; stsfld 9 (large byte array)
    il = b"".join(
        [
            b"\x20" + struct.pack("<i", 0x14000000) + b"\x80" + _token(MDT_FIELD_DEF, 1),
            b"\x20" + struct.pack("<i", 0x17000000) + b"\x80" + _token(MDT_FIELD_DEF, 2),
            b"\x15\x80" + _token(MDT_FIELD_DEF, 3),
            b"\x1f\x1a\x80" + _token(MDT_FIELD_DEF, 4),
            b"\x1f\x1a\x80" + _token(MDT_FIELD_DEF, 5),
            b"\x17\x80" + _token(MDT_FIELD_DEF, 6),
            b"\x14\x80" + _token(MDT_FIELD_DEF, 7),
            b"\x72" + _token(MDT_STRING, 1) + b"\x80" + _token(MDT_FIELD_DEF, 8),
            b"\x20"
            + struct.pack("<i", 200)
            + b"\x8d\x01\x00\x00\x01\x25\xd0"
            + _token(MDT_FIELD_DEF, 10)
            + b"\x28\x01\x00\x00\x0a\x80"
            + _token(MDT_FIELD_DEF, 9),
            b"\x2a",
        ]
    )
    sigs = {
        MDT_FIELD_DEF | 4: b"\x06\x11\x20",  # ELEMENT_TYPE_VALUETYPE (SpecialFolder)
        MDT_FIELD_DEF | 5: b"\x06\x08",  # ELEMENT_TYPE_I4 (int)
    }
    buckets = config_item.parse_config_items(_fat_method(il), field_sig_lookup=sigs.get)
    by_cls = {type(item): vals for item, vals in buckets}

    # Exact category order preserved
    assert [type(item) for item, _ in buckets] == config_item.SUPPORTED_CONFIG_ITEMS
    assert by_cls[config_item.BoolConfigItem] == {MDT_FIELD_DEF | 6: True}
    assert by_cls[config_item.ByteArrayConfigItem] == {
        MDT_FIELD_DEF | 9: (200, MDT_FIELD_DEF | 10)
    }
    assert by_cls[config_item.IntConfigItem] == {
        MDT_FIELD_DEF | 1: 0x14000000,
        MDT_FIELD_DEF | 2: 0x17000000,
        MDT_FIELD_DEF | 3: -1,
        MDT_FIELD_DEF | 5: 26,
    }
    assert by_cls[config_item.NullConfigItem] == {MDT_FIELD_DEF | 7: "null"}
    assert by_cls[config_item.SpecialFolderConfigItem] == {
        MDT_FIELD_DEF | 4: "APPLICATIONDATA"
    }
    assert by_cls[config_item.EncryptedStringConfigItem] == {
        MDT_FIELD_DEF | 8: MDT_STRING | 1
    }
    # Invalid Fat headers with Size nibble < 3 (< 12 bytes) must be rejected
    assert config_item._extract_cil_il_bytes(_fat_method(b"\x2a", header_dwords=0)) is None
    assert config_item._extract_cil_il_bytes(_fat_method(b"\x2a", header_dwords=1)) is None
    assert config_item._extract_cil_il_bytes(_fat_method(b"\x2a", header_dwords=2)) is None


def test_config_item_parse_from_exception_does_not_crash_on_hex_bytes() -> None:
    class _FailingItem(config_item.ConfigItem):
        def __init__(self) -> None:
            super().__init__("failing", b"(\x16)\x80(.{3}\x04)")

        def _derive_item_value(self, raw_value: bytes) -> int:
            raise ValueError("forced failure")

    # Previously raised TypeError: 'bytes' object cannot be interpreted as an integer
    assert _FailingItem().parse_from(b"\x16\x80\x01\x00\x00\x04") == {}


# ---------------------------------------------------------------------------
# 4. DotNetPEPayload edge cases
# ---------------------------------------------------------------------------


def _make_bare_payload(data: bytes) -> DotNetPEPayload:
    obj = DotNetPEPayload.__new__(DotNetPEPayload)
    obj.file_path = "mem"
    obj.data = data
    obj.sha256 = hashlib.sha256(data).hexdigest()
    obj.yara_match = ""
    obj._field_rva_map = {}
    obj._field_table = None
    obj._methods = []
    obj._methods_by_offset = []
    obj._methods_by_token = []
    obj._offsets = []
    obj._tokens = []
    return obj


def test_dotnetpe_tiny_header_size_rva_zero_and_bounds() -> None:
    tiny_il = b"\x72" + _token(MDT_STRING, 1) + b"\x2a"  # 6 bytes IL + 1 byte hdr = 7
    tiny_bytes = _tiny_method(tiny_il)
    fat_il = b"\x00\x2a"
    fat_bytes = _fat_method(fat_il, header_dwords=4)  # 16-byte header + 2 = 18
    bad_fat_bytes = _fat_method(fat_il, header_dwords=2)  # invalid < 12-byte Fat header

    raw = b"MZ" + b"\x00" * 14 + tiny_bytes + fat_bytes + bad_fat_bytes
    tiny_off = 16
    fat_off = 16 + len(tiny_bytes)
    bad_fat_off = fat_off + len(fat_bytes)

    payload = _make_bare_payload(raw)
    rows = [
        SimpleNamespace(Rva=0, Name=SimpleNamespace(value="DllImportZero")),
        SimpleNamespace(Rva=0x999999, Name=SimpleNamespace(value="InvalidRva")),
        SimpleNamespace(Rva=tiny_off, Name=SimpleNamespace(value="TinyMethod")),
        SimpleNamespace(Rva=fat_off, Name=SimpleNamespace(value="FatMethod")),
        SimpleNamespace(Rva=bad_fat_off, Name=SimpleNamespace(value="BadFatMethod")),
    ]
    payload.dotnetpe = SimpleNamespace(
        net=SimpleNamespace(
            mdtables=SimpleNamespace(MethodDef=SimpleNamespace(rows=rows)),
            user_strings=None,
        ),
        get_offset_from_rva=lambda rva: (_ for _ in ()).throw(ValueError("bad"))
        if rva == 0x999999
        else rva,
    )

    methods = payload._generate_method_list()
    assert [m.name for m in methods] == ["TinyMethod", "FatMethod", "BadFatMethod"]
    # Tiny method must include the full body including trailing ret (0x2a)
    assert methods[0].size == len(tiny_bytes)
    assert payload.method_body_from_method(methods[0]) == tiny_bytes
    # Fat method respects 4-dword header size (16 + 2 = 18)
    assert methods[1].size == len(fat_bytes)
    # Invalid Fat header nibble < 3 yields 0-size method rather than slicing header
    assert methods[2].size == 0

    payload._methods = methods
    payload._methods_by_offset = sorted(methods, key=lambda m: m.offset)
    payload._methods_by_token = methods
    payload._offsets = [m.offset for m in payload._methods_by_offset]
    payload._tokens = [m.token for m in payload._methods_by_token]

    # Bounds checks on method_from_instruction_offset (no IndexError / negative wrap)
    assert payload.method_from_instruction_offset(tiny_off + 6, step=0).name == "TinyMethod"
    assert payload.method_from_instruction_offset(tiny_off, step=1).name == "FatMethod"
    with pytest.raises(ConfigParserException):
        payload.method_from_instruction_offset(tiny_off, step=-1)
    with pytest.raises(ConfigParserException):
        payload.method_from_instruction_offset(fat_off, step=2)
    with pytest.raises(ConfigParserException):
        payload.method_from_instruction_offset(fat_off, step=2, by_token=True)

    # user_string_from_rva raises ConfigParserException when user_strings is None or value is None
    with pytest.raises(ConfigParserException):
        payload.user_string_from_rva(MDT_STRING | 1)
    payload.dotnetpe.net.user_strings = SimpleNamespace(
        get=lambda _idx: SimpleNamespace(value=None)
    )
    with pytest.raises(ConfigParserException):
        payload.user_string_from_rva(MDT_STRING | 1)


def test_dotnetpe_field_name_and_byte_string_bounds() -> None:
    payload = _make_bare_payload(b"hello\x00world")
    payload._field_table = SimpleNamespace(
        rows=[
            SimpleNamespace(Name=SimpleNamespace(value="FieldOne")),
            SimpleNamespace(Name=SimpleNamespace(value=None)),
        ]
    )
    assert payload.field_name_from_rva(MDT_FIELD_DEF | 1) == "FieldOne"
    # Invalid UTF-8 Field.Name (value=None) must raise ConfigParserException
    with pytest.raises(ConfigParserException):
        payload.field_name_from_rva(MDT_FIELD_DEF | 2)
    # RID 0 (0x04000000) must raise, not wrap to rows[-1]
    with pytest.raises(ConfigParserException):
        payload.field_name_from_rva(MDT_FIELD_DEF)
    # Non-FieldDef token must raise
    with pytest.raises(ConfigParserException):
        payload.field_name_from_rva(MDT_STRING | 1)

    assert payload.byte_string_from_offset(0) == b"hello"
    assert payload.byte_string_from_offset(6) == b"world"
    with pytest.raises(ConfigParserException):
        payload.byte_string_from_offset(-1)


def test_dotnetpe_empty_bytes_raises_config_parser_exception() -> None:
    with pytest.raises(ConfigParserException):
        DotNetPEPayload(file_path="", data=b"")


def test_dotnetpe_custom_attribute_from_type_fixes() -> None:
    payload = _make_bare_payload(b"")
    prop_table = SimpleNamespace(
        rows=[
            SimpleNamespace(Name=SimpleNamespace(value="OtherTypeProp")),
            SimpleNamespace(Name=SimpleNamespace(value="ReverseProxyPort")),
            SimpleNamespace(Name=SimpleNamespace(value="LongValue")),
        ]
    )
    td_table = SimpleNamespace(
        rows=[
            SimpleNamespace(
                TypeNamespace=SimpleNamespace(value="Server.Properties"),
                TypeName=SimpleNamespace(value="WrongType"),
            ),
            SimpleNamespace(
                TypeNamespace=SimpleNamespace(value="Server.Properties"),
                TypeName=SimpleNamespace(value="Settings"),
            ),
        ]
    )
    pm_table = SimpleNamespace(
        rows=[
            SimpleNamespace(
                Parent=SimpleNamespace(row_index=1),
                PropertyList=[SimpleNamespace(row_index=1)],
            ),
            SimpleNamespace(
                Parent=SimpleNamespace(row_index=2),
                PropertyList=[
                    SimpleNamespace(row_index=2),
                    SimpleNamespace(row_index=3),
                ],
            ),
        ]
    )
    long_str = "A" * 140
    long_len_encoded = bytes([0x80 | (len(long_str) >> 8), len(long_str) & 0xFF])
    ca_table = SimpleNamespace(
        rows=[
            # MethodDef attribute with row_index=2 must NOT collide with Property row 2
            SimpleNamespace(
                Parent=SimpleNamespace(
                    row_index=2, table=SimpleNamespace(name="MethodDef")
                ),
                Value=SimpleNamespace(value=b"\x01\x00\x05WRONG\x00\x00"),
            ),
            # Property row 1 belongs to WrongType, must NOT be included
            SimpleNamespace(
                Parent=SimpleNamespace(
                    row_index=1, table=SimpleNamespace(name="Property")
                ),
                Value=SimpleNamespace(value=b"\x01\x00\x04NOPE\x00\x00"),
            ),
            # Property row 2 (1-byte compressed length)
            SimpleNamespace(
                Parent=SimpleNamespace(
                    row_index=2, table=SimpleNamespace(name="Property")
                ),
                Value=SimpleNamespace(value=b"\x01\x00\x043128\x00\x00"),
            ),
            # Property row 3 (2-byte compressed length >= 128)
            SimpleNamespace(
                Parent=SimpleNamespace(
                    row_index=3, table=SimpleNamespace(name="Property")
                ),
                Value=SimpleNamespace(
                    value=b"\x01\x00" + long_len_encoded + long_str.encode("utf-8") + b"\x00\x00"
                ),
            ),
        ]
    )
    payload.dotnetpe = SimpleNamespace(
        net=SimpleNamespace(
            mdtables=SimpleNamespace(
                CustomAttribute=ca_table,
                TypeDef=td_table,
                Property=prop_table,
                PropertyMap=pm_table,
            )
        )
    )
    result = payload.custom_attribute_from_type("Server.Properties", "Settings")
    assert result == {"ReverseProxyPort": "3128", "LongValue": long_str}


# ---------------------------------------------------------------------------
# 5. Decryptors
# ---------------------------------------------------------------------------


def _aes_with_iv_encrypt(key: bytes, plaintext: str, mode: int = AES.MODE_CBC) -> str:
    iv = b"\x11" * 16
    ct = AES.new(key, mode, iv=iv).encrypt(pad(plaintext.encode("utf-8"), 16))
    return b64encode(b"\x22" * 32 + iv + ct).decode()


def test_aes_with_iv_second_regex_branch_multi_salt_and_whitespace_salt() -> None:
    salt1 = b"wrong_salt_12345"
    salt2 = b" spaced_salt "  # Must preserve leading/trailing spaces
    iterations = 1000
    passphrase = "MySecretPass"
    real_key = hashlib.pbkdf2_hmac("sha1", passphrase.encode(), salt2, iterations, 32)

    salt1_field_rva = MDT_FIELD_DEF | 1
    salt2_field_rva = MDT_FIELD_DEF | 2
    key_field_rva = MDT_FIELD_DEF | 3
    salt1_str_rva = MDT_STRING | 1
    salt2_str_rva = MDT_STRING | 2
    ctor1_tok = MDT_METHOD_DEF | 1
    ctor2_tok = MDT_METHOD_DEF | 2

    # Salt init blocks: ldstr <salt_str_rva> (5B) + 5B call + stsfld <salt_field_rva> (5B) + ret (1B)
    salt1_init = b"\x72" + struct.pack("<I", salt1_str_rva) + b"\x28\x01\x00\x00\x0a\x80" + struct.pack("<I", salt1_field_rva) + b"\x2a"
    salt2_init = b"\x72" + struct.pack("<I", salt2_str_rva) + b"\x28\x01\x00\x00\x0a\x80" + struct.pack("<I", salt2_field_rva) + b"\x2a"

    # Salt/iter patterns inside two separate ctor methods
    ctor1_body = b"\x02\x7e" + struct.pack("<I", salt1_field_rva) + b"\x20" + struct.pack("<I", iterations) + b"\x73\x01\x00\x00\x0a"
    ctor2_body = b"\x02\x7e" + struct.pack("<I", salt2_field_rva) + b"\x20" + struct.pack("<I", iterations) + b"\x73\x01\x00\x00\x0a"

    # Key init references for both ctors
    key_ref1 = struct.pack("<I", key_field_rva) + b"\x73" + struct.pack("<I", ctor1_tok)
    key_ref2 = struct.pack("<I", key_field_rva) + b"\x73" + struct.pack("<I", ctor2_tok)

    # SECOND branch of _PATTERN_AES_KEY_AND_BLOCK_SIZE_AND_ALGO (previously crashed!)
    algo_branch2 = (
        b"\x11\x01\x20"
        + struct.pack("<I", 256)
        + b"\x28\x01\x00\x00\x0a"
        + b"\x11\x01\x20"
        + struct.pack("<I", 128)
        + b"\x6f\x02\x00\x00\x0a"
        + b"\x11\x01\x17\x6f\x03\x00\x00\x0a"
    )

    off_ctor1 = len(salt1_init) + len(salt2_init)
    off_ctor2 = off_ctor1 + len(ctor1_body)
    blob = salt1_init + salt2_init + ctor1_body + ctor2_body + key_ref1 + key_ref2 + algo_branch2

    payload = _StubPayload(
        data=blob,
        fields={key_field_rva: "Key"},
        strings={salt1_str_rva: salt1.decode(), salt2_str_rva: salt2.decode()},
        methods=[
            DotNetPEMethod(".ctor", off_ctor1, off_ctor1, len(ctor1_body), ctor1_tok),
            DotNetPEMethod(".ctor", off_ctor2, off_ctor2, len(ctor2_body), ctor2_tok),
        ],
    )

    dec = ConfigDecryptorAESWithIV(payload)
    assert dec._key_size == 32
    assert dec._aes_algo == AES.MODE_CBC
    assert dec.salt == salt1

    decrypted = dec.decrypt_encrypted_strings(
        {
            "Key": passphrase,
            "Hosts": _aes_with_iv_encrypt(real_key, "c2.example.com"),
            "Ports": _aes_with_iv_encrypt(real_key, "4444"),
            "Empty": "",
        }
    )
    assert decrypted["Hosts"] == "c2.example.com"
    assert decrypted["Ports"] == "4444"
    # Key AND matching salt2 (not salt1!) must be reported
    assert dec.key == real_key
    assert dec.salt == salt2

    # Template sample (only placeholders + long plaintext with spaces) must succeed with salt intact
    dec.reset_per_config_state()
    template_out = dec.decrypt_encrypted_strings(
        {
            "Key": "%Key%",
            "Hosts": "%Hosts%",
            "LongNote": "This is a long plaintext builder placeholder with spaces over 64 chars!!",
        }
    )
    assert template_out["Hosts"] == "%Hosts%"
    assert dec.key is None
    assert dec.salt == salt1


def test_aes_with_iv_rejects_excessive_pbkdf2_iterations() -> None:
    salt_field_rva = MDT_FIELD_DEF | 1
    salt_str_rva = MDT_STRING | 1
    salt_init = b"\x72" + struct.pack("<I", salt_str_rva) + b"\x28\x01\x00\x00\x0a\x80" + struct.pack("<I", salt_field_rva) + b"\x2a"
    # 500,000,000 iterations -> must be rejected as DoS
    ctor_body = b"\x02\x7e" + struct.pack("<I", salt_field_rva) + b"\x20" + struct.pack("<I", 500_000_000) + b"\x73\x01\x00\x00\x0a"
    payload = _StubPayload(
        data=salt_init + ctor_body,
        strings={salt_str_rva: "salt"},
    )
    with pytest.raises(IncompatibleDecryptorException):
        ConfigDecryptorAESWithIV(payload)


def test_aes_with_iv_pbkdf_dotall_no_stdout_and_raises_on_zero_decrypted(
    capsys: pytest.CaptureFixture[str],
) -> None:
    salt = b"0123456789"  # length 10 == 0x0A ('\n') -> previously broke without re.DOTALL!
    password = "pbkdf_password"
    derived = hashlib.pbkdf2_hmac("sha1", password.encode(), salt, 1000, 48)
    key, iv = derived[:32], derived[32:]

    pw_str_rva = MDT_STRING | 0x0A  # also contains 0x0A!
    salt_field_rva = MDT_FIELD_DEF | 0x0A  # also contains 0x0A!
    salt_offset = 0
    pattern_bytes = (
        b"\x72"
        + struct.pack("<I", pw_str_rva)
        + b"\x1f"
        + bytes([len(salt)])
        + b"\x8d\x01\x00\x00\x01\x25\xd0"
        + struct.pack("<I", salt_field_rva)
        + b"\x28"
    )
    payload = _StubPayload(
        data=salt + pattern_bytes,
        strings={pw_str_rva: password},
        field_rvas={salt_field_rva: salt_offset},
    )

    dec = ConfigDecryptorAESWithIV_pbkdf(payload)
    ct_b64 = b64encode(
        AES.new(key, AES.MODE_CBC, iv=iv).encrypt(pad(b"10.0.0.1", 16))
    ).decode()
    out = dec.decrypt_encrypted_strings({"Hosts": ct_b64, "Plain": "not_b64"})
    assert out == {"Hosts": "10.0.0.1", "Plain": "not_b64"}

    # Failure case must raise AND emit nothing to stdout (no print("error", e)!)
    bad_ct = b64encode(b"\xaa" * 32).decode()
    with pytest.raises(ConfigParserException):
        dec.decrypt_encrypted_strings({"Hosts": bad_ct})
    assert capsys.readouterr().out == ""


@pytest.mark.parametrize(
    ("mode_byte", "aes_mode"),
    [
        (b"\x17", AES.MODE_CBC),
        (b"\x1a", AES.MODE_CFB),
        (b"\x18", AES.MODE_ECB),
    ],
)
def test_rijndael_cbc_cfb_ecb_and_failure_guards(
    mode_byte: bytes, aes_mode: int
) -> None:
    key_field_rva = MDT_FIELD_DEF | 1
    raw_key = "RijndaelKey"
    derived_key = hashlib.md5(raw_key.encode()).digest()

    blob = (
        b"\x7e"
        + struct.pack("<I", key_field_rva)
        + b"\x6f\x01\x00\x00\x0a\x11\x06\x0c"
        + b"\x06\x09\x6f\x01\x00\x00\x0a\x06"
        + mode_byte
        + b"\x6f\x02\x00\x00\x0a\x06\x6f\x03\x00\x00\x0a\x13"
    )
    payload = _StubPayload(data=blob, fields={key_field_rva: "Key"})
    dec = ConfigDecryptorRijndael(payload)
    assert dec.mode == aes_mode

    iv = b"\x33" * 16
    if aes_mode == AES.MODE_CBC:
        ct = iv + AES.new(derived_key, AES.MODE_CBC, iv=iv).encrypt(pad(b"host.test", 16))
    elif aes_mode == AES.MODE_CFB:
        ct = iv + AES.new(derived_key, AES.MODE_CFB, iv=iv, segment_size=128).encrypt(
            pad(b"host.test", 16)
        )
    else:
        ct = AES.new(derived_key, AES.MODE_ECB).encrypt(pad(b"host.test", 16))

    out = dec.decrypt_encrypted_strings({"Key": raw_key, "Hosts": b64encode(ct).decode()})
    assert out["Hosts"] == "host.test"

    # Missing key field must raise ConfigParserException (not TypeError in AES.new)
    dec.reset_per_config_state()
    with pytest.raises(ConfigParserException):
        dec.decrypt_encrypted_strings({"Other": b64encode(ct).decode()})

    # All-plaintext input must raise so downstream decryptors still run
    dec.reset_per_config_state()
    with pytest.raises(ConfigParserException):
        dec.decrypt_encrypted_strings({"Key": raw_key, "Hosts": "not_encrypted"})


def test_rijndael_unknown_mode_byte_does_not_raise_keyerror() -> None:
    key_field_rva = MDT_FIELD_DEF | 1
    blob = (
        b"\x7e"
        + struct.pack("<I", key_field_rva)
        + b"\x6f\x01\x00\x00\x0a\x11\x06\x0c"
        + b"\x06\x09\x6f\x01\x00\x00\x0a\x06\x99\x6f\x02\x00\x00\x0a\x06\x6f\x03\x00\x00\x0a\x13"
    )
    dec = ConfigDecryptorRijndael(_StubPayload(data=blob, fields={key_field_rva: "Key"}))
    assert dec.mode == AES.MODE_CBC


def test_ecb_hardcoded_string_key_3des_and_rejects_unmatched_mode() -> None:
    # Neither is_AES nor is_3DES -> must raise IncompatibleDecryptorException (not UnboundLocalError)
    key_field_rva = MDT_FIELD_DEF | 1
    no_mode_blob = b"\x7e" + struct.pack("<I", key_field_rva) + b"\x28\x01\x00\x00\x06\x6f"
    with pytest.raises(IncompatibleDecryptorException):
        ConfigDecryptorECB(_StubPayload(data=no_mode_blob, fields={key_field_rva: "Mutex"}))

    # Hardcoded #US string key (0x70xxxxxx) + AES-ECB (previously always failed!)
    key_str_rva = MDT_STRING | 1
    raw_key = "HardcodedMutexKey"
    md5_digest = hashlib.md5(raw_key.encode()).digest()
    aes_key = md5_digest[:15] + md5_digest[:16] + b"\x00"
    aes_marker = (
        b"\x06\x20\x00\x01\x00\x00\x6f\x01\x00\x00\x0a"
        b"\x06\x20\x80\x00\x00\x00\x6f\x02\x00\x00\x0a"
        b"\x06\x18\x6f\x03\x00\x00\x0a"
    )
    hardcoded_key_marker = b"\x00\x72" + struct.pack("<I", key_str_rva) + b"\x0a\x28\x01\x00\x00\x0a"
    payload = _StubPayload(
        data=aes_marker + hardcoded_key_marker,
        strings={key_str_rva: raw_key},
    )
    dec = ConfigDecryptorECB(payload)
    ct_b64 = b64encode(
        AES.new(aes_key, AES.MODE_ECB).encrypt(pad(b"xworm.example.com", 16))
    ).decode()
    out = dec.decrypt_encrypted_strings({"Hosts": ct_b64})
    assert out["Hosts"] == "xworm.example.com"
    assert dec.key == aes_key

    # 3DES-ECB + plaintext XenoRAT regression (must raise when 0 strings decrypt!)
    des3_marker = b"\x28\x01\x00\x00\x0a\x13\x04\x11\x04"
    md5_marker = b"\x7e" + struct.pack("<I", key_field_rva) + b"\x28\x01\x00\x00\x06\x6f"
    payload_3des = _StubPayload(
        data=des3_marker + md5_marker,
        fields={key_field_rva: "startup_name"},
    )
    dec3 = ConfigDecryptorECB(payload_3des)
    # Valid 3DES ciphertext decrypts
    k3 = DES3.adjust_key_parity(hashlib.md5(b"des3pass").digest())
    ct3 = b64encode(DES3.new(k3, DES3.MODE_ECB).encrypt(pad(b"1.2.3.4", 8))).decode()
    assert dec3.decrypt_encrypted_strings({"startup_name": "des3pass", "Hosts": ct3})["Hosts"] == "1.2.3.4"

    # Plaintext XenoRAT (startup_name="nothingset", EncryptionKey=64-hex-char SHA256) must raise
    dec3.reset_per_config_state()
    with pytest.raises(ConfigParserException):
        dec3.decrypt_encrypted_strings(
            {
                "startup_name": "nothingset",
                "ServerIp": "77.221.152.198",
                "EncryptionKey": "03ac674216f3e15c761ee1a5e255f067953623c8b388b4459e13f978d7c846f4",
            }
        )


def test_decrypt_xor_handles_colons_in_plaintext_and_bad_lengths() -> None:
    dec = ConfigDecryptorDecryptXOR.__new__(ConfigDecryptorDecryptXOR)
    dec.key = b"K"
    arr = b"\x10\x20\x30\x40"
    plain = b"test"
    arr2 = bytes(plain[i] ^ ord("K") ^ arr[i] for i in range(4))
    dec._xor_strings = [
        f"{arr.hex()}:{arr2.hex()}",
        "https://example.com:443/path",
        "12:34:56",
        "dead:beefcafe",  # len(arr) < len(arr2)
        "plain_without_colon",
    ]
    assert dec._decode_encoded_strings() == [
        "test",
        "https://example.com:443/path",
        "12:34:56",
        "dead:beefcafe",
        "plain_without_colon",
    ]

    dec.key = b""
    with pytest.raises(ConfigParserException):
        dec._decode_encoded_strings()


def test_random_hardcoded_invalid_rva_does_not_crash_on_hex_bytes() -> None:
    bad_rva = MDT_STRING | 99
    good_rva = MDT_STRING | 1
    body = b"\x72" + struct.pack("<I", bad_rva) + b"\x72" + struct.pack("<I", good_rva)
    method = DotNetPEMethod("GetHost", 0, 0, len(body), MDT_METHOD_DEF | 1)
    payload = _StubPayload(data=body, strings={good_rva: "a.example.com:443"}, methods=[method])

    dec = ConfigDecryptorRandomHardcoded.__new__(ConfigDecryptorRandomHardcoded)
    dec._payload = payload
    dec._random_domain_method = method
    assert dec._get_hardcoded_hosts() == ["a.example.com:443"]


# ---------------------------------------------------------------------------
# 6. RATConfigParser & config_normalization
# ---------------------------------------------------------------------------


def test_config_normalization_delimiters_and_case_insensitive_nulls() -> None:
    assert check_key_n_value("Hosts", " 1.1.1.1 ; 2.2.2.2 , 3.3.3.3 ") == (
        "Hosts",
        ["1.1.1.1", "2.2.2.2", "3.3.3.3"],
    )
    assert check_key_n_value("Ports", "NULL") == ("Ports", [])
    assert check_key_n_value("Hosts", "False") == ("Hosts", [])
    assert check_key_n_value("mutex_string", "abc") == ("Mutex", "abc")
    assert check_key_n_value("hardcoded_hosts", ["a:443"]) == ("Hosts", ["a:443"])
    assert check_key_n_value("UrlHost", "https://a.test") == ("Hosts", ["https://a.test"])


def test_rat_config_parser_no_stale_decryptor_leak_and_verify_hash_floor() -> None:
    # Build two .cctor methods:
    # 1. Small 3-field plaintext .cctor (matches ConfigDecryptorPlaintext but < floor=5)
    # 2. Full 6-field AES-ECB .cctor with known field names (must be decrypted by ECB, NOT leaked Plaintext!)
    raw_key = "SecretMutex"
    md5_digest = hashlib.md5(raw_key.encode()).digest()
    aes_key = md5_digest[:15] + md5_digest[:16] + b"\x00"
    enc_host = b64encode(
        AES.new(aes_key, AES.MODE_ECB).encrypt(pad(b"real.c2.test", 16))
    ).decode()
    enc_port = b64encode(AES.new(aes_key, AES.MODE_ECB).encrypt(pad(b"4444", 16))).decode()

    fields = {
        MDT_FIELD_DEF | 1: "Hosts",
        MDT_FIELD_DEF | 2: "Ports",
        MDT_FIELD_DEF | 3: "Version",
        MDT_FIELD_DEF | 4: "Mutex",
        MDT_FIELD_DEF | 5: "Group",
        MDT_FIELD_DEF | 6: "Install",
    }
    strings = {
        MDT_STRING | 1: "dummy_host",
        MDT_STRING | 2: "80",
        MDT_STRING | 3: "1.0",
        MDT_STRING | 4: enc_host,
        MDT_STRING | 5: enc_port,
        MDT_STRING | 6: raw_key,
        MDT_STRING | 7: "Grp1",
        MDT_STRING | 8: "false",
    }

    cctor_small_il = b"".join(
        [
            b"\x72" + _token(MDT_STRING, 1) + b"\x80" + _token(MDT_FIELD_DEF, 1),
            b"\x72" + _token(MDT_STRING, 2) + b"\x80" + _token(MDT_FIELD_DEF, 2),
            b"\x72" + _token(MDT_STRING, 3) + b"\x80" + _token(MDT_FIELD_DEF, 3),
            b"\x2a",
        ]
    )
    cctor_real_il = b"".join(
        [
            b"\x72" + _token(MDT_STRING, 4) + b"\x80" + _token(MDT_FIELD_DEF, 1),
            b"\x72" + _token(MDT_STRING, 5) + b"\x80" + _token(MDT_FIELD_DEF, 2),
            b"\x72" + _token(MDT_STRING, 3) + b"\x80" + _token(MDT_FIELD_DEF, 3),
            b"\x72" + _token(MDT_STRING, 6) + b"\x80" + _token(MDT_FIELD_DEF, 4),
            b"\x72" + _token(MDT_STRING, 7) + b"\x80" + _token(MDT_FIELD_DEF, 5),
            b"\x72" + _token(MDT_STRING, 8) + b"\x80" + _token(MDT_FIELD_DEF, 6),
            # Spurious invalid field token in method body must be skipped, not abort!
            b"\x72" + _token(MDT_STRING, 8) + b"\x80" + _token(MDT_FIELD_DEF, 99),
            b"\x2a",
        ]
    )
    m_small = _fat_method(cctor_small_il)
    m_real = _fat_method(cctor_real_il)

    aes_marker = (
        b"\x06\x20\x00\x01\x00\x00\x6f\x01\x00\x00\x0a"
        b"\x06\x20\x80\x00\x00\x00\x6f\x02\x00\x00\x0a"
        b"\x06\x18\x6f\x03\x00\x00\x0a"
    )
    md5_marker = b"\x7e" + _token(MDT_FIELD_DEF, 4) + b"\x28\x01\x00\x00\x06\x6f"
    blob = m_small + m_real + aes_marker + md5_marker

    stub = _StubPayload(
        data=blob,
        fields=fields,
        strings=strings,
        methods=[
            DotNetPEMethod(".cctor", 0, 0, len(m_small), MDT_METHOD_DEF | 1),
            DotNetPEMethod(".cctor", len(m_small), len(m_small), len(m_real), MDT_METHOD_DEF | 2),
        ],
    )

    parser = RATConfigParser.__new__(RATConfigParser)
    parser.remap_config = False
    parser.preserve_obfuscated_keys = False
    parser._dnpp = stub
    parser._decryptor = None
    parser._decryptor_cache = {}
    parser._incompatible_decryptors = set()

    cfg = parser._get_config()
    assert cfg["Hosts"] == "real.c2.test"
    assert cfg["Ports"] == "4444"
    assert isinstance(parser._decryptor, ConfigDecryptorECB)
    assert parser._decryptor.key == aes_key

    # VerifyHash floor test: a 4-item config must NOT pass (_MIN_CONFIG_LEN_FLOOR == 5)
    verify_il = b"\x7e\x01\x00\x00\x04\x6f\x01\x00\x00\x0a\x6f\x02\x00\x00\x0a\x74\x01\x00\x00\x01\x2a"
    four_il = b"".join(
        [
            b"\x72" + _token(MDT_STRING, 1) + b"\x80" + _token(MDT_FIELD_DEF, 1),
            b"\x72" + _token(MDT_STRING, 2) + b"\x80" + _token(MDT_FIELD_DEF, 2),
            b"\x72" + _token(MDT_STRING, 3) + b"\x80" + _token(MDT_FIELD_DEF, 3),
            b"\x72" + _token(MDT_STRING, 7) + b"\x80" + _token(MDT_FIELD_DEF, 5),
            b"\x2a",
        ]
    )
    mv = _fat_method(verify_il)
    m4 = _fat_method(four_il)
    parser._dnpp = _StubPayload(
        data=mv + m4,
        fields=fields,
        strings=strings,
        methods=[
            DotNetPEMethod("VerifyHash", 0, 0, len(mv), MDT_METHOD_DEF | 1),
            DotNetPEMethod(".cctor", len(mv), len(mv), len(m4), MDT_METHOD_DEF | 2),
        ],
    )
    parser._decryptor_cache = {}
    parser._incompatible_decryptors = set()
    with pytest.raises(ConfigParserException):
        parser._get_config_verify_hash_method()


def test_remap_config_and_obfuscation_check() -> None:
    parser = RATConfigParser.__new__(RATConfigParser)
    remapped = parser._remap_config(
        decoded_config={
            "Hosts": "1.1.1.1",
            "HostsFE": "2.2.2.2",
            "ServerPort": 4444,
            "Port": "5555",
            "Key": "",
            "EncryptionKey": "abc",
            "hardcoded_hosts": ["3.3.3.3:443"],
        },
        config_fields_map={
            1: "Hosts",
            2: "HostsFE",
            3: "ServerPort",
            4: "Port",
            5: "Key",
            6: "EncryptionKey",
        },
    )
    assert remapped["Hosts"] == ["1.1.1.1", "2.2.2.2", "3.3.3.3:443"]
    assert remapped["Ports"] == [4444, "5555"]
    assert remapped["Key"] == "abc"

    # Order-independent obfuscation detection + underscore-stripped normalized keys
    assert parser._is_likely_obfuscated_config({"Hosts": "1.1.1.1", "梽": "x"}) is True
    assert parser._is_likely_obfuscated_config({"梽": "x", "Hosts": "1.1.1.1"}) is True
    assert parser._is_likely_obfuscated_config({"BSOD": "false", "AntiProcess": "false"}) is False
    assert parser._is_likely_obfuscated_config({"aaa": "1", "bbb": "2"}) is True


# ---------------------------------------------------------------------------
# 7. rkp CLI & RKPMACO wrapper
# ---------------------------------------------------------------------------


def test_rkp_load_yara_fallback_and_dynamic_log_filter(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    from rat_king_parser.yara_utils import YARA_PATH, YARC_PATH, recompile

    # Round-trip yara-x compile -> serialize (.yarc) -> deserialize -> scan
    out_yarc = tmp_path / "test_rules.yarc"
    recompile(YARA_PATH, str(out_yarc))
    loaded = rkp.load_yara(str(out_yarc))
    assert loaded is not None

    # Direct .yar source loading
    loaded_from_src = rkp.load_yara(YARA_PATH)
    assert loaded_from_src is not None

    # Fallback to bundled rules.yar when deserializing YARC_PATH fails
    def _boom(_fp):
        raise OSError("incompatible yara-x binary")

    monkeypatch.setattr(rkp.yara_x.Rules, "deserialize_from", staticmethod(_boom))
    rules = rkp.load_yara(YARC_PATH)
    assert rules is not None

    # Verify yara-x matching AND legacy yara-python .match() duck-typing
    xenorat_blob = (
        b"xeno rat XenoUpdateManager nothingset \x1f\x10\x8dAAAA\x0a"
        + b"\x72AAA\x70\x80AAA\x04" * 6
    )
    payload_hit = _make_bare_payload(xenorat_blob)
    assert payload_hit._match_yara(rules) == "xenorat"

    payload_miss = _make_bare_payload(b"benign bytes")
    assert payload_miss._match_yara(rules) == "No match"

    legacy_rule = SimpleNamespace(match=lambda data: ["asyncrat"] if b"xeno" in data else [])
    assert payload_hit._match_yara(legacy_rule) == "asyncrat"
    assert payload_miss._match_yara(legacy_rule) == "No match"

    # Dynamic file_path logging filter updates across calls in the same worker
    rec1 = logging.LogRecord("test", logging.DEBUG, __file__, 1, "msg1", (), None)
    rec2 = logging.LogRecord("test", logging.DEBUG, __file__, 2, "msg2", (), None)
    flt = rkp._FilePathLogFilter()
    rkp._CURRENT_FILE_PATH = "first.exe"
    flt.filter(rec1)
    rkp._CURRENT_FILE_PATH = "second.exe"
    flt.filter(rec2)
    assert rec1.file_path == "first.exe"
    assert rec2.file_path == "second.exe"


def test_rkp_maco_wrapper_reuses_matches_and_validates_network_values(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Build lightweight stubs for optional [maco] dependencies
    class _ValidationError(Exception):
        pass

    fake_validators = types.ModuleType("validators")
    fake_validators.ValidationError = _ValidationError
    fake_validators.ipv4 = lambda s: True if s in ("1.2.3.4",) else _ValidationError()
    fake_validators.ipv6 = lambda s: True if s in ("2001:db8::1",) else _ValidationError()
    fake_validators.domain = (
        lambda s, consider_tld=True: True if s in ("c2.example.com", "web.example.com") else _ValidationError()
    )
    fake_validators.url = (
        lambda s: True if s.startswith("https://") else _ValidationError()
    )

    class _CategoryEnum:
        rat = "rat"

    class _ExtractorModel:
        class Connection:
            def __init__(self, **kw):
                self.__dict__.update(kw)

        class Http:
            def __init__(self, **kw):
                self.__dict__.update(kw)

        class Encryption:
            def __init__(self, **kw):
                self.__dict__.update(kw)

        def __init__(self, family: str):
            self.family = family
            self.category = []
            self.mutex = []
            self.tcp = []
            self.http = []
            self.encryption = []
            self.campaign_id = []
            self.version = None
            self.other = {}

    fake_maco = types.ModuleType("maco")
    fake_extractor = types.ModuleType("maco.extractor")
    fake_extractor.Extractor = object
    fake_model = types.ModuleType("maco.model")
    fake_model.ExtractorModel = _ExtractorModel
    fake_model.CategoryEnum = _CategoryEnum
    fake_maco.extractor = fake_extractor
    fake_maco.model = fake_model

    monkeypatch.setitem(sys.modules, "validators", fake_validators)
    monkeypatch.setitem(sys.modules, "maco", fake_maco)
    monkeypatch.setitem(sys.modules, "maco.extractor", fake_extractor)
    monkeypatch.setitem(sys.modules, "maco.model", fake_model)
    mod_name = "rat_king_parser.extern.maco.rkp_maco"
    monkeypatch.delitem(sys.modules, mod_name, raising=False)
    try:
        rkp_maco = importlib.import_module(mod_name)

        seen_yara_args = []

        class _FakeParser:
            def __init__(self, yara_rule=None, data=None, remap_config=False):
                seen_yara_args.append(yara_rule)
                self.error = None
                self.report = {
                    "yara_possible_family": "",
                    "key": "deadbeef",
                    "salt": "cafebabe",
                    "config": {
                        "Mutex": "null",
                        "Version": "1.2.3",
                        "Ports": [True, "4444", "99999", "²", 8080],
                        "Hosts": [
                            "[2001:db8::1]:4444",
                            "1.2.3.4:5555",
                            "web.example.com:443",
                            "c2.example.com:9000",
                            "https://panel.example.com:8443/gate",
                            12345,  # non-str in list must not crash
                        ],
                        "Group": "CampA",
                        "TelegramToken": "123:ABC",
                    },
                }

        monkeypatch.setattr(rkp_maco, "RATConfigParser", _FakeParser)
        ext = rkp_maco.RKPMACO()
        res = ext.run(io.BytesIO(b"MZ"), matches=[SimpleNamespace(rule="asyncrat")])

        # Must reuse MACO matches without re-running YARA inside RATConfigParser
        assert seen_yara_args == [None]
        assert res.family == "asyncrat"
        assert res.mutex == []  # "null" filtered out
        assert res.version == "1.2.3"
        assert res.campaign_id == ["CampA"]
        assert res.encryption[0].key == "deadbeef"
        assert res.encryption[0].salt == "cafebabe"
        assert res.other["TelegramToken"] == "123:ABC"

        tcp_ports = [c.server_port for c in res.tcp if getattr(c, "server_ip", None) is None and getattr(c, "server_domain", None) is None]
        assert tcp_ports == [4444, 8080]
        tcp_ips = [(c.server_ip, c.server_port) for c in res.tcp if getattr(c, "server_ip", None)]
        assert tcp_ips == [("2001:db8::1", 4444), ("1.2.3.4", 5555)]
        tcp_domains = [(c.server_domain, c.server_port) for c in res.tcp if getattr(c, "server_domain", None)]
        assert tcp_domains == [("c2.example.com", 9000)]
        assert any(getattr(h, "hostname", None) == "web.example.com" and h.port == 443 for h in res.http)
        assert any(getattr(h, "uri", None) == "https://panel.example.com:8443/gate" for h in res.http)

        # Also verify yara-x style Rule objects exposing .identifier (not .rule)
        res_yarax = ext.run(io.BytesIO(b"MZ"), matches=[SimpleNamespace(identifier="xworm")])
        assert res_yarax.family == "xworm"
    finally:
        sys.modules.pop(mod_name, None)


def test_yara_x_compiled_rules_match_all_bundled_families(tmp_path) -> None:
    from pathlib import Path

    import yara_x

    from rat_king_parser.yara_utils import YARA_PATH, YARC_PATH, recompile

    rules_src = yara_x.compile(Path(YARA_PATH).read_text(encoding="utf-8"))
    # Production loader transparently falls back to rules.yar if bundled rules.yarc
    # was serialized by a different yara-x format version.
    rules_loaded = rkp.load_yara(YARC_PATH)

    # Also verify serialize -> deserialize round-trip with the active yara-x version
    local_yarc = tmp_path / "rules.yarc"
    recompile(YARA_PATH, str(local_yarc))
    with open(local_yarc, "rb") as fp:
        rules_bin = yara_x.Rules.deserialize_from(fp)

    patt_config_10 = b"\x72AAA\x70\x80AAA\x04" * 10
    patt_verify = b"\x7eAAA\x04\x6fAAA\x0a\x6fAAA\x0a\x74AAA\x01"
    aes_key_base = b"\x7eAAA\x04\x73AAA\x06\x80"
    aes_salt_base = bytes.fromhex("BFEB1E56FBCD973BB219")

    family_blobs = {
        "asyncrat": b"AsyncClient masterKey can not be null or empty "
        + aes_key_base
        + aes_salt_base
        + patt_verify
        + patt_config_10,
        "dcrat": b"dcrat qwqdan save_Plugin " + aes_key_base + patt_config_10,
        "quasarrat": b"Quasar. QuasarApplication ENABLELOGGER RECONNECTDELAY "
        + patt_config_10,
        "xenorat": b"xeno rat XenoUpdateManager nothingset \x1f\x10\x8dAAAA\x0a"
        + patt_config_10,
        "xworm": b"xworm Xwormmm XClient XLogger " + patt_config_10,
        "venomrat": b"venomrat HVNC_REPLY_MESSAGE OfflineKeylog sending.... "
        + aes_key_base
        + patt_config_10,
    }

    for expected_family, blob in family_blobs.items():
        src_hits = [r.identifier for r in rules_src.scan(blob).matching_rules]
        loaded_hits = [r.identifier for r in rules_loaded.scan(blob).matching_rules]
        bin_hits = [r.identifier for r in rules_bin.scan(blob).matching_rules]
        assert expected_family in src_hits
        assert expected_family in loaded_hits
        assert expected_family in bin_hits
        assert _make_bare_payload(blob)._match_yara(rules_bin) == expected_family

