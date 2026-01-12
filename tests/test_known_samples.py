#!/usr/bin/env python3
#
# test_known_samples.py
#
# Author: jeFF0Falltrades
#
# Test runner for CI job against known samples (only available in main repo)
#
# MIT License
#
# Copyright (c) 2026 Jeff Archer
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
import json
import subprocess
from pathlib import Path

import pytest

SAMPLES_DIR = Path("tests/samples")
EXPECTED_DIR = Path("tests/expected")

# Fields that are allowed to exist in parser output
ALLOWED_FIELDS = {
    "sha256",
    "yara_possible_family",
    "key",
    "salt",
    "config",
    "file_path",
}


def normalize_output(data: dict) -> dict:
    """
    Strip non-deterministic or environment-specific fields
    """
    return {
        "sha256": data.get("sha256"),
        "yara_possible_family": data.get("yara_possible_family"),
        "key": data.get("key"),
        "salt": data.get("salt"),
        "config": data.get("config"),
    }


@pytest.mark.skipif(
    not SAMPLES_DIR.exists(),
    reason="Malware samples not available (is this a fork PR?)",
)
@pytest.mark.parametrize(
    "expected_file",
    sorted(EXPECTED_DIR.glob("*.json")),
    ids=lambda p: p.stem,
)
def test_parser_against_known_samples(expected_file):
    with expected_file.open("r", encoding="utf-8") as f:
        expected = json.load(f)

    assert isinstance(expected, dict), "Expected output must be a JSON object"
    assert "sha256" in expected, "Expected output missing sha256"

    sha = expected["sha256"]

    sample_path = next((p for p in SAMPLES_DIR.iterdir() if p.is_file() and p.name.startswith(sha)), None)

    assert sample_path is not None, f"No sample file found for SHA {sha}"

    proc = subprocess.run(
        ["rat-king-parser", str(sample_path)],
        capture_output=True,
        text=True,
        check=True,
    )

    try:
        parsed = json.loads(proc.stdout)
    except json.JSONDecodeError:
        pytest.fail(
            "Parser did not emit valid JSON.\n"
            f"STDOUT:\n{proc.stdout}\n\nSTDERR:\n{proc.stderr}"
        )

    assert isinstance(parsed, list), "Parser output must be a JSON array"
    assert len(parsed) > 0, "Parser output array is empty"

    parsed = parsed[0]

    assert isinstance(parsed, dict), "Parser result must be a JSON object"
    assert parsed.get("sha256") == sha, "SHA256 mismatch in parser output"
    assert isinstance(parsed.get("config"), dict), "config must be a dictionary"

    unexpected_fields = set(parsed.keys()) - ALLOWED_FIELDS
    assert not unexpected_fields, f"Unexpected output fields: {unexpected_fields}"

    normalized_actual = normalize_output(parsed)
    normalized_expected = normalize_output(expected)

    assert normalized_actual == normalized_expected
