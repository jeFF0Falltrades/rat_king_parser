#!/usr/bin/env python3
#
# rkp.py
#
# Author: jeFF0Falltrades
#
# A robust, multiprocessing-capable RAT configuration parser for AsyncRAT,
# DcRAT, VenomRAT, QuasarRAT, and derivative RAT families
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
from argparse import ArgumentParser, Namespace
from concurrent.futures import ProcessPoolExecutor
from itertools import repeat
from json import dumps
from logging import DEBUG, WARNING, Filter, LogRecord, basicConfig, getLogger
from os import cpu_count
from pathlib import Path
from typing import Any

import yara_x
from yara_x import Rules

from rat_king_parser._version import __version__
from rat_king_parser.config_parser import RATConfigParser
from rat_king_parser.yara_utils import YARA_PATH, YARC_PATH, recompile

logger = getLogger(__name__)

# Per-worker state initialized once per subprocess via ProcessPoolExecutor initializer
_WORKER_YARA_RULE: Rules | None = None
_WORKER_YARA_PATH: str | None = None
_CURRENT_FILE_PATH: str = ""


class _FilePathLogFilter(Filter):
    def filter(self, record: LogRecord) -> bool:
        record.file_path = _CURRENT_FILE_PATH
        return True


def _configure_logging(debug: bool) -> None:
    root = getLogger()
    if not root.handlers:
        basicConfig(
            level=DEBUG if debug else WARNING,
            format="%(levelname)s:%(name)s:%(file_path)s:%(message)s",
        )
    else:
        root.setLevel(DEBUG if debug else WARNING)
    if not any(isinstance(f, _FilePathLogFilter) for f in root.filters):
        root.addFilter(_FilePathLogFilter())
    for handler in root.handlers:
        if not any(isinstance(f, _FilePathLogFilter) for f in handler.filters):
            handler.addFilter(_FilePathLogFilter())


# Loads the compiled yara-x rules for known strains from the provided path,
# falling back to compiling the bundled source rules if the bundled .yarc was
# serialized with a different yara-x version
def load_yara(compiled_rule_path: str) -> Rules:
    if compiled_rule_path.endswith((".yar", ".yara")):
        try:
            return yara_x.compile(Path(compiled_rule_path).read_text(encoding="utf-8"))
        except Exception as e:
            raise RuntimeError(
                f"Error compiling yara rule source at {compiled_rule_path}"
            ) from e
    try:
        with open(compiled_rule_path, "rb") as fp:
            return yara_x.Rules.deserialize_from(fp)
    except Exception as e:
        if compiled_rule_path == YARC_PATH:
            try:
                logger.debug(
                    "Failed loading compiled YARA-X rules (%s); compiling %s from source",
                    e,
                    YARA_PATH,
                )
                return yara_x.compile(Path(YARA_PATH).read_text(encoding="utf-8"))
            except Exception as compile_err:
                raise RuntimeError(
                    f"Error loading or compiling bundled yara rule - Check {compiled_rule_path} or run with -r/--recompile and retry"
                ) from compile_err
        raise RuntimeError(
            f"Error loading yara rule - Check {compiled_rule_path} or run with -r/--recompile and retry"
        ) from e


def _init_worker(yara_rule_path: str, debug: bool) -> None:
    global _WORKER_YARA_RULE, _WORKER_YARA_PATH
    _configure_logging(debug)
    _WORKER_YARA_RULE = load_yara(yara_rule_path)
    _WORKER_YARA_PATH = yara_rule_path


# Parses arguments
def parse_args() -> Namespace:
    ap = ArgumentParser()
    ap.add_argument(
        "-v", "--version", action="version", version=f"%(prog)s {__version__}"
    )
    ap.add_argument(
        "file_paths",
        nargs="+",
        help="One or more RAT payload file paths",
    )
    ap.add_argument("-d", "--debug", action="store_true", help="Enable debug logging")
    ap.add_argument(
        "-n",
        "--normalize",
        action="store_true",
        help="Attempt to translate common variations of config keys to normalized field names",
    )
    ap.add_argument(
        "-p",
        "--preserve-keys",
        action="store_true",
        help='Preserve potentially obfuscated configuration keys as-is instead of replacing them with placeholder "obfuscated key" entries',
    )
    ap.add_argument(
        "-r",
        "--recompile",
        action="store_true",
        help="Recompile the YARA rule file used for family detection prior to running the parser",
    )
    ap.add_argument(
        "-y",
        "--yara",
        default=YARC_PATH,
        help=f"Uses the *compiled* yara rule at this path to determine the potential family of each payload (uses a prepackaged rule at {YARC_PATH} by default)",
    )
    return ap.parse_args()


# Processes payloads and parses configs, utilizing multiprocessing
def parse_config(
    file_path: str,
    yara_rule_path: str,
    debug: bool = False,
    normalize: bool = False,
    preserve_keys: bool = False,
) -> dict[str, Any]:
    global _CURRENT_FILE_PATH, _WORKER_YARA_RULE, _WORKER_YARA_PATH
    _CURRENT_FILE_PATH = file_path
    _configure_logging(debug)
    # YARA Rules objects cannot be pickled and are cached once per subprocess
    if _WORKER_YARA_RULE is None or _WORKER_YARA_PATH != yara_rule_path:
        _WORKER_YARA_RULE = load_yara(yara_rule_path)
        _WORKER_YARA_PATH = yara_rule_path
    return RATConfigParser(
        file_path,
        _WORKER_YARA_RULE,
        remap_config=normalize,
        preserve_obfuscated_keys=preserve_keys,
    ).report


def main() -> None:
    parsed_args = parse_args()

    if parsed_args.recompile:
        recompile()

    decrypted_configs: list[dict[str, Any]] = []

    if len(parsed_args.file_paths) == 1:
        # Fast path: avoid spawning a worker pool for a single payload
        decrypted_configs.append(
            parse_config(
                parsed_args.file_paths[0],
                parsed_args.yara,
                parsed_args.debug,
                parsed_args.normalize,
                parsed_args.preserve_keys,
            )
        )
    else:
        max_workers = min(len(parsed_args.file_paths), cpu_count() or 1)
        with ProcessPoolExecutor(
            max_workers=max_workers,
            initializer=_init_worker,
            initargs=(parsed_args.yara, parsed_args.debug),
        ) as executor:
            results = executor.map(
                parse_config,
                parsed_args.file_paths,
                repeat(parsed_args.yara),
                repeat(parsed_args.debug),
                repeat(parsed_args.normalize),
                repeat(parsed_args.preserve_keys),
            )
            decrypted_configs.extend(results)

    if len(decrypted_configs) > 0:
        print(dumps(decrypted_configs, ensure_ascii=False))


if __name__ == "__main__":
    main()
