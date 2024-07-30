#!/usr/bin/env python3
#
# rat_king_parser.py
#
# Author: jeFF0Falltrades
#
# A robust, multiprocessing-capable RAT configuration parser for AsyncRAT,
# DcRAT, VenomRAT, QuasarRAT, and similar RAT families utilizing a known
# "Settings" module for establishing their configurations, from the YouTube
# tutorial here:
#
# https://www.youtube.com/watch?v=yoz44QKe_2o
#
# and based on the original AsyncRAT config parser here:
#
# https://github.com/jeFF0Falltrades/Tutorials/tree/master/asyncrat_config_parser
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
from argparse import ArgumentParser
from concurrent.futures import ProcessPoolExecutor
from config_parser import RATConfigParser
from itertools import repeat
from json import dumps
from logging import basicConfig, DEBUG, getLogger, WARNING
from pathlib import Path
from yara import load
from yara_rules.recompile import recompile

logger = getLogger(__name__)

YARC_PATH = "yara_rules/rules.yarc"
YARA_RECOMPILE_PATH = "yara_rules/recompile.py"


# Loads the compiled yara rules for known strains from the provided path
def load_yara(compiled_rule_path):
    try:
        return load(compiled_rule_path)
    except Exception as e:
        raise Exception(
            f"Error loading yara rule - Check {compiled_rule_path} or run with -r/--recompile and retry"
        ) from e


# Parses arguments
def parse_args():
    ap = ArgumentParser()
    ap.add_argument(
        "file_paths",
        nargs="+",
        help="One or more RAT payload file paths",
    )
    ap.add_argument("-d", "--debug", action="store_true", help="Enable debug logging")
    ap.add_argument(
        "-r",
        "--recompile",
        action="store_true",
        help="Recompile the YARA rule used for family detection prior to running the parser",
    )
    ap.add_argument(
        "-y",
        "--yara",
        default=str(Path(__file__).parent / YARC_PATH),
        help=f"Uses the *compiled* yara rule at this path to determine the potential family of each payload (uses a prepackaged rule at {YARC_PATH} by default)",
    )
    return ap.parse_args()


# Processes payloads and parses configs in a multiprocessing-friendly manner
def parse_config(fp, debug, yara_rule_path):
    # Since we are utilizing multiprocessing, set up logging once per child
    basicConfig(
        level=DEBUG if debug else WARNING,
        format=f"%(levelname)s:%(name)s:{fp}:%(message)s",
    )
    # YARA rule types cannot be pickled and must be instantiated per subprocess
    rule = load_yara(yara_rule_path)
    return RATConfigParser(fp, rule).report


if __name__ == "__main__":
    parsed_args = parse_args()

    if parsed_args.recompile:
        recompile()

    decrypted_configs, results = [], []

    with ProcessPoolExecutor() as executor:
        results = executor.map(
            parse_config,
            parsed_args.file_paths,
            repeat(parsed_args.debug),
            repeat(parsed_args.yara),
        )

    # ProcessPoolExecutor.map() does not block, so we wait until after results
    # are collected from all subprocesses to add them to our collection
    decrypted_configs.extend(results)
    if len(decrypted_configs) > 0:
        print(dumps(decrypted_configs))
