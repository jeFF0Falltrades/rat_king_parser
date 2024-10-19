#!/usr/bin/env python3
#
# recompile.py
#
# Author: jeFF0Falltrades
#
# A simple utility script to recompile the specified YARA rule with yara-python
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
import os.path
from argparse import ArgumentParser

from yara import compile

YARA_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "rules.yar")
YARC_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "rules.yarc")


# Compiles the YARA rules at the specified file path and saves them
def recompile(input_path: str = YARA_PATH, output_path: str = YARC_PATH) -> None:
    compiled_rule = compile(input_path)
    compiled_rule.save(output_path)


if __name__ == "__main__":
    ap = ArgumentParser()
    ap.add_argument("-i", "--input", default=YARA_PATH, help="YARA rule to compile")
    ap.add_argument(
        "-o", "--output", default=YARC_PATH, help="Compiled rule output path"
    )
    args = ap.parse_args()
    recompile(args.input, args.output)
