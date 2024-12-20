#!/usr/bin/env python3
#
# rkp_maco.py
#
# Author: jeFF0Falltrades
#
# A MACO-compatible extractor wrapping the RAT King Parser
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
import typing
from enum import Enum, auto
from logging import getLogger
from pathlib import Path
from re import search
from typing import Optional

import validators
from maco import extractor, model
from yara import Match, load

from rat_king_parser.config_parser import RATConfigParser
from rat_king_parser.yara_utils import YARA_PATH, YARC_PATH

logger = getLogger(__name__)


# Helper Enum for known plaintext config value types
class ConfigValueTypes(Enum):
    MUTEX = auto()
    PORT = auto()
    VERSION = auto()


# Known plaintext config keys mapped to their MACO value types
MAP_KNOWN_PLAINTEXT_CONFIG_KEYS = {
    "Mutex": ConfigValueTypes.MUTEX,
    "Ports": ConfigValueTypes.PORT,
    "Version": ConfigValueTypes.VERSION,
}


class RKPMACO(extractor.Extractor):
    """A MACO-compatible wrapper of jeFF0Falltrades' RAT King Parser"""

    family = "RAT"
    author = "jeFF0Falltrades"
    last_modified = "2024-10-18"
    sharing = "TLP:WHITE"
    yara_rule = open(str(Path(__file__).parent / YARA_PATH)).read()

    def run(
        self, stream: typing.BinaryIO, matches: typing.List[Match]
    ) -> typing.Optional[model.ExtractorModel]:
        report = RATConfigParser(
            load(str(Path(__file__).parent / YARC_PATH)),
            data=stream.read(),
            remap_config=True,
        ).report

        # Check if exception occurred within RKP parsing
        if isinstance(report["config"], str) and report["config"].startswith(
            "Exception"
        ):
            logger.error(report["config"])
            return

        # Attempt to extract malware family from YARA match
        extracted_family = report["yara_possible_family"]
        rkp_model = model.ExtractorModel(
            family=extracted_family if extracted_family != "No match" else "Unknown"
        )
        rkp_model.category.append(model.CategoryEnum.rat)

        for k, v in report["config"].items():
            # Check for known config keys
            if k in MAP_KNOWN_PLAINTEXT_CONFIG_KEYS:
                match MAP_KNOWN_PLAINTEXT_CONFIG_KEYS[k]:
                    case ConfigValueTypes.MUTEX:
                        rkp_model.mutex.append(v)
                    # For ports found in their own config field, separate from
                    # their corresponding host, it is difficult to map them to
                    # the appropriate server_domain/server_ip
                    #
                    # Instead, these will show individually as "server_port"
                    # entries in the MACO config
                    case ConfigValueTypes.PORT:
                        rkp_model.tcp.extend(
                            [
                                rkp_model.Connection(server_port=port)
                                for port in v
                                if port.isdigit()
                            ]
                        )
                    case ConfigValueTypes.VERSION:
                        rkp_model.version = v
                continue

            # If v is a list, it contains other config values to be parsed
            if isinstance(v, list):
                possible_network_values = v
            # Otherwise, parse the value directly from v, accounting for the
            # `;` delimiter
            elif isinstance(v, str):
                possible_network_values = v.split(";")
            else:
                continue

            for network_value in possible_network_values:
                network_value, port = self._split_network_value(network_value)

                # Check for IP value
                #
                # Note that this validation will still pass some version
                # numbers (e.g. 1.3.0.0) that look like valid IPv4s, and so may
                # generate false-positive C2 entries
                if not isinstance(
                    validators.ipv4(network_value), validators.ValidationError
                ) or not isinstance(
                    validators.ipv6(network_value), validators.ValidationError
                ):
                    self._add_tcp_ip(rkp_model, network_value, port)
                    continue

                # Check for domain value
                if not isinstance(
                    validators.domain(network_value, consider_tld=True),
                    validators.ValidationError,
                ):
                    if port == 80 or port == 443:
                        protocol = "http" if port == 80 else "https"
                        rkp_model.http.append(
                            rkp_model.Http(
                                protocol=protocol,
                                hostname=network_value,
                                port=port,
                                usage="c2",
                            )
                        )
                    else:
                        rkp_model.tcp.append(
                            rkp_model.Connection(
                                server_domain=network_value,
                                server_port=port,
                                usage="c2",
                            )
                        )
                    continue

                # Check for URL value
                if not isinstance(
                    validators.url(network_value), validators.ValidationError
                ):
                    protocol = (
                        network_value.split(":")[0]
                        if network_value.startswith("http")
                        else None
                    )
                    rkp_model.http.append(
                        rkp_model.Http(
                            protocol=protocol,
                            uri=network_value,
                            usage="c2",
                        )
                    )
                    continue

        return rkp_model

    # Helper function to handle both IPv4 and IPv6 values
    def _add_tcp_ip(
        self, model: model.ExtractorModel, server_ip: str, server_port: Optional[int]
    ) -> None:
        model.tcp.append(
            model.Connection(server_ip=server_ip, server_port=server_port, usage="c2")
        )

    # Parses a single network value into a host/IP and port, if a port is
    # suffixed to the host/IP
    def _split_network_value(
        self, network_value: str
    ) -> typing.Tuple[str, Optional[int]]:
        match = search(r":([0-9]+)$", network_value)
        if match is not None:
            try:
                val, port = network_value.split(":")
                return val, int(port)
            except ValueError:
                pass
        return network_value, None  #
