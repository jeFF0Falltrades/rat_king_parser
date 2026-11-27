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
import re
import typing
from enum import Enum, auto
from logging import getLogger
from pathlib import Path

import validators
from maco import extractor, model
from yara import Match, Rules, load
from yara import compile as yara_compile

from rat_king_parser.config_parser import RATConfigParser
from rat_king_parser.yara_utils import YARA_PATH, YARC_PATH

logger = getLogger(__name__)

_NETWORK_SPLIT_DELIMS = re.compile(r"[,;]")
_BRACKETED_IPV6_PORT = re.compile(r"^\[([^\]]+)\]:([0-9]+)$")


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


def _parse_valid_port(raw_port: typing.Any) -> typing.Optional[int]:
    if isinstance(raw_port, bool):
        return None
    if isinstance(raw_port, int):
        return raw_port if 1 <= raw_port <= 65535 else None
    if isinstance(raw_port, str):
        stripped = raw_port.strip()
        if stripped.isascii() and stripped.isdigit():
            port = int(stripped)
            return port if 1 <= port <= 65535 else None
    return None


class RKPMACO(extractor.Extractor):
    """A MACO-compatible wrapper of jeFF0Falltrades' RAT King Parser"""

    family = "RAT"
    author = "jeFF0Falltrades"
    last_modified = "2024-10-18"
    sharing = "TLP:WHITE"
    yara_rule = Path(YARA_PATH).read_text(encoding="utf-8")
    _cached_yara_rules: typing.Optional[Rules] = None

    @classmethod
    def _get_compiled_yara_rules(cls) -> Rules:
        if cls._cached_yara_rules is None:
            try:
                cls._cached_yara_rules = load(YARC_PATH)
            except Exception:
                cls._cached_yara_rules = yara_compile(source=cls.yara_rule)
        return cls._cached_yara_rules

    def run(
        self, stream: typing.BinaryIO, matches: typing.List[Match]
    ) -> typing.Optional[model.ExtractorModel]:
        # Reuse MACO's existing YARA matches instead of scanning twice when available
        yara_rule_to_run = None if matches else self._get_compiled_yara_rules()
        parser = RATConfigParser(
            yara_rule=yara_rule_to_run,
            data=stream.read(),
            remap_config=True,
        )
        report = parser.report

        # Check if exception occurred within RKP parsing
        if parser.error or (
            isinstance(report["config"], str)
            and report["config"].startswith("Exception")
        ):
            logger.error("%s", report["config"])
            return None

        # Attempt to extract malware family from MACO YARA match or RKP YARA match
        if matches:
            extracted_family = str(matches[0].rule)
        else:
            extracted_family = report["yara_possible_family"]
        rkp_model = model.ExtractorModel(
            family=(
                extracted_family
                if extracted_family and extracted_family != "No match"
                else "Unknown"
            )
        )
        rkp_model.category.append(model.CategoryEnum.rat)

        # Preserve encryption key/salt metadata when available
        key_val = report.get("key")
        salt_val = report.get("salt")
        if (key_val and key_val != "None") or (salt_val and salt_val != "None"):
            enc_kwargs: dict[str, typing.Any] = {}
            if key_val and key_val != "None":
                enc_kwargs["key"] = key_val
            if salt_val and salt_val != "None":
                enc_kwargs["constants"] = [salt_val]
            if enc_kwargs and hasattr(rkp_model, "Encryption"):
                try:
                    rkp_model.encryption.append(rkp_model.Encryption(**enc_kwargs))
                except Exception as e:
                    logger.debug("Could not populate MACO encryption metadata: %s", e)

        other_fields: dict[str, typing.Any] = {}

        for k, v in report["config"].items():
            # Check for known config keys
            if k in MAP_KNOWN_PLAINTEXT_CONFIG_KEYS:
                match MAP_KNOWN_PLAINTEXT_CONFIG_KEYS[k]:
                    case ConfigValueTypes.MUTEX:
                        if (
                            isinstance(v, str)
                            and v.strip()
                            and v.strip().lower() not in ("null", "false")
                        ):
                            rkp_model.mutex.append(v)
                    # For ports found in their own config field, separate from
                    # their corresponding host, it is difficult to map them to
                    # the appropriate server_domain/server_ip
                    #
                    # Instead, these will show individually as "server_port"
                    # entries in the MACO config
                    case ConfigValueTypes.PORT:
                        if isinstance(v, list):
                            for port_item in v:
                                parsed_port = _parse_valid_port(port_item)
                                if parsed_port is not None:
                                    rkp_model.tcp.append(
                                        rkp_model.Connection(server_port=parsed_port)
                                    )
                        else:
                            parsed_port = _parse_valid_port(v)
                            if parsed_port is not None:
                                rkp_model.tcp.append(
                                    rkp_model.Connection(server_port=parsed_port)
                                )
                    case ConfigValueTypes.VERSION:
                        if isinstance(v, str) and v:
                            rkp_model.version = v
                continue

            if k == "Group" and isinstance(v, str) and v:
                if hasattr(rkp_model, "campaign_id"):
                    rkp_model.campaign_id.append(v)
                else:
                    other_fields[k] = v
                continue

            # If v is a list, it contains other config values to be parsed
            if isinstance(v, list):
                possible_network_values = [item for item in v if isinstance(item, str)]
            # Otherwise, parse the value directly from v, accounting for
            # `,` and `;` delimiters
            elif isinstance(v, str):
                possible_network_values = _NETWORK_SPLIT_DELIMS.split(v)
            else:
                other_fields[k] = v
                continue

            matched_network = False
            for raw_network_value in possible_network_values:
                network_value = raw_network_value.strip()
                if not network_value:
                    continue
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
                    matched_network = True
                    continue

                # Check for domain value
                if not isinstance(
                    validators.domain(network_value, consider_tld=True),
                    validators.ValidationError,
                ):
                    if port in (80, 443):
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
                    matched_network = True
                    continue

                # Check for URL value
                if not isinstance(
                    validators.url(network_value), validators.ValidationError
                ):
                    protocol = (
                        network_value.split(":", 1)[0]
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
                    matched_network = True
                    continue

            if not matched_network and v not in ("", None, []):
                other_fields[k] = v

        if other_fields and hasattr(rkp_model, "other"):
            rkp_model.other.update(other_fields)

        return rkp_model

    # Helper function to handle both IPv4 and IPv6 values
    def _add_tcp_ip(
        self, model: model.ExtractorModel, server_ip: str, server_port: typing.Optional[int]
    ) -> None:
        model.tcp.append(
            model.Connection(server_ip=server_ip, server_port=server_port, usage="c2")
        )

    # Parses a single network value into a host/IP and port, if a port is
    # suffixed to the host/IP
    def _split_network_value(
        self, network_value: str
    ) -> typing.Tuple[str, typing.Optional[int]]:
        # Leave URLs intact for validators.url()
        if "://" in network_value:
            return network_value, None
        # Handle bracketed IPv6 with port, e.g. [2001:db8::1]:4444
        ipv6_match = _BRACKETED_IPV6_PORT.match(network_value)
        if ipv6_match is not None:
            host, raw_port = ipv6_match.groups()
            port = _parse_valid_port(raw_port)
            if port is not None:
                return host, port
            return host, None
        # Handle IPv4/domain with single trailing :port
        if network_value.count(":") == 1:
            host, raw_port = network_value.rsplit(":", 1)
            port = _parse_valid_port(raw_port)
            if port is not None:
                return host, port
        return network_value, None
