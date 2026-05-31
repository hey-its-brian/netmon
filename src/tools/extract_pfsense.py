"""Extract the correlation-relevant data from a pfSense config.xml backup.

Reads a full pfSense config backup and writes a sanitized rules.yaml containing
ONLY the firewall rules and the interface map — no passwords, keys, or other
secrets. This lets an automated backup pipeline keep the full config.xml out of
the running container:

    [backup tool] -> config.xml -> extract_pfsense -> rules.yaml -> netmon

Usage:
    python -m src.tools.extract_pfsense CONFIG.xml [-o rules.yaml]
"""

import argparse
import sys

from ..ruleset.pfsense import parse_pfsense_interfaces, parse_pfsense_rules
from ..ruleset.yaml_io import dump_ruleset


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="extract_pfsense",
        description="Extract firewall rules + interface map from a pfSense "
        "config.xml backup into a sanitized rules.yaml.",
    )
    parser.add_argument("config", help="path to the pfSense config.xml backup")
    parser.add_argument(
        "-o",
        "--out",
        default="rules.yaml",
        help="output ruleset YAML path (default: rules.yaml)",
    )
    args = parser.parse_args(argv)

    try:
        rules = parse_pfsense_rules(args.config)
        interfaces = parse_pfsense_interfaces(args.config)
    except Exception as e:  # noqa: BLE001
        print(f"error: failed to parse {args.config}: {e}", file=sys.stderr)
        return 1

    dump_ruleset(rules, interfaces, args.out)
    print(
        f"Extracted {len(rules)} rule(s) and {len(interfaces)} interface(s) "
        f"from {args.config} -> {args.out}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
