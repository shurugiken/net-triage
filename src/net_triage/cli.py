"""Command-line interface for net-triage."""

from __future__ import annotations

import argparse
import sys
from typing import Optional, Sequence

from . import __version__
from .checks import DEFAULT_PORTS, FAIL, WARN, overall_verdict, triage
from .report import render_json, render_text

# Exit codes: 0 = all PASS, 1 = at least one WARN, 2 = at least one FAIL,
# 3 = usage/argument error (argparse already exits 2 on its own errors, but we
# reserve 3 for our own input validation).
_EXIT_BY_VERDICT = {FAIL: 2, WARN: 1}


def _parse_ports(raw: str) -> tuple[int, ...]:
    """Parse a comma-separated port list into a tuple of ints."""
    ports: list[int] = []
    for part in raw.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            value = int(part)
        except ValueError as exc:
            raise ValueError(f"invalid port {part!r}") from exc
        if not (0 < value < 65536):
            raise ValueError(f"port out of range: {value}")
        if value not in ports:
            ports.append(value)
    if not ports:
        raise ValueError("no valid ports given")
    return tuple(ports)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="net-triage",
        description="Triage a host: DNS, TCP ports, HTTP(S), and connect latency.",
    )
    parser.add_argument("host", help="hostname or IP address to check")
    parser.add_argument(
        "-p",
        "--ports",
        help=(
            "comma-separated ports to probe "
            f"(default: {','.join(str(p) for p in DEFAULT_PORTS)})"
        ),
    )
    parser.add_argument(
        "-t",
        "--timeout",
        type=float,
        default=5.0,
        help="per-connection timeout in seconds (default: 5.0)",
    )
    parser.add_argument(
        "--latency-samples",
        type=int,
        default=3,
        help="number of TCP connects used for the latency estimate (default: 3)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="emit a JSON report instead of text",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.ports:
        try:
            ports = _parse_ports(args.ports)
        except ValueError as exc:
            print(f"net-triage: error: {exc}", file=sys.stderr)
            return 3
    else:
        ports = DEFAULT_PORTS

    if args.timeout <= 0:
        print("net-triage: error: timeout must be positive", file=sys.stderr)
        return 3

    results = triage(
        args.host,
        ports=ports,
        timeout=args.timeout,
        latency_samples=args.latency_samples,
    )

    if args.json:
        print(render_json(args.host, results))
    else:
        print(render_text(args.host, results))

    return _EXIT_BY_VERDICT.get(overall_verdict(results), 0)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
