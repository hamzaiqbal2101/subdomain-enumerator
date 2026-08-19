"""Command-line interface for the subdomain enumerator.

Exit codes:

- ``0`` -- success (even when no subdomains are found; the run itself worked)
- ``1`` -- fatal DNS/enumeration failure (e.g. resolver configuration error)
- ``2`` -- command-line usage error (argparse)
- ``3`` -- operational error (invalid domain, bad wordlist, output failure)
"""

from __future__ import annotations

import argparse
import ipaddress
import sys
import time

from . import __version__
from .enumerator import Enumerator
from .output import render
from .resolver import DnsQueryError, Resolver
from .validation import ValidationError, iter_builtin_wordlist, load_wordlist

DEFAULT_THREADS = 20
DEFAULT_TIMEOUT = 5.0
DEFAULT_RETRIES = 2

AUTHORIZATION_NOTICE = (
    "NOTICE: This tool performs DNS reconnaissance. Use it ONLY against "
    "domains you own or have explicit written authorization to test (e.g. bug "
    "bounty programs, your own infrastructure, lab environments). You are "
    "responsible for complying with all applicable laws and policies. For any "
    "domain you do not control, prefer --passive-only, which queries public "
    "OSINT sources and sends no traffic to the target at all."
)


class CliError(Exception):
    """Operational failure that maps to exit code 3."""


def _positive_int(value: str) -> int:
    """Parse ``value`` as a positive integer for argparse.

    Args:
        value: Raw string from the command line.

    Returns:
        The parsed integer.

    Raises:
        argparse.ArgumentTypeError: If the value is not an integer or is < 1.
    """
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"{value!r} is not an integer") from exc
    if parsed < 1:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return parsed


def _non_negative_int(value: str) -> int:
    """Parse ``value`` as a non-negative integer for argparse (0 allowed).

    Args:
        value: Raw string from the command line.

    Returns:
        The parsed integer.

    Raises:
        argparse.ArgumentTypeError: If the value is not an integer or is < 0.
    """
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"{value!r} is not an integer") from exc
    if parsed < 0:
        raise argparse.ArgumentTypeError("must be a non-negative integer")
    return parsed


def _bounded_threads(value: str) -> int:
    """Parse a thread count, clamped to a sane upper bound.

    Args:
        value: Raw string from the command line.

    Returns:
        A thread count in ``1..1000``.

    Raises:
        argparse.ArgumentTypeError: If the value is invalid or exceeds 1000.
    """
    parsed = _positive_int(value)
    if parsed > 1000:
        raise argparse.ArgumentTypeError("must be at most 1000")
    return parsed


def _positive_float(value: str) -> float:
    """Parse ``value`` as a positive float for argparse.

    Args:
        value: Raw string from the command line.

    Returns:
        The parsed float.

    Raises:
        argparse.ArgumentTypeError: If the value is not numeric or is <= 0.
    """
    try:
        parsed = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"{value!r} is not a number") from exc
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be a positive number")
    return parsed


def _nameservers(value: str) -> list[str]:
    """Parse a comma-separated list of nameserver IPs for argparse.

    Args:
        value: Raw comma-separated string from the command line.

    Returns:
        A list of validated IPv4/IPv6 addresses.

    Raises:
        argparse.ArgumentTypeError: If the list is empty or an entry is not a
            valid IP address.
    """
    servers = [part.strip() for part in value.split(",") if part.strip()]
    if not servers:
        raise argparse.ArgumentTypeError("no nameservers provided")
    for server in servers:
        try:
            ipaddress.ip_address(server)
        except ValueError as exc:
            raise argparse.ArgumentTypeError(
                f"{server!r} is not a valid nameserver IP"
            ) from exc
    return servers


def build_parser() -> argparse.ArgumentParser:
    """Build the argument parser."""
    parser = argparse.ArgumentParser(
        prog="subdomain-enumerator",
        description=(
            "Enumerate subdomains of a domain using wordlist brute-force and "
            "certificate-transparency OSINT, with wildcard filtering and "
            "CNAME takeover detection. Authorized use only."
        ),
    )
    parser.add_argument(
        "domain",
        nargs="?",
        help="Root domain to enumerate (e.g. example.com). Either this or "
        "--domain is required.",
    )
    parser.add_argument(
        "--domain",
        dest="domain_opt",
        metavar="DOMAIN",
        help="Root domain to enumerate (alternative to the positional "
        "argument).",
    )
    parser.add_argument(
        "--wordlist",
        "-w",
        metavar="FILE",
        help="Custom wordlist file (one label per line). Defaults to a "
        "bundled list of common hostnames.",
    )
    parser.add_argument(
        "--no-bruteforce",
        action="store_true",
        help="Skip the wordlist brute-force pass (OSINT sources only).",
    )
    parser.add_argument(
        "--no-crt",
        action="store_true",
        help="Skip the certificate-transparency (crt.sh) source.",
    )
    parser.add_argument(
        "--passive-only",
        action="store_true",
        help="Passive enumeration only: query OSINT sources, skip the active "
        "wordlist brute-force pass.",
    )
    parser.add_argument(
        "--active-only",
        action="store_true",
        help="Active enumeration only: skip OSINT sources, use wordlist "
        "brute-force exclusively.",
    )
    parser.add_argument(
        "--threads",
        "-t",
        type=_bounded_threads,
        default=DEFAULT_THREADS,
        metavar="N",
        help=f"Concurrent DNS worker threads (default: {DEFAULT_THREADS}).",
    )
    parser.add_argument(
        "--timeout",
        type=_positive_float,
        default=DEFAULT_TIMEOUT,
        metavar="SECONDS",
        help=f"Per-query timeout in seconds (default: {DEFAULT_TIMEOUT}).",
    )
    parser.add_argument(
        "--retries",
        type=_non_negative_int,
        default=DEFAULT_RETRIES,
        metavar="N",
        help=f"Retries per query after a timeout (default: {DEFAULT_RETRIES}).",
    )
    parser.add_argument(
        "--resolver",
        type=_nameservers,
        metavar="IP[,IP...]",
        help="Comma-separated recursive DNS servers (default: system "
        "resolvers).",
    )
    parser.add_argument(
        "--output",
        "-o",
        metavar="FILE",
        help="Write results to FILE instead of stdout.",
    )
    parser.add_argument(
        "--format",
        "-f",
        choices=("table", "json", "csv", "list"),
        default="table",
        help="Output format (default: table).",
    )
    parser.add_argument(
        "--include-unresolved",
        action="store_true",
        help="Include hostnames reported by OSINT sources that do not "
        "currently resolve.",
    )
    parser.add_argument(
        "--include-wildcards",
        action="store_true",
        help="Keep records that match the domain's DNS wildcard (default: "
        "filter them out as false positives).",
    )
    parser.add_argument(
        "--no-takeover",
        action="store_true",
        help="Skip CNAME takeover analysis.",
    )
    parser.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="Suppress the authorization notice and progress output.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    return parser


def _load_entries(args: argparse.Namespace) -> list[str]:
    """Load and validate the wordlist entries for the run."""
    if args.no_bruteforce:
        return []
    if args.wordlist:
        return load_wordlist(args.wordlist)
    return list(iter_builtin_wordlist())


def _run(args: argparse.Namespace) -> int:
    """Execute one enumeration run from parsed CLI arguments.

    Args:
        args: Parsed ``argparse.Namespace`` (after ``main`` normalizes the
            domain and mode flags).

    Returns:
        Exit code (0 on success, 1 on fatal DNS failure, 3 on operational
        errors such as a missing wordlist).

    Raises:
        ValidationError: If the target domain is invalid.
        CliError: If no wordlist entries are available for brute-force.
    """
    if not args.quiet:
        print(AUTHORIZATION_NOTICE, file=sys.stderr)
        print("", file=sys.stderr)

    domain = args.domain.strip().lower()
    from .validation import normalize_domain

    domain = normalize_domain(domain)

    resolver = Resolver(
        nameservers=args.resolver,
        timeout=args.timeout,
        retries=args.retries,
    )

    entries = _load_entries(args)
    if not entries and not args.no_bruteforce:
        raise CliError("no wordlist entries available for brute-force")

    enumerator = Enumerator(
        domain=domain,
        resolver=resolver,
        threads=args.threads,
        include_unresolved=args.include_unresolved,
        include_wildcards=args.include_wildcards,
        check_takeover=not args.no_takeover,
        use_cert_transparency=not args.no_crt,
        progress=_progress
        if (not args.quiet and sys.stderr.isatty())
        else None,
        result_callback=_found if not args.quiet else None,
    )

    start = time.perf_counter()
    results = enumerator.run(entries)
    elapsed = time.perf_counter() - start

    output = render(results, args.format)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as handle:
            handle.write(output + "\n")
    else:
        print(output)

    if not args.quiet:
        print("", file=sys.stderr)
        print(_summary(enumerator, elapsed), file=sys.stderr)
    return 0


def _found(record) -> None:
    """Print a discovered hostname to stderr as soon as it is verified."""
    ips = ", ".join(record.ip_addresses)
    cname = f" -> {record.cname}" if record.cname else ""
    print(f"[+] {record.name} {ips}{cname}", file=sys.stderr)


def _progress(done: int, total: int) -> None:
    """Render progress to stderr (done/total, or wildcard signal on -1)."""
    if done < 0:
        print(
            "\rWildcard DNS detected -- filtering false positives..."
            + " " * 20,
            file=sys.stderr,
        )
        return
    print(f"\rResolved {done}/{total} candidate(s)", end="", file=sys.stderr)


def _summary(enumerator: Enumerator, elapsed: float) -> str:
    """Build the end-of-run summary text.

    Args:
        enumerator: The finished :class:`Enumerator`, whose stats describe the
            run.
        elapsed: Wall-clock seconds the run took.

    Returns:
        Multi-line summary covering candidates tested, hosts found, records
        filtered, elapsed time, takeover candidates, and any source warnings.
    """
    stats = enumerator.stats
    lines = [
        f"Tested: {stats.candidates} candidate(s)",
        f"Found: {stats.resolved} resolved, {stats.unresolved} unresolved",
        f"Filtered: {stats.wildcard_filtered} wildcard echo(es), "
        f"{stats.dns_errors} DNS error(s)",
        f"Elapsed: {elapsed:.2f}s",
        f"Takeover candidates: {stats.takeover_candidates}",
    ]
    for message in stats.source_errors:
        lines.append(f"Source warning: {message}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    """CLI entry point; returns the process exit code."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.passive_only and args.active_only:
        parser.error("--passive-only and --active-only are mutually exclusive")
    if args.domain and args.domain_opt:
        parser.error("domain given both positionally and with --domain")
    args.domain = args.domain or args.domain_opt
    if not args.domain:
        parser.error("a target domain is required (--domain DOMAIN)")
    args.no_bruteforce = args.no_bruteforce or args.passive_only
    args.no_crt = args.no_crt or args.active_only

    try:
        return _run(args)
    except ValidationError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 3
    except CliError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 3
    except DnsQueryError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except (OSError, IOError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 3