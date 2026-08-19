"""Output formatting for enumeration results.

Four formats are supported:

- ``table`` -- human-readable aligned columns for the terminal.
- ``json``  -- machine-readable, includes every field (for tools/jupyter).
- ``csv``   -- spreadsheet-friendly (Excel, pandas).
- ``list``  -- bare hostnames, one per line (for piping into other tools).

All formatters are pure functions of the records, so they are trivially
unit-testable and deterministic.
"""

from __future__ import annotations

import csv
import io
import json

from .model import Subdomain


def to_table(records: list[Subdomain], width: int = 24) -> str:
    """Render records as an aligned text table.

    Args:
        records: The subdomains to render.
        width: Minimum width for the hostname column.

    Returns:
        A single string (no trailing newline) ready for printing.
    """
    if not records:
        return "No subdomains found."

    rows = [
        (
            r.name,
            ", ".join(r.ip_addresses),
            r.cname or "-",
            ", ".join(sorted(r.sources)),
            _takeover_cell(r),
        )
        for r in records
    ]
    name_w = max(width, max(len(r[0]) for r in rows))
    ip_w = max(10, max(len(r[1]) for r in rows))
    cname_w = max(5, max(len(r[2]) for r in rows))
    src_w = max(6, max(len(r[3]) for r in rows))

    header = (
        f"{'Hostname'.ljust(name_w)}  "
        f"{'IPs'.ljust(ip_w)}  "
        f"{'CNAME'.ljust(cname_w)}  "
        f"{'Source'.ljust(src_w)}  "
        f"{'Takeover'}"
    )
    divider = "-" * len(header)
    lines = [header, divider]
    for name, ips, cname, source, takeover in rows:
        lines.append(
            f"{name.ljust(name_w)}  {ips.ljust(ip_w)}  "
            f"{cname.ljust(cname_w)}  {source.ljust(src_w)}  {takeover}"
        )
    return "\n".join(lines)


def to_json(records: list[Subdomain]) -> str:
    """Render records as a JSON array of objects."""
    return json.dumps(
        [record_to_dict(r) for r in records],
        indent=2,
        sort_keys=True,
    )


def to_csv(records: list[Subdomain]) -> str:
    """Render records as CSV with a header row."""
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(
        [
            "hostname",
            "record_type",
            "ipv4",
            "ipv6",
            "cname",
            "sources",
            "resolved",
            "wildcard",
            "takeover_service",
            "takeover_confidence",
            "takeover_target",
        ]
    )
    for r in records:
        writer.writerow(
            [
                r.name,
                r.record_type,
                ",".join(r.ipv4),
                ",".join(r.ipv6),
                r.cname or "",
                ",".join(sorted(r.sources)),
                str(r.resolved).lower(),
                str(r.wildcard).lower(),
                r.takeover.service if r.takeover else "",
                r.takeover.confidence if r.takeover else "",
                r.takeover.cname_target if r.takeover else "",
            ]
        )
    return buffer.getvalue().rstrip("\n")


def to_names(records: list[Subdomain]) -> str:
    """Render bare hostnames, one per line."""
    return "\n".join(r.name for r in records)


def record_to_dict(record: Subdomain) -> dict:
    """Convert a record to a JSON-serializable dict."""
    data: dict = {
        "hostname": record.name,
        "record_type": record.record_type,
        "ipv4": list(record.ipv4),
        "ipv6": list(record.ipv6),
        "cname": record.cname,
        "sources": sorted(record.sources),
        "resolved": record.resolved,
        "wildcard": record.wildcard,
    }
    if record.takeover is not None:
        data["takeover"] = {
            "service": record.takeover.service,
            "confidence": record.takeover.confidence,
            "target": record.takeover.cname_target,
            "detail": record.takeover.detail,
        }
    return data


def _takeover_cell(record: Subdomain) -> str:
    """Render the takeover column for a table row.

    Args:
        record: The subdomain to describe.

    Returns:
        ``-`` when no takeover was assessed, otherwise the confidence (upper
        case) and service name, e.g. ``HIGH (Amazon S3)``.
    """
    if record.takeover is None:
        return "-"
    return (
        f"{record.takeover.confidence.upper()} ({record.takeover.service})"
    )


FORMATTERS = {
    "table": to_table,
    "json": to_json,
    "csv": to_csv,
    "list": to_names,
}


def render(records: list[Subdomain], fmt: str) -> str:
    """Render ``records`` in the requested format.

    Args:
        records: Subdomains to render.
        fmt: One of ``table``, ``json``, ``csv``, ``list``.

    Returns:
        The formatted text.

    Raises:
        ValueError: If ``fmt`` is unknown.
    """
    try:
        return FORMATTERS[fmt](records)
    except KeyError as exc:
        raise ValueError(
            f"unknown output format {fmt!r}; expected one of "
            f"{', '.join(sorted(FORMATTERS))}"
        ) from exc