"""Wordlist-driven brute-force candidate generation.

Subdomain brute-forcing is simply: for every label in the wordlist, form the
hostname ``<label>.<domain>`` and ask DNS whether it exists. The value of a
good wordlist is coverage of the *interesting* labels (``admin``, ``api``,
``jenkins``, ``vpn``, ...), so the bundled default list skews towards common
hostnames found in real infrastructure.

The module deliberately does not do any DNS work: it produces candidate
hostnames, and the engine resolves them concurrently.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator


def bruteforce_candidates(domain: str, entries: Iterable[str]) -> Iterator[str]:
    """Yield ``<entry>.<domain>`` for every valid wordlist entry.

    Entries that are already fully-qualified (contain a dot, e.g. ``api.v2``)
    are appended as-is; single labels are joined with ``.``. The root domain
    itself is never re-emitted.

    Args:
        domain: The normalized root domain.
        entries: Validated, normalized wordlist entries.

    Yields:
        Candidate hostnames in wordlist order.
    """
    for entry in entries:
        if entry == domain:
            continue
        yield f"{entry}.{domain}"


def total_candidates(entries: list[str]) -> int:
    """Number of candidates the brute-force pass will produce."""
    return len(entries)