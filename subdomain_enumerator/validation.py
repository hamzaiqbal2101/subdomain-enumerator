"""Input validation for domains and wordlist entries.

Validation is a hard gate, not a suggestion: a malformed root domain or a
wordlist line containing path separators would otherwise produce confusing
DNS failures or, worse, cause the tool to send queries for garbage labels.
All validation happens before any network activity.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterator

_MAX_FQDN_LENGTH = 253
_MAX_LABEL_LENGTH = 63
_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$")


class ValidationError(ValueError):
    """Raised when a domain or wordlist entry fails validation."""


def normalize_domain(domain: str) -> str:
    """Normalize and validate a root domain.

    Lowercases, strips a trailing dot, IDNA-encodes Unicode labels, and
    enforces RFC 1035 length and character rules. Bare IP addresses are
    rejected (enumeration targets are names, not addresses).

    Args:
        domain: The root domain to enumerate, e.g. ``example.com``.

    Returns:
        The normalized, lowercase domain without a trailing dot.

    Raises:
        ValidationError: If the domain is an IP address, a single label, or
            violates DNS naming rules.
    """
    raw = domain.strip().rstrip(".").lower()
    if not raw:
        raise ValidationError("domain must not be empty")
    if len(raw) > _MAX_FQDN_LENGTH:
        raise ValidationError(
            f"domain is {len(raw)} characters; maximum is {_MAX_FQDN_LENGTH}"
        )

    if _looks_like_ip(raw):
        raise ValidationError(
            f"{raw!r} is an IP address; enumerate a domain name instead"
        )

    labels = raw.split(".")
    if len(labels) < 2:
        raise ValidationError(
            f"{raw!r} is a single label; provide a full domain like "
            "example.com"
        )

    normalized = ".".join(_normalize_label(label) for label in labels)
    if len(normalized) > _MAX_FQDN_LENGTH:
        raise ValidationError(
            f"domain is {len(normalized)} characters after normalization; "
            f"maximum is {_MAX_FQDN_LENGTH}"
        )
    return normalized


def _looks_like_ip(value: str) -> bool:
    """True when ``value`` parses as an IPv4/IPv6 address."""
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _normalize_label(label: str) -> str:
    """Validate and normalize one DNS label.

    Args:
        label: The raw label to check.

    Returns:
        The lowercased, IDNA-encoded ASCII label.

    Raises:
        ValidationError: If the label is too long or contains illegal
            characters (only letters, digits, and hyphens, not leading or
            trailing with a hyphen).
    """
    if len(label) > _MAX_LABEL_LENGTH:
        raise ValidationError(
            f"label {label!r} is {len(label)} characters; maximum is "
            f"{_MAX_LABEL_LENGTH}"
        )
    ascii_label = _idna_encode(label)
    if not _LABEL_RE.fullmatch(ascii_label):
        raise ValidationError(
            f"invalid label {label!r}: must contain only letters, digits, "
            "and hyphens, and must not start or end with a hyphen"
        )
    return ascii_label


def _idna_encode(label: str) -> str:
    """IDNA-encode ``label`` so Unicode hostnames become ASCII.

    Args:
        label: The raw label.

    Returns:
        The ASCII (punycode) form, lowercased.

    Raises:
        ValidationError: If the label cannot be IDNA-encoded.
    """
    try:
        return label.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ValidationError(f"invalid label {label!r}: {exc}") from exc


def validate_wordlist_line(line: str) -> str | None:
    """Validate a single wordlist entry.

    Blank lines and ``#`` comments are skipped. Entries may be single labels
    (``api``) or dotted prefixes (``api.v2``); both are validated as DNS
    labels. Path separators and wildcard characters are rejected.

    Args:
        line: A raw line from a wordlist file.

    Returns:
        The normalized lowercase entry, or None if the line is blank or a
        comment.

    Raises:
        ValidationError: If the entry contains invalid characters or an
            invalid label.
    """
    entry = line.strip().lower()
    if not entry or entry.startswith("#"):
        return None
    if any(c in entry for c in ("/", "\\", " ", "\t", "*", "?", '"', "'")):
        raise ValidationError(
            f"invalid wordlist entry {entry!r}: contains an illegal character"
        )
    for label in entry.split("."):
        _normalize_label(label)
    return entry


def load_wordlist(path: str) -> list[str]:
    """Load and validate a wordlist file.

    Args:
        path: Path to a newline-delimited wordlist.

    Returns:
        A de-duplicated, normalized list of valid entries.

    Raises:
        ValidationError: If any entry is invalid (illegal characters, bad
            labels, or over-length labels).
        OSError: If the file cannot be read.
    """
    seen: dict[str, None] = {}
    with open(path, "r", encoding="utf-8", errors="strict") as handle:
        for raw in handle:
            entry = validate_wordlist_line(raw)
            if entry is not None:
                seen.setdefault(entry, None)
    if not seen:
        raise ValidationError(f"wordlist {path!r} contains no valid entries")
    return list(seen)


def iter_builtin_wordlist() -> Iterator[str]:
    """Yield the bundled default wordlist entries (no file I/O on disk)."""
    import importlib.resources

    text = (
        importlib.resources.files("subdomain_enumerator")
        .joinpath("data", "common_subdomains.txt")
        .read_text(encoding="utf-8")
    )
    for raw in text.splitlines():
        entry = validate_wordlist_line(raw)
        if entry is not None:
            yield entry


def label_count(fqdn: str) -> int:
    """Number of labels in a fully qualified hostname (RFC 1035 subdomain)."""
    return fqdn.count(".") + 1