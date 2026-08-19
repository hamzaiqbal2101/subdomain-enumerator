"""Passive OSINT sources for subdomain discovery.

The primary source is Certificate Transparency (CT) logs, queried through the
public crt.sh API. CT is a passive, low-noise source: every TLS certificate a
domain has been issued is logged, and certificate names are a rich source of
subdomains -- including hosts that are no longer in DNS (which is exactly what
a security assessment wants to see).

The module is deliberately small and testable: the HTTP fetching is isolated
behind an injectable ``fetcher`` callable so tests can exercise the parsing
without touching the network.
"""

from __future__ import annotations

import json
from collections.abc import Callable

import requests

CRTSH_URL = "https://crt.sh/?q=%25.{domain}&output=json"
CRTSH_TIMEOUT = 30.0
_USER_AGENT = "subdomain-enumerator/1.0 (security assessment; authorized use only)"


class SourceError(RuntimeError):
    """Raised when an OSINT source cannot be reached or returns bad data."""


def _default_fetcher(url: str, timeout: float) -> str:
    """Fetch ``url`` and return its body as text.

    Uses ``requests``; certificate verification is NOT disabled, so a TLS
    error aborts the fetch. Non-2xx responses raise ``HTTPError``.
    """
    response = requests.get(
        url, timeout=timeout, headers={"User-Agent": _USER_AGENT}
    )
    response.raise_for_status()
    return response.text


Fetcher = Callable[[str, float], str]


def _names_from_entry(entry: dict) -> list[str]:
    """Extract and normalize names from a single crt.sh JSON entry.

    crt.sh entries carry a ``name_value`` field that can contain several
    newline-separated names. ``*.`` wildcard prefixes are stripped.
    """
    raw_names = entry.get("name_value", "")
    names: list[str] = []
    for raw in str(raw_names).splitlines():
        name = raw.strip().lstrip("*.").lower()
        if name:
            names.append(name)
    return names


def _is_within(name: str, domain: str) -> bool:
    """True when ``name`` equals ``domain`` or is a subdomain of it."""
    return name == domain or name.endswith("." + domain)


def parse_crtsh_json(body: str, domain: str) -> list[str]:
    """Parse a crt.sh JSON response into normalized subdomain names.

    Args:
        body: Raw JSON text returned by crt.sh.
        domain: The root domain; entries outside it are discarded.

    Returns:
        Unique, lowercased hostnames within ``domain`` (wildcard prefixes
        stripped, leading/trailing dots removed).

    Raises:
        SourceError: If the body is not valid JSON.
    """
    try:
        entries = json.loads(body)
    except json.JSONDecodeError as exc:
        raise SourceError("crt.sh returned invalid JSON") from exc
    if not isinstance(entries, list):
        raise SourceError("crt.sh returned an unexpected payload structure")

    found: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        for name in _names_from_entry(entry):
            if name == domain:
                continue
            if _is_within(name, domain):
                found.add(name)
    return sorted(found)


def fetch_certificate_transparency(
    domain: str,
    timeout: float = CRTSH_TIMEOUT,
    fetcher: Fetcher | None = None,
) -> list[str]:
    """Query crt.sh for every hostname ever seen in a certificate for ``domain``.

    Args:
        domain: The root domain (already validated).
        timeout: HTTP timeout in seconds.
        fetcher: Callable used to fetch the URL; injectable for tests. Defaults
            to the standard-library HTTPS fetcher.

    Returns:
        Unique, normalized subdomain names, or ``[]`` if the source returned
        no usable data.

    Raises:
        SourceError: If the request fails (network, TLS, HTTP status) or the
            response is not parseable JSON.
    """
    fetcher = fetcher or _default_fetcher
    url = CRTSH_URL.format(domain=domain)
    try:
        body = fetcher(url, timeout)
    except requests.exceptions.HTTPError as exc:
        code = exc.response.status_code if exc.response is not None else 0
        raise SourceError(f"crt.sh returned HTTP {code} for {domain}") from exc
    except requests.exceptions.Timeout as exc:
        raise SourceError(f"crt.sh timed out for {domain}") from exc
    except requests.exceptions.SSLError as exc:
        raise SourceError(f"crt.sh TLS error for {domain}: {exc}") from exc
    except requests.exceptions.RequestException as exc:
        raise SourceError(f"crt.sh unreachable for {domain}: {exc}") from exc

    return parse_crtsh_json(body, domain)