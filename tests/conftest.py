"""Shared fixtures and a fully offline fake DNS resolver.

All tests that exercise the enumeration pipeline use :class:`FakeResolver`,
which implements the same public interface as
:class:`subdomain_enumerator.resolver.Resolver` but answers from an in-memory
table. This keeps the suite deterministic and network-free.
"""

from __future__ import annotations

import pytest

from subdomain_enumerator.resolver import DnsQueryError, Resolution, WildcardInfo

DOMAIN = "example.com"


class FakeResolver:
    """In-memory DNS resolver for deterministic tests."""

    def __init__(
        self,
        records: dict[str, Resolution] | None = None,
        wildcard: WildcardInfo | None = None,
        dangling: set[str] | None = None,
        errors: set[str] | None = None,
    ) -> None:
        self.records = records or {}
        self.wildcard = wildcard or WildcardInfo()
        self.dangling = set(dangling or [])
        self.errors = set(errors or [])

    def resolve(self, hostname: str) -> Resolution:
        if hostname in self.errors:
            raise DnsQueryError(f"simulated DNS failure for {hostname}")
        if hostname in self.records:
            return self.records[hostname]
        return Resolution()

    def detect_wildcard(self, domain: str, samples: int = 2) -> WildcardInfo:
        return self.wildcard

    def name_exists(self, hostname: str) -> bool:
        return hostname not in self.dangling

    def is_dangling(self, hostname: str) -> bool:
        return hostname in self.dangling


@pytest.fixture
def fake_resolver() -> type[FakeResolver]:
    return FakeResolver


def resolution(
    ipv4: list[str] | None = None,
    ipv6: list[str] | None = None,
    cname: str | None = None,
    exists: bool = True,
) -> Resolution:
    """Build a Resolution with sensible defaults."""
    return Resolution(ipv4=ipv4 or [], ipv6=ipv6 or [], cname=cname, exists=exists)


@pytest.fixture(autouse=True)
def _no_network(monkeypatch):
    """Guarantee the suite never touches the real network.

    Any test that forgets to stub the crt.sh fetcher (or that would otherwise
    reach out over HTTP) fails loudly instead of making a live request.
    """
    import subdomain_enumerator.sources as sources

    def _block(*args, **kwargs):
        raise AssertionError(
            "network access is disabled in tests; stub the fetcher or use "
            "--no-crt"
        )

    monkeypatch.setattr(sources, "_default_fetcher", _block)
    yield