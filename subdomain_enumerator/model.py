"""Data models for the subdomain enumerator.

These dataclasses are the single source of truth passed between the
enumeration engine, the resolvers, and the output formatters. Keeping the
model explicit (rather than passing raw dicts around) makes the data flow
easy to follow and unit-test.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class TakeoverResult:
    """Result of a CNAME takeover check for one subdomain.

    A subdomain is a candidate for takeover when its CNAME points at a
    third-party service (S3 bucket, GitHub Pages site, etc.) that is no longer
    provisioned. The definitive confirmation usually requires an HTTP-level
    probe; ``confidence`` reflects how strongly the passive DNS check
    indicates a dangling target.
    """

    service: str
    cname_target: str
    confidence: str  # one of "high", "medium", "low"
    detail: str


@dataclass
class Subdomain:
    """A discovered hostname and everything the enumeration learned about it.

    Attributes:
        name: Fully qualified, lowercased hostname (without trailing dot).
        ipv4: Resolved A record addresses.
        ipv6: Resolved AAAA record addresses.
        cname: Canonical name target, if the hostname is an alias.
        sources: Where the name was discovered (``wordlist``, ``crt.sh``, ...).
        resolved: Whether any DNS records were returned. False means the name
            was reported by an OSINT source but does not currently resolve.
        wildcard: True when the hostname matched the domain's wildcard
            signature and is therefore almost certainly a wildcard false
            positive rather than a real host.
        takeover: Result of the CNAME takeover check, if one was performed.
    """

    name: str
    ipv4: list[str] = field(default_factory=list)
    ipv6: list[str] = field(default_factory=list)
    cname: str | None = None
    sources: set[str] = field(default_factory=set)
    resolved: bool = False
    wildcard: bool = False
    takeover: TakeoverResult | None = None

    def add_source(self, source: str) -> None:
        """Record that ``source`` reported this hostname."""
        self.sources.add(source)

    @property
    def ip_addresses(self) -> list[str]:
        """All resolved IP addresses (IPv4 then IPv6), deduplicated."""
        seen: set[str] = set()
        ordered: list[str] = []
        for ip in [*self.ipv4, *self.ipv6]:
            if ip not in seen:
                seen.add(ip)
                ordered.append(ip)
        return ordered

    @property
    def is_alias(self) -> bool:
        """True when this hostname is a CNAME rather than a direct A/AAAA."""
        return self.cname is not None

    @property
    def record_type(self) -> str:
        """The DNS record type this hostname was discovered with.

        ``CNAME`` for aliases (the raw record at this name), ``A`` for direct
        address records, ``none`` for hostnames with no records.
        """
        if self.cname:
            return "CNAME"
        if self.ipv4 or self.ipv6:
            return "A"
        return "none"

    def merge(self, other: "Subdomain") -> None:
        """Fold ``other`` (a duplicate discovery) into this record."""
        for ip in other.ipv4:
            if ip not in self.ipv4:
                self.ipv4.append(ip)
        for ip in other.ipv6:
            if ip not in self.ipv6:
                self.ipv6.append(ip)
        if other.cname and not self.cname:
            self.cname = other.cname
        self.sources |= other.sources
        self.resolved = self.resolved or other.resolved
        self.wildcard = self.wildcard or other.wildcard
        if other.takeover and not self.takeover:
            self.takeover = other.takeover