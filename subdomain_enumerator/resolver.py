"""DNS resolution layer built on dnspython.

This module wraps :mod:`dns.resolver` behind a small, testable interface and
adds the two behaviours that make subdomain enumeration reliable:

- **Query independence**: each hostname is queried for CNAME (without
  following), A, and AAAA records. CNAMEs matter for takeover detection;
  A/AAAA matter for "does it resolve".
- **Wildcard handling**: before enumeration the engine asks
  :func:`detect_wildcard` whether the root domain answers for random,
  non-existent labels. If it does, the returned IP set is used to filter out
  wildcard false positives later.

Retries are bounded and every timeout or SERVFAIL is surfaced as
:class:`DnsQueryError` so the caller can decide (default: fail the run) rather
than silently swallowing DNS instability.
"""

from __future__ import annotations

import dns.exception
import dns.resolver
from dataclasses import dataclass, field

_DEFAULT_NAMESERVERS: list[str] | None = None


class DnsQueryError(RuntimeError):
    """Raised when a DNS query cannot be completed reliably."""


@dataclass
class Resolution:
    """What the resolver learned about one hostname.

    Attributes:
        ipv4: A record addresses (dotted quad strings).
        ipv6: AAAA record addresses (compressed strings).
        cname: The raw CNAME target of the queried name, if it is an alias.
        exists: True if the name has a CNAME, A, or AAAA record. This is what
            distinguishes "the name resolves" from "the name is NXDOMAIN".
    """

    ipv4: list[str] = field(default_factory=list)
    ipv6: list[str] = field(default_factory=list)
    cname: str | None = None
    exists: bool = False


@dataclass
class WildcardInfo:
    """Result of probing the root domain for a DNS wildcard.

    Attributes:
        active: True when the domain answers for random non-existent labels.
        ips: Union of IP addresses the wildcard answered with across samples.
    """

    active: bool = False
    ips: set[str] = field(default_factory=set)


def default_nameservers() -> list[str]:
    """The system-configured recursive resolvers.

    Reads the configured nameservers once and caches them. Falls back to
    ``8.8.8.8`` if dnspython cannot discover any.
    """
    global _DEFAULT_NAMESERVERS
    if _DEFAULT_NAMESERVERS is None:
        try:
            _DEFAULT_NAMESERVERS = dns.resolver.Resolver().nameservers
        except Exception:  # pragma: no cover - environment dependent
            _DEFAULT_NAMESERVERS = ["8.8.8.8"]
    return list(_DEFAULT_NAMESERVERS)


class Resolver:
    """Thin wrapper around ``dns.resolver.Resolver`` with bounded retries."""

    def __init__(
        self,
        nameservers: list[str] | None = None,
        timeout: float = 5.0,
        retries: int = 2,
        tcp: bool = False,
    ) -> None:
        """Wrap ``dns.resolver.Resolver`` with bounded retries.

        Args:
            nameservers: Optional list of recursive nameserver IPs to use
                instead of the system-configured resolvers.
            timeout: Per-query lifetime in seconds.
            retries: Number of retries after a timeout or no-nameserver error
                (each attempt counts toward ``retries + 1`` total queries).
            tcp: Force TCP for DNS queries.
        """
        self._resolver = dns.resolver.Resolver(configure=True)
        if nameservers:
            self._resolver.nameservers = nameservers
        self._timeout = timeout
        self._retries = max(0, retries)
        self._tcp = tcp

    def _query(self, hostname: str, rdtype: str) -> dns.resolver.Answer:
        """Query ``rdtype`` for ``hostname`` with retry-on-timeout.

        Args:
            hostname: The name to query.
            rdtype: DNS record type string (``"A"``, ``"AAAA"``, ``"CNAME"``).

        Returns:
            The dnspython answer object.

        Raises:
            DnsQueryError: If every attempt times out or no nameserver
                responds.
            dns.resolver.NXDOMAIN: If the name does not exist (re-raised so
                callers can distinguish a definitive NXDOMAIN from a soft
                failure).
        """
        last_error: dns.exception.DNSException | None = None
        for attempt in range(self._retries + 1):
            try:
                return self._resolver.resolve(
                    hostname,
                    rdtype,
                    lifetime=self._timeout,
                    tcp=self._tcp,
                )
            except dns.resolver.NXDOMAIN:
                raise
            except (dns.exception.Timeout, dns.resolver.NoNameservers) as exc:
                last_error = exc
                continue
        assert last_error is not None
        raise DnsQueryError(
            f"DNS query for {hostname} {rdtype} failed after "
            f"{self._retries + 1} attempt(s): {last_error}"
        ) from last_error

    def resolve(self, hostname: str) -> Resolution:
        """Resolve a hostname's CNAME, A, and AAAA records.

        Args:
            hostname: Fully qualified hostname without a trailing dot.

        Returns:
            A :class:`Resolution` describing the records found.

        Raises:
            DnsQueryError: If the query repeatedly times out or no usable
                nameserver responds.
        """
        result = Resolution()

        # Query the raw CNAME (without following) so takeover detection can
        # see where the alias points.
        try:
            cname_answer = self._query(hostname, "CNAME")
            for record in cname_answer:
                result.cname = str(record.target).rstrip(".")
                result.exists = True
        except dns.resolver.NXDOMAIN:
            return result
        except (dns.resolver.NoAnswer, dns.resolver.NoMetaqueries):
            pass

        # A and AAAA queries follow CNAME chains automatically. A name whose
        # chain ends at NXDOMAIN still "exists" as an alias -- that is the
        # dangling-CNAME signature that takeover detection looks for.
        for rdtype, target in (("A", result.ipv4), ("AAAA", result.ipv6)):
            try:
                answer = self._query(hostname, rdtype)
                for record in answer:
                    target.append(str(record.address))
                if target:
                    result.exists = True
            except dns.resolver.NXDOMAIN:
                if result.cname:
                    result.exists = True
                continue
            except (dns.resolver.NoAnswer, dns.resolver.NoMetaqueries):
                continue

        return result

    def name_exists(self, hostname: str) -> bool:
        """True if any record type exists for ``hostname`` (NXDOMAIN check).

        NXDOMAIN means the name genuinely does not exist. Any other response
        (even an empty answer) means the name is present in DNS.
        """
        try:
            answer = self._query(hostname, "A")
            return len(answer) > 0
        except dns.resolver.NXDOMAIN:
            return False
        except (dns.resolver.NoAnswer, dns.resolver.NoMetaqueries):
            return True

    def detect_wildcard(self, domain: str, samples: int = 2) -> WildcardInfo:
        """Probe ``domain`` for a wildcard record matching non-existent names.

        Queries ``samples`` random labels and unions the IPs answered. If any
        sample resolves, the domain has a wildcard; the unioned IP set is the
        signature used to filter false positives.

        Args:
            domain: The root domain to probe.
            samples: Number of distinct random labels to query (default 2).

        Returns:
            :class:`WildcardInfo` describing whether a wildcard exists and the
            IP addresses it answers with.
        """
        import secrets

        info = WildcardInfo()
        for _ in range(max(1, samples)):
            probe = f"{secrets.token_hex(8)}.{domain}"
            resolution = self.resolve(probe)
            if resolution.exists:
                info.active = True
                info.ips.update(resolution.ipv4)
                info.ips.update(resolution.ipv6)
        return info

    def is_dangling(self, hostname: str) -> bool:
        """True if ``hostname`` is NXDOMAIN (a candidate dangling target).

        Used by takeover detection: a CNAME whose target no longer exists is
        the classic signature of a subdomain takeover.
        """
        return not self.name_exists(hostname)