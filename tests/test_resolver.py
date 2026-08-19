"""Tests for the dnspython resolver wrapper.

The real ``Resolver`` is tested here by replacing its ``_query`` method with a
stub, so no network is involved. The stub returns canned answers keyed by
record type, mirroring how dnspython behaves.
"""

from __future__ import annotations

import dns.name
import dns.resolver
import pytest

from subdomain_enumerator.resolver import DnsQueryError, Resolution, Resolver


class FakeRecord:
    def __init__(self, address=None, target=None):
        self.address = address
        self.target = target


class FakeAnswer:
    def __init__(self, records):
        self._records = records

    def __iter__(self):
        return iter(self._records)

    def __len__(self):
        return len(self._records)


def _name(text: str) -> dns.name.Name:
    return dns.name.from_text(text)


class FakeDns:
    """Stands in for ``dns.resolver.Resolver`` with canned answers.

    Lives at ``Resolver._resolver`` so the real ``_query`` retry loop and
    exception translation still run.
    """

    def __init__(
        self,
        a=None,
        aaaa=None,
        cname=None,
        nxdomain=None,
        errors=None,
        noanswer=None,
    ):
        self.a = a or {}
        self.aaaa = aaaa or {}
        self.cname = cname or {}
        self.nxdomain = nxdomain or set()
        self.errors = errors or set()
        self.noanswer = noanswer or set()

    def resolve(self, hostname, rdtype, lifetime=5.0, tcp=False):
        if hostname in self.errors:
            raise dns.exception.Timeout(timeout=lifetime)
        if hostname in self.noanswer:
            raise dns.resolver.NoAnswer()
        if rdtype == "CNAME":
            if hostname in self.cname:
                return FakeAnswer(
                    [FakeRecord(target=_name(self.cname[hostname]))]
                )
            raise dns.resolver.NoAnswer()
        if hostname in self.nxdomain:
            raise dns.resolver.NXDOMAIN()
        if rdtype == "A":
            if hostname in self.a:
                return FakeAnswer(
                    [FakeRecord(address=ip) for ip in self.a[hostname]]
                )
            raise dns.resolver.NoAnswer()
        if rdtype == "AAAA":
            if hostname in self.aaaa:
                return FakeAnswer(
                    [FakeRecord(address=ip) for ip in self.aaaa[hostname]]
                )
            raise dns.resolver.NoAnswer()
        raise dns.resolver.NoAnswer()


def make_resolver(
    a: dict[str, list[str]] | None = None,
    aaaa: dict[str, list[str]] | None = None,
    cname: dict[str, str] | None = None,
    nxdomain: set[str] | None = None,
    errors: set[str] | None = None,
    noanswer: set[str] | None = None,
) -> Resolver:
    """Build a Resolver whose backing dnspython object is a canned stub."""
    resolver = Resolver()
    resolver._resolver = FakeDns(
        a=a, aaaa=aaaa, cname=cname, nxdomain=nxdomain,
        errors=errors, noanswer=noanswer,
    )
    return resolver


class TestResolve:
    def test_a_record(self):
        r = make_resolver(a={"www.example.com": ["1.2.3.4"]})
        result = r.resolve("www.example.com")
        assert result == Resolution(ipv4=["1.2.3.4"], exists=True)

    def test_a_and_aaaa(self):
        r = make_resolver(
            a={"host.example.com": ["1.2.3.4"]},
            aaaa={"host.example.com": ["2001:db8::1"]},
        )
        result = r.resolve("host.example.com")
        assert result.ipv4 == ["1.2.3.4"]
        assert result.ipv6 == ["2001:db8::1"]
        assert result.exists

    def test_cname_only(self):
        r = make_resolver(cname={"cdn.example.com": "assets.example.net."})
        result = r.resolve("cdn.example.com")
        assert result.cname == "assets.example.net"
        assert result.exists

    def test_nxdomain_is_not_resolved(self):
        r = make_resolver(nxdomain={"gone.example.com"})
        result = r.resolve("gone.example.com")
        assert not result.exists
        assert result.ipv4 == []

    def test_no_answer_is_unresolved(self):
        r = make_resolver(noanswer={"quiet.example.com"})
        result = r.resolve("quiet.example.com")
        assert not result.exists

    def test_dangling_cname_keeps_cname(self):
        # CNAME exists but the A query on the alias raises NXDOMAIN.
        r = make_resolver(
            cname={"old.example.com": "gone.bucket.s3.amazonaws.com."},
            nxdomain={"old.example.com"},
        )
        result = r.resolve("old.example.com")
        assert result.cname == "gone.bucket.s3.amazonaws.com"
        assert result.exists

    def test_timeout_raises_after_retries(self):
        r = make_resolver(errors={"flaky.example.com"})
        try:
            r.resolve("flaky.example.com")
        except DnsQueryError as exc:
            assert "attempt" in str(exc)
        else:
            pytest.fail("expected DnsQueryError")


class TestNameExists:
    def test_nxdomain_is_false(self):
        r = make_resolver(nxdomain={"gone.example.com"})
        assert r.name_exists("gone.example.com") is False

    def test_no_answer_is_true(self):
        r = make_resolver(noanswer={"quiet.example.com"})
        assert r.name_exists("quiet.example.com") is True

    def test_existing_is_true(self):
        r = make_resolver(a={"www.example.com": ["1.2.3.4"]})
        assert r.name_exists("www.example.com") is True

    def test_is_dangling_inverts_name_exists(self):
        r = make_resolver(nxdomain={"gone.example.com"})
        assert r.is_dangling("gone.example.com") is True
        assert r.is_dangling("www.example.com") is False


class TestDetectWildcard:
    def test_no_wildcard(self):
        import secrets

        r = make_resolver(nxdomain={f"{secrets.token_hex(8)}.example.com"})
        info = r.detect_wildcard("example.com", samples=2)
        assert info.active is False
        assert info.ips == set()

    def test_wildcard_detected(self, monkeypatch):
        # A resolver that answers for ANY name (mimics *.example.com).
        r = make_resolver(a={"anything.example.com": ["10.0.0.1"]})
        monkeypatch.setattr(
            r,
            "resolve",
            lambda hostname: Resolution(ipv4=["10.0.0.1"], exists=True)
            if hostname.endswith(".example.com")
            else Resolution(),
        )
        info = r.detect_wildcard("example.com", samples=3)
        assert info.active is True
        assert info.ips == {"10.0.0.1"}