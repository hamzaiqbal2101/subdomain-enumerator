"""Integration-style tests of the Enumerator pipeline (all offline)."""

from __future__ import annotations

from subdomain_enumerator.enumerator import Enumerator, matches_wildcard
from subdomain_enumerator.model import Subdomain
from subdomain_enumerator.resolver import WildcardInfo

from tests.conftest import DOMAIN, FakeResolver, resolution


def run(
    entries,
    records=None,
    wildcard=None,
    dangling=None,
    errors=None,
    **kwargs,
):
    resolver = FakeResolver(
        records=records or {},
        wildcard=wildcard or WildcardInfo(),
        dangling=set(dangling or []),
        errors=set(errors or []),
    )
    enumerator = Enumerator(
        domain=DOMAIN,
        resolver=resolver,
        use_cert_transparency=False,
        **kwargs,
    )
    results = enumerator.run(entries)
    return results, enumerator


class TestResolution:
    def test_resolved_subdomains_found(self):
        records = {
            "www.example.com": resolution(ipv4=["1.2.3.4"]),
            "mail.example.com": resolution(ipv4=["5.6.7.8"]),
        }
        results, _ = run(["www", "mail", "nope"], records=records)
        names = [r.name for r in results]
        assert names == ["mail.example.com", "www.example.com"]
        assert all(r.resolved for r in results)

    def test_cname_record_preserved(self):
        records = {"cdn.example.com": resolution(cname="assets.example.net")}
        results, _ = run(["cdn"], records=records)
        assert results[0].cname == "assets.example.net"
        assert results[0].is_alias

    def test_unresolved_filtered_by_default(self):
        records = {"www.example.com": resolution(ipv4=["1.2.3.4"])}
        results, _ = run(["www", "gone"], records=records)
        assert [r.name for r in results] == ["www.example.com"]

    def test_include_unresolved(self):
        records = {"www.example.com": resolution(ipv4=["1.2.3.4"])}
        results, _ = run(
            ["www", "gone"], records=records, include_unresolved=True
        )
        names = [r.name for r in results]
        assert "gone.example.com" in names
        gone = next(r for r in results if r.name == "gone.example.com")
        assert gone.resolved is False

    def test_dns_errors_counted_but_do_not_abort(self):
        results, enumerator = run(
            ["www", "flaky"],
            records={"www.example.com": resolution(ipv4=["1.2.3.4"])},
            errors={"flaky.example.com"},
        )
        assert [r.name for r in results] == ["www.example.com"]
        assert enumerator.stats.dns_errors == 1


class TestWildcard:
    def test_wildcard_echo_filtered(self):
        wildcard = WildcardInfo(active=True, ips={"10.0.0.1"})
        records = {
            "www.example.com": resolution(ipv4=["1.2.3.4"]),
            "random1.example.com": resolution(ipv4=["10.0.0.1"]),
        }
        results, enumerator = run(
            ["www", "random1"], records=records, wildcard=wildcard
        )
        assert [r.name for r in results] == ["www.example.com"]
        assert enumerator.stats.wildcard_filtered == 1

    def test_include_wildcards_keeps_them(self):
        wildcard = WildcardInfo(active=True, ips={"10.0.0.1"})
        records = {"random1.example.com": resolution(ipv4=["10.0.0.1"])}
        results, _ = run(
            ["random1"], records=records, wildcard=wildcard, include_wildcards=True
        )
        assert results[0].name == "random1.example.com"
        assert results[0].wildcard is True

    def test_subset_of_wildcard_ips_is_filtered(self):
        # A host answering with a subset of the wildcard IPs is still a
        # wildcard echo (e.g. a single-record wildcard answer).
        wildcard = WildcardInfo(active=True, ips={"10.0.0.1", "10.0.0.2"})
        records = {"host.example.com": resolution(ipv4=["10.0.0.1"])}
        results, enumerator = run(
            ["host"], records=records, wildcard=wildcard
        )
        assert results == []
        assert enumerator.stats.wildcard_filtered == 1


class TestTakeover:
    def test_dangling_cname_flagged_high(self):
        records = {
            "old.example.com": resolution(
                cname="old.s3.amazonaws.com", exists=True
            )
        }
        results, enumerator = run(
            ["old"], records=records, dangling={"old.s3.amazonaws.com"}
        )
        assert results[0].takeover is not None
        assert results[0].takeover.confidence == "high"
        assert enumerator.stats.takeover_candidates == 1

    def test_no_takeover_check_when_disabled(self):
        records = {
            "old.example.com": resolution(
                cname="old.s3.amazonaws.com", exists=True
            )
        }
        results, enumerator = run(
            ["old"],
            records=records,
            dangling={"old.s3.amazonaws.com"},
            check_takeover=False,
        )
        assert results[0].takeover is None


class TestMerge:
    def test_duplicate_across_sources_merged(self, monkeypatch):
        """www.example.com found by CT and wordlist resolves once, merged."""
        records = {"www.example.com": resolution(ipv4=["1.2.3.4"])}
        resolver = FakeResolver(records=records)

        from subdomain_enumerator import enumerator as en

        monkeypatch.setattr(
            en,
            "fetch_certificate_transparency",
            lambda domain: ["www.example.com"],
        )
        enumerator = Enumerator(DOMAIN, resolver, use_cert_transparency=True)
        results = enumerator.run(["www"])
        assert len(results) == 1
        assert results[0].sources == {"crt.sh", "wordlist"}


class TestResultCallback:
    def test_fires_for_each_kept_result(self):
        records = {
            "www.example.com": resolution(ipv4=["1.2.3.4"]),
            "mail.example.com": resolution(ipv4=["5.6.7.8"]),
        }
        seen = []

        def callback(record):
            seen.append(record.name)

        results, _ = run(
            ["www", "mail", "nope"],
            records=records,
            result_callback=callback,
        )
        assert sorted(seen) == sorted(r.name for r in results)
        assert "nope.example.com" not in seen

    def test_does_not_fire_for_wildcard_filtered(self):
        wildcard = WildcardInfo(active=True, ips={"10.0.0.1"})
        records = {
            "echo.example.com": resolution(ipv4=["10.0.0.1"]),
            "www.example.com": resolution(ipv4=["1.2.3.4"]),
        }
        seen = []

        def callback(record):
            seen.append(record.name)

        results, _ = run(
            ["echo", "www"],
            records=records,
            wildcard=wildcard,
            result_callback=callback,
        )
        assert seen == ["www.example.com"]
        assert len(results) == 1


def test_matches_wildcard_requires_active_wildcard():
    record = Subdomain(name="x.example.com", ipv4=["10.0.0.1"], resolved=True)
    assert not matches_wildcard(record, WildcardInfo())
    assert matches_wildcard(
        record, WildcardInfo(active=True, ips={"10.0.0.1"})
    )