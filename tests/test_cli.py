"""Tests for the CLI (offline: DNS and crt.sh are stubbed)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from subdomain_enumerator import cli
from subdomain_enumerator.resolver import Resolution

from tests.conftest import DOMAIN, FakeResolver


@pytest.fixture
def wordlist(tmp_path: Path) -> Path:
    path = tmp_path / "words.txt"
    path.write_text("www\nmail\napi\n", encoding="utf-8")
    return path


@pytest.fixture
def offline_resolver(monkeypatch):
    """Point the CLI's Resolver at an in-memory FakeResolver."""

    def factory(**kwargs):
        return FakeResolver(
            records={
                "www.example.com": Resolution(ipv4=["1.2.3.4"], exists=True),
                "api.example.com": Resolution(ipv4=["2.3.4.5"], exists=True),
            }
        )

    monkeypatch.setattr(cli, "Resolver", factory)


def _run(args):
    return cli.main(["--no-crt", *args])


class TestSuccess:
    def test_encodes_default_quiet(self, offline_resolver, wordlist, capsys):
        assert _run(["-q", "-w", str(wordlist), DOMAIN]) == 0
        out = capsys.readouterr().out
        assert "www.example.com" in out
        assert "api.example.com" in out
        assert "mail.example.com" not in out

    def test_output_file_written(self, offline_resolver, wordlist, tmp_path):
        out_path = tmp_path / "results.json"
        assert (
            _run(
                [
                    "-q",
                    "-w",
                    str(wordlist),
                    "-f",
                    "json",
                    "-o",
                    str(out_path),
                    DOMAIN,
                ]
            )
            == 0
        )
        data = json.loads(out_path.read_text(encoding="utf-8"))
        assert {d["hostname"] for d in data} == {
            "www.example.com",
            "api.example.com",
        }

    def test_include_unresolved_shows_nxdomain_hosts(
        self, offline_resolver, wordlist, capsys
    ):
        assert (
            _run(
                ["-q", "--include-unresolved", "-w", str(wordlist), DOMAIN]
            )
            == 0
        )
        out = capsys.readouterr().out
        assert "mail.example.com" in out

    def test_no_bruteforce_does_not_require_wordlist(
        self, offline_resolver, capsys
    ):
        assert _run(["-q", "--no-bruteforce", DOMAIN]) == 0
        out = capsys.readouterr().out
        assert "No subdomains found." in out or "Hostname" in out


class TestExitCodes:
    @pytest.mark.parametrize(
        "args",
        [
            [],  # no domain
            ["-f", "yaml", DOMAIN],  # bad format choice
            ["-t", "0", DOMAIN],  # non-positive threads
            ["--resolver", "notanip", DOMAIN],  # bad nameserver
        ],
    )
    def test_argparse_errors_exit_2(self, offline_resolver, args):
        with pytest.raises(SystemExit) as excinfo:
            cli.main([*args])
        assert excinfo.value.code == 2

    @pytest.mark.parametrize(
        "args",
        [
            ["not a domain"],  # invalid domain -> ValidationError
            ["192.168.1.1"],  # IP rejected
        ],
    )
    def test_validation_errors_return_3(self, offline_resolver, args):
        assert cli.main(["-q", *args]) == 3

    def test_missing_wordlist_returns_3(self, offline_resolver, tmp_path):
        assert cli.main(["-q", "-w", str(tmp_path / "nope.txt"), DOMAIN]) == 3

    def test_invalid_domain_returns_3(self, offline_resolver, wordlist):
        assert cli.main(["-q", "-w", str(wordlist), "not a domain"]) == 3

    def test_domain_flag_required(self, offline_resolver):
        with pytest.raises(SystemExit) as excinfo:
            cli.main(["-q"])
        assert excinfo.value.code == 2

    def test_domain_dual_specification_errors(self, offline_resolver):
        with pytest.raises(SystemExit) as excinfo:
            cli.main(["-q", "--domain", DOMAIN, DOMAIN])
        assert excinfo.value.code == 2

    def test_mode_flags_mutually_exclusive(self, offline_resolver):
        with pytest.raises(SystemExit) as excinfo:
            cli.main(["-q", "--passive-only", "--active-only", DOMAIN])
        assert excinfo.value.code == 2


class TestModeFlags:
    def test_domain_flag(self, offline_resolver, wordlist, capsys):
        assert (
            cli.main(["-q", "--no-crt", "-w", str(wordlist), "--domain", DOMAIN])
            == 0
        )
        out = capsys.readouterr().out
        assert "www.example.com" in out

    def test_retries_zero_accepted(self, offline_resolver, wordlist):
        assert (
            cli.main(
                ["-q", "--no-crt", "-w", str(wordlist), "--retries", "0", DOMAIN]
            )
            == 0
        )

    def test_passive_only_runs_without_wordlist(
        self, offline_resolver, wordlist, capsys
    ):
        # --passive-only skips brute-force; with --no-crt no candidates remain.
        assert (
            cli.main(["-q", "--no-crt", "--passive-only", DOMAIN]) == 0
        )
        assert "No subdomains found." in capsys.readouterr().out

    def test_active_only_uses_wordlist(
        self, offline_resolver, wordlist, capsys
    ):
        assert (
            cli.main(["-q", "-w", str(wordlist), "--active-only", DOMAIN]) == 0
        )
        out = capsys.readouterr().out
        assert "www.example.com" in out


class TestBanner:
    def test_authorization_notice_printed_unless_quiet(
        self, offline_resolver, wordlist, capsys
    ):
        _run(["-w", str(wordlist), DOMAIN])
        err = capsys.readouterr().err
        assert "ONLY against domains you own" in err

    def test_quiet_suppresses_banner(
        self, offline_resolver, wordlist, capsys
    ):
        _run(["-q", "-w", str(wordlist), DOMAIN])
        err = capsys.readouterr().err
        assert "ONLY against domains" not in err


class TestSummary:
    def test_summary_includes_tested_found_elapsed(
        self, offline_resolver, wordlist, capsys
    ):
        _run(["-w", str(wordlist), DOMAIN])
        err = capsys.readouterr().err
        assert "Tested:" in err
        assert "Found:" in err
        assert "Elapsed:" in err
        assert "[+] www.example.com" in err  # live result line