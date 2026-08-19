"""Tests for domain and wordlist validation."""

from __future__ import annotations

import pytest

from subdomain_enumerator.validation import (
    ValidationError,
    label_count,
    load_wordlist,
    normalize_domain,
    validate_wordlist_line,
)


class TestNormalizeDomain:
    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("example.com", "example.com"),
            ("EXAMPLE.com", "example.com"),
            ("example.com.", "example.com"),
            ("  example.com  ", "example.com"),
            ("a.b.example.com", "a.b.example.com"),
            ("bücher.example", "xn--bcher-kva.example"),
            ("sub-domain.example.org", "sub-domain.example.org"),
        ],
    )
    def test_valid_domains(self, raw, expected):
        assert normalize_domain(raw) == expected

    @pytest.mark.parametrize(
        "raw",
        [
            "",
            "   ",
            "localhost",
            "com",  # single label
            "192.168.1.1",  # IP address
            "2001:db8::1",
            "-bad.example.com",  # leading hyphen
            "bad-.example.com",  # trailing hyphen
            "exa mple.com",  # space
            "under_score.example.com",  # underscore
            "a" * 64 + ".example.com",  # over-length label
            "a" * 254 + ".com",  # over-length fqdn
        ],
    )
    def test_invalid_domains(self, raw):
        with pytest.raises(ValidationError):
            normalize_domain(raw)


class TestWordlist:
    def test_blank_and_comments_skipped(self):
        assert validate_wordlist_line("") is None
        assert validate_wordlist_line("   ") is None
        assert validate_wordlist_line("# comment") is None

    def test_valid_entry_normalized(self):
        assert validate_wordlist_line("  API  ") == "api"

    def test_dotted_prefix_allowed(self):
        assert validate_wordlist_line("api.v2") == "api.v2"

    @pytest.mark.parametrize(
        "line",
        [
            "bad label",
            "a/b",
            "a\\b",
            "*.example",
            "?x",
            "qu'ote",
            '"quote"',
        ],
    )
    def test_illegal_characters_rejected(self, line):
        with pytest.raises(ValidationError):
            validate_wordlist_line(line)

    def test_load_wordlist_dedupes(self, tmp_path):
        path = tmp_path / "words.txt"
        path.write_text("# comment\n\napi\nAPI\nmail\n", encoding="utf-8")
        entries = load_wordlist(str(path))
        assert entries == ["api", "mail"]

    def test_load_wordlist_empty_file(self, tmp_path):
        path = tmp_path / "empty.txt"
        path.write_text("# only comments\n", encoding="utf-8")
        with pytest.raises(ValidationError, match="no valid entries"):
            load_wordlist(str(path))

    def test_load_missing_file(self, tmp_path):
        with pytest.raises(OSError):
            load_wordlist(str(tmp_path / "nope.txt"))


def test_label_count():
    assert label_count("a.b.c") == 3
    assert label_count("example.com") == 2