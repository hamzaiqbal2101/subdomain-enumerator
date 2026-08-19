"""Tests for the crt.sh OSINT source (parsing + fetch error handling)."""

from __future__ import annotations

import json

import pytest
import requests

from subdomain_enumerator.sources import (
    SourceError,
    fetch_certificate_transparency,
    parse_crtsh_json,
)

DOMAIN = "example.com"


def _body(entries):
    return json.dumps(entries)


class TestParse:
    def test_extracts_names_and_dedupes(self):
        body = _body(
            [
                {"name_value": "www.example.com\napi.example.com"},
                {"name_value": "www.example.com"},
                {"name_value": "*.cdn.example.com"},
            ]
        )
        assert parse_crtsh_json(body, DOMAIN) == [
            "api.example.com",
            "cdn.example.com",
            "www.example.com",
        ]

    def test_discards_names_outside_domain(self):
        body = _body(
            [
                {"name_value": "www.example.com"},
                {"name_value": "evil.org"},
                {"name_value": "example.com"},
            ]
        )
        assert parse_crtsh_json(body, DOMAIN) == ["www.example.com"]

    def test_common_name_fallback_not_used_if_no_name_value(self):
        body = _body([{"common_name": "x.example.com"}])
        assert parse_crtsh_json(body, DOMAIN) == []

    def test_invalid_json_raises(self):
        with pytest.raises(SourceError, match="invalid JSON"):
            parse_crtsh_json("not json", DOMAIN)

    def test_non_list_payload_raises(self):
        with pytest.raises(SourceError, match="unexpected payload"):
            parse_crtsh_json('{"a": 1}', DOMAIN)

    def test_empty_list_is_fine(self):
        assert parse_crtsh_json("[]", DOMAIN) == []

    def test_unicode_names_kept(self):
        body = _body([{"name_value": "täst.example.com"}])
        assert parse_crtsh_json(body, DOMAIN) == ["täst.example.com"]


class TestFetch:
    def test_success_with_injected_fetcher(self):
        def fetcher(url, timeout):
            assert "%25.example.com" in url
            return _body([{"name_value": "www.example.com"}])

        assert fetch_certificate_transparency(DOMAIN, fetcher=fetcher) == [
            "www.example.com"
        ]

    def test_http_error_raises_source_error(self):
        def fetcher(url, timeout):
            response = requests.Response()
            response.status_code = 502
            raise requests.exceptions.HTTPError(response=response)

        with pytest.raises(SourceError, match="HTTP 502"):
            fetch_certificate_transparency(DOMAIN, fetcher=fetcher)

    def test_timeout_raises_source_error(self):
        def fetcher(url, timeout):
            raise requests.exceptions.ConnectTimeout("timed out")

        with pytest.raises(SourceError, match="timed out"):
            fetch_certificate_transparency(DOMAIN, fetcher=fetcher)

    def test_network_error_raises_source_error(self):
        def fetcher(url, timeout):
            raise requests.exceptions.ConnectionError("boom")

        with pytest.raises(SourceError, match="unreachable"):
            fetch_certificate_transparency(DOMAIN, fetcher=fetcher)

    def test_tls_error_raises_source_error(self):
        def fetcher(url, timeout):
            raise requests.exceptions.SSLError("cert verify failed")

        with pytest.raises(SourceError, match="TLS error"):
            fetch_certificate_transparency(DOMAIN, fetcher=fetcher)