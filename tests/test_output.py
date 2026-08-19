"""Tests for the output formatters."""

from __future__ import annotations

import json

import pytest

from subdomain_enumerator.model import Subdomain, TakeoverResult
from subdomain_enumerator.output import render, to_csv, to_json, to_names, to_table


def _record(
    name="www.example.com",
    ipv4=None,
    ipv6=None,
    cname=None,
    sources=None,
    resolved=True,
    takeover=None,
):
    return Subdomain(
        name=name,
        ipv4=ipv4 or [],
        ipv6=ipv6 or [],
        cname=cname,
        sources=sources or {"wordlist"},
        resolved=resolved,
        takeover=takeover,
    )


def _records():
    return [
        _record(
            name="www.example.com",
            ipv4=["1.2.3.4"],
            ipv6=["2001:db8::1"],
        ),
        _record(
            name="old.example.com",
            cname="old.s3.amazonaws.com",
            sources={"crt.sh"},
            takeover=TakeoverResult(
                service="Amazon S3",
                cname_target="old.s3.amazonaws.com",
                confidence="high",
                detail="dangling",
            ),
        ),
    ]


class TestTable:
    def test_contains_headers_and_rows(self):
        out = to_table(_records())
        assert "Hostname" in out
        assert "www.example.com" in out
        assert "old.example.com" in out

    def test_empty_records(self):
        assert to_table([]) == "No subdomains found."


class TestJson:
    def test_structure(self):
        data = json.loads(to_json(_records()))
        assert [d["hostname"] for d in data] == [
            "www.example.com",
            "old.example.com",
        ]
        assert data[0]["record_type"] == "A"
        assert data[1]["record_type"] == "CNAME"
        takeover_row = data[1]["takeover"]
        assert takeover_row["confidence"] == "high"
        assert takeover_row["service"] == "Amazon S3"

    def test_no_takeover_key_when_absent(self):
        data = json.loads(to_json([_record()]))
        assert "takeover" not in data[0]


class TestCsv:
    def test_header_and_rows(self):
        out = to_csv(_records())
        lines = out.splitlines()
        assert lines[0].startswith("hostname,record_type,ipv4")
        assert "www.example.com,A,1.2.3.4," in lines[1]
        assert "old.example.com,CNAME,,,old.s3.amazonaws.com" in lines[2]
        assert "high" in lines[2]

    def test_csv_round_trips_through_csv_module(self):
        import csv
        import io

        rows = list(csv.reader(io.StringIO(to_csv(_records()))))
        assert rows[0][0] == "hostname"
        assert rows[1][0] == "www.example.com"


class TestNames:
    def test_bare_hostnames(self):
        assert to_names(_records()) == (
            "www.example.com\nold.example.com"
        )


class TestRender:
    def test_unknown_format_raises(self):
        with pytest.raises(ValueError, match="unknown output format"):
            render(_records(), "yaml")

    @pytest.mark.parametrize("fmt", ["table", "json", "csv", "list"])
    def test_known_formats_render(self, fmt):
        assert render(_records(), fmt)  # non-empty, no exception