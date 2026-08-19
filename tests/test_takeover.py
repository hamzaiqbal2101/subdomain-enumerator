"""Tests for CNAME takeover detection."""

from __future__ import annotations

import pytest

from subdomain_enumerator import takeover


class _Resolver:
    """Resolver stub exposing only what check_takeover needs."""

    def __init__(self, dangling: set[str]):
        self._dangling = dangling

    def is_dangling(self, hostname: str) -> bool:
        return hostname in self._dangling


def test_known_service_dangling_is_high():
    resolver = _Resolver(dangling={"myapp.s3.amazonaws.com"})
    result = takeover.check_takeover("myapp.s3.amazonaws.com", resolver)
    assert result is not None
    assert result.service == "Amazon S3"
    assert result.confidence == "high"


def test_known_service_resolving_is_low():
    resolver = _Resolver(dangling=set())
    result = takeover.check_takeover("myapp.s3.amazonaws.com", resolver)
    assert result is not None
    assert result.confidence == "low"


def test_unknown_service_dangling_is_medium():
    resolver = _Resolver(dangling={"mystery.somecloud.io"})
    result = takeover.check_takeover("mystery.somecloud.io", resolver)
    assert result is not None
    assert result.confidence == "medium"
    assert result.service == "unidentified service"


def test_unknown_service_resolving_is_none():
    resolver = _Resolver(dangling=set())
    assert takeover.check_takeover("mystery.somecloud.io", resolver) is None


def test_empty_cname_is_none():
    assert takeover.check_takeover("", _Resolver(dangling=set())) is None


@pytest.mark.parametrize(
    ("target", "service"),
    [
        ("x.s3.amazonaws.com", "Amazon S3"),
        ("x.s3.us-west-2.amazonaws.com", "Amazon S3"),
        ("x.elasticbeanstalk.com", "AWS Elastic Beanstalk"),
        ("x.azurewebsites.net", "Azure App Service"),
        ("x.github.io", "GitHub Pages"),
        ("x.netlify.app", "Netlify"),
        ("x.herokudns.com", "Heroku"),
        ("x.ghost.io", "Ghost"),
        ("x.tumblr.com", "Tumblr"),
        ("x.wordpress.com", "WordPress.com"),
        ("x.myshopify.com", "Shopify"),
        ("x.fastly.net", "Fastly"),
        ("x.pantheonsite.io", "Pantheon"),
        ("x.readme.io", "ReadMe.io"),
        ("x.surge.sh", "Surge.sh"),
        ("x.bitbucket.io", "Bitbucket"),
        ("x.zendesk.com", "Zendesk"),
        ("x.sendgrid.net", "SendGrid"),
        ("x.freshdesk.com", "Freshdesk"),
        ("x.unbouncepages.com", "Unbounce"),
    ],
)
def test_signature_match_table(target, service):
    resolver = _Resolver(dangling={target})
    result = takeover.check_takeover(target, resolver)
    assert result is not None
    assert result.service == service


def test_case_insensitive_matching():
    resolver = _Resolver(dangling={"MYAPP.S3.AMAZONAWS.COM".lower()})
    result = takeover.check_takeover("MyApp.S3.AmazonAWS.COM", resolver)
    assert result is not None
    assert result.service == "Amazon S3"