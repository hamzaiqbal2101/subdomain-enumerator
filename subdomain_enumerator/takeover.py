"""Subdomain takeover detection.

A subdomain takeover is possible when a hostname's CNAME points at a
third-party service (S3 bucket, GitHub Pages site, Azure app, ...) whose
provisioning has lapsed. The canonical passive signature is:

1. the CNAME target belongs to a known takeover-prone service, AND
2. the CNAME target is now NXDOMAIN (the service stopped answering for it).

When both hold, anyone who re-registers that target can serve content from the
victim's subdomain. This module scores candidates:

- ``high``   -- known service AND target is NXDOMAIN (strongest passive signal)
- ``medium`` -- unknown service but the CNAME target is NXDOMAIN
- ``low``    -- known service, but the target still resolves (active service;
                listed for completeness, NOT a vulnerability)

Passive DNS checks cannot definitively confirm a takeover -- the final word
belongs to an HTTP-level probe or the service's own API (e.g. does an S3
bucket return ``NoSuchBucket``). The README documents this clearly.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import TYPE_CHECKING

from .model import TakeoverResult

if TYPE_CHECKING:  # pragma: no cover - import cycle avoidance
    from .resolver import Resolver


@dataclass(frozen=True)
class TakeoverSignature:
    """A known CNAME takeover-prone service and how to recognise it.

    Attributes:
        service: Display name of the cloud service.
        pattern: Regex matched against the lowercase CNAME target.
        detail: One-line description of what the CNAME should point at.
    """

    service: str
    pattern: re.Pattern[str]
    detail: str

    def matches(self, cname_target: str) -> bool:
        """True if the (lowercased) CNAME target belongs to this service."""
        return self.pattern.search(cname_target.lower()) is not None


SIGNATURES: tuple[TakeoverSignature, ...] = (
    TakeoverSignature(
        "Amazon S3",
        re.compile(r"\.s3(?:[.-][a-z0-9-]+)?\.amazonaws\.com"),
        "points at an S3 bucket (bucket must exist for the name to resolve)",
    ),
    TakeoverSignature(
        "AWS Elastic Beanstalk",
        re.compile(r"\.elasticbeanstalk\.com"),
        "points at an Elastic Beanstalk environment",
    ),
    TakeoverSignature(
        "Azure App Service",
        re.compile(r"\.azurewebsites\.net"),
        "points at an Azure App Service",
    ),
    TakeoverSignature(
        "Azure Cloud Services",
        re.compile(r"\.cloudapp\.net"),
        "points at an Azure cloud service",
    ),
    TakeoverSignature(
        "Azure Traffic Manager",
        re.compile(r"\.trafficmanager\.net"),
        "points at an Azure Traffic Manager profile",
    ),
    TakeoverSignature(
        "GitHub Pages",
        re.compile(r"\.github\.io"),
        "points at a GitHub Pages site (repo must be configured to answer)",
    ),
    TakeoverSignature(
        "Netlify",
        re.compile(r"\.netlify\.app|\.netlify\.com"),
        "points at a Netlify site",
    ),
    TakeoverSignature(
        "Heroku",
        re.compile(r"\.herokudns\.com|\.herokuapp\.com"),
        "points at a Heroku dyno",
    ),
    TakeoverSignature(
        "Ghost",
        re.compile(r"\.ghost\.io"),
        "points at a Ghost blog",
    ),
    TakeoverSignature(
        "Tumblr",
        re.compile(r"\.tumblr\.com"),
        "points at a Tumblr blog",
    ),
    TakeoverSignature(
        "WordPress.com",
        re.compile(r"\.wordpress\.com"),
        "points at a WordPress.com site",
    ),
    TakeoverSignature(
        "Shopify",
        re.compile(r"\.shopify\.com|\.myshopify\.com"),
        "points at a Shopify storefront",
    ),
    TakeoverSignature(
        "Fastly",
        re.compile(r"\.fastly\.net|\.fastlylb\.net|\.fastlylabs\.com"),
        "points at a Fastly service",
    ),
    TakeoverSignature(
        "Pantheon",
        re.compile(r"\.pantheonsite\.io"),
        "points at a Pantheon site",
    ),
    TakeoverSignature(
        "ReadMe.io",
        re.compile(r"\.readme\.io"),
        "points at a ReadMe.io docs site",
    ),
    TakeoverSignature(
        "Surge.sh",
        re.compile(r"\.surge\.sh"),
        "points at a Surge.sh static site",
    ),
    TakeoverSignature(
        "Bitbucket",
        re.compile(r"\.bitbucket\.io"),
        "points at a Bitbucket Pages site",
    ),
    TakeoverSignature(
        "Zendesk",
        re.compile(r"\.zendesk\.com"),
        "points at a Zendesk help center",
    ),
    TakeoverSignature(
        "SendGrid",
        re.compile(r"\.sendgrid\.net"),
        "points at a SendGrid account",
    ),
    TakeoverSignature(
        "Freshdesk",
        re.compile(r"\.freshdesk\.com"),
        "points at a Freshdesk support portal",
    ),
    TakeoverSignature(
        "Unbounce",
        re.compile(r"\.unbouncepages\.com"),
        "points at an Unbounce landing page",
    ),
)


def check_takeover(
    cname_target: str,
    resolver: "Resolver",
) -> TakeoverResult | None:
    """Assess a CNAME target for takeover potential.

    Args:
        cname_target: The lowercased CNAME target of the subdomain (no
            trailing dot).
        resolver: Resolver used to test whether the target is dangling.

    Returns:
        A :class:`TakeoverResult` when the target matches a known service or
        is dangling, otherwise None.
    """
    if not cname_target:
        return None

    signature = next(
        (sig for sig in SIGNATURES if sig.matches(cname_target)), None
    )
    dangling = resolver.is_dangling(cname_target)

    if signature is not None:
        if dangling:
            return TakeoverResult(
                service=signature.service,
                cname_target=cname_target,
                confidence="high",
                detail=(
                    f"{signature.detail}; target is NXDOMAIN, so the "
                    "provisioning has lapsed and the name may be re-registered"
                ),
            )
        return TakeoverResult(
            service=signature.service,
            cname_target=cname_target,
            confidence="low",
            detail=(
                f"{signature.detail}; target still resolves (active service) "
                "-- listed for completeness, not a confirmed finding"
            ),
        )

    if dangling:
        return TakeoverResult(
            service="unidentified service",
            cname_target=cname_target,
            confidence="medium",
            detail=(
                "CNAME target is NXDOMAIN but does not match a known service; "
                "investigate the apex domain manually"
            ),
        )
    return None