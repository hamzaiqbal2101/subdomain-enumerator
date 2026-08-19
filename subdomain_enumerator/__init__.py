"""Subdomain enumeration: wordlist brute-force, CT-log OSINT, takeover checks."""

__version__ = "1.0.0"

from .enumerator import Enumerator, EnumerationStats
from .model import Subdomain, TakeoverResult
from .resolver import DnsQueryError, Resolution, Resolver
from .validation import ValidationError

__all__ = [
    "DnsQueryError",
    "EnumerationStats",
    "Enumerator",
    "Resolution",
    "Resolver",
    "Subdomain",
    "TakeoverResult",
    "ValidationError",
    "__version__",
]