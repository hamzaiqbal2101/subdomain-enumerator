"""Enumeration engine: orchestrates sources, resolution, and analysis.

The engine's job is to turn candidate hostnames (from the wordlist and the
OSINT sources) into a clean, deduplicated, analysed set of :class:`Subdomain`
records. The pipeline is:

1. **Wildcard detection** -- probe the root domain with random labels. If a
   wildcard exists, remember its IP signature so false positives can be
   dropped later.
2. **Candidate collection** -- brute-force candidates and OSINT-discovered
   names, deduplicated.
3. **Concurrent resolution** -- resolve all candidates with a bounded thread
   pool.
4. **Wildcard filtering** -- drop records whose IP set matches the wildcard
   signature (unless the caller asked to keep them).
5. **Takeover analysis** -- for every resolved alias, score the CNAME target.
6. **Sorting** -- deterministic output ordering for reproducible reports.

Every network failure inside a worker is captured in the run statistics
rather than killing the whole run; the caller decides how to surface them.
"""

from __future__ import annotations

import threading
from collections.abc import Callable, Iterable
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field

from .model import Subdomain
from .resolver import DnsQueryError, Resolver, WildcardInfo
from .sources import SourceError, fetch_certificate_transparency
from .takeover import check_takeover

ProgressCallback = Callable[[int, int], None]
ResultCallback = Callable[["Subdomain"], None]


@dataclass
class EnumerationStats:
    """Counters describing how a run went.

    Attributes:
        candidates: Number of unique hostnames submitted for resolution.
        resolved: Number of unique hostnames with DNS records.
        unresolved: Number of unique hostnames with no records.
        wildcard_filtered: Records dropped because they matched the wildcard.
        dns_errors: Individual queries that failed (timeout/SERVFAIL).
        source_errors: Messages from OSINT sources that failed.
        takeover_candidates: Alias records flagged for takeover review.
    """

    candidates: int = 0
    resolved: int = 0
    unresolved: int = 0
    wildcard_filtered: int = 0
    dns_errors: int = 0
    source_errors: list[str] = field(default_factory=list)
    takeover_candidates: int = 0


def matches_wildcard(record: Subdomain, wildcard: WildcardInfo) -> bool:
    """True if ``record`` looks like a wildcard false positive.

    A host that resolves to (a subset of) the exact IPs the wildcard answers
    with is almost certainly a wildcard echo rather than a real host.
    """
    if not wildcard.active or not record.ip_addresses:
        return False
    return set(record.ip_addresses) <= wildcard.ips


class Enumerator:
    """Runs the full enumeration pipeline against one root domain."""

    def __init__(
        self,
        domain: str,
        resolver: Resolver,
        threads: int = 20,
        include_unresolved: bool = False,
        include_wildcards: bool = False,
        check_takeover: bool = True,
        use_cert_transparency: bool = True,
        progress: ProgressCallback | None = None,
        result_callback: ResultCallback | None = None,
    ) -> None:
        """Configure an enumeration run.

        Args:
            domain: The normalized root domain.
            resolver: The DNS resolver to query (see :mod:`.resolver`).
            threads: Maximum concurrent DNS workers.
            include_unresolved: Keep hostnames with no DNS records.
            include_wildcards: Keep records matching the domain's wildcard.
            check_takeover: Run CNAME takeover analysis on resolved aliases.
            use_cert_transparency: Query crt.sh for passive discovery.
            progress: Optional callback ``(done, total)`` for progress; a
                ``(-1, -1)`` call signals that a wildcard was detected.
            result_callback: Optional callback invoked with each kept
                :class:`Subdomain` as it is verified (for live output).
        """
        self._domain = domain
        self._resolver = resolver
        self._threads = max(1, threads)
        self._include_unresolved = include_unresolved
        self._include_wildcards = include_wildcards
        self._check_takeover = check_takeover
        self._use_ct = use_cert_transparency
        self._progress = progress
        self._result_callback = result_callback
        self._stats = EnumerationStats()
        self._lock = threading.Lock()

    @property
    def stats(self) -> EnumerationStats:
        """The :class:`EnumerationStats` accumulated so far this run."""
        return self._stats

    def _resolve_one(self, hostname: str) -> Subdomain | None:
        """Resolve a single hostname into a Subdomain (or None on DNS error)."""
        try:
            resolution = self._resolver.resolve(hostname)
        except DnsQueryError:
            with self._lock:
                self._stats.dns_errors += 1
            return None

        return Subdomain(
            name=hostname,
            ipv4=resolution.ipv4,
            ipv6=resolution.ipv6,
            cname=resolution.cname,
            resolved=resolution.exists,
        )

    def _analyze_alias(self, record: Subdomain) -> None:
        """Perform takeover analysis on a resolved alias hostname."""
        if not self._check_takeover or not record.cname:
            return
        try:
            result = check_takeover(record.cname, self._resolver)
        except DnsQueryError:
            return
        if result is not None:
            record.takeover = result
            with self._lock:
                self._stats.takeover_candidates += 1

    def _resolve_many(
        self, hostnames: Iterable[str], progress_total: int
    ) -> list[Subdomain]:
        """Resolve many hostnames concurrently with a bounded thread pool.

        Returns records in deterministic (sorted-by-name) order so merging is
        stable regardless of thread scheduling.
        """
        hostname_list = list(hostnames)
        found: dict[str, Subdomain] = {}
        done = 0

        def report() -> None:
            """Emit the current completion count via the progress callback."""
            if self._progress is not None:
                self._progress(done, progress_total)

        with ThreadPoolExecutor(max_workers=self._threads) as executor:
            future_map: dict[Future[str], str] = {
                executor.submit(self._resolve_one, name): name
                for name in hostname_list
            }
            for future in as_completed(future_map):
                hostname = future_map[future]
                record = future.result()
                if record is not None:
                    if hostname in found:
                        found[hostname].merge(record)
                    else:
                        found[hostname] = record
                done += 1
                report()

        return sorted(found.values(), key=lambda r: r.name)

    def run(
        self,
        wordlist_entries: list[str],
    ) -> list[Subdomain]:
        """Execute the full enumeration pipeline.

        Args:
            wordlist_entries: Validated wordlist labels to brute-force.

        Returns:
            Sorted list of :class:`Subdomain` records after wildcard filtering
            and (optionally) unresolved-host filtering.
        """
        from .bruteforce import bruteforce_candidates

        wildcard = self._resolver.detect_wildcard(self._domain)
        if wildcard.active and self._progress is not None:
            self._progress(-1, -1)  # -1 signals "wildcard detected"

        # OSINT source first (passive, cheap, may reveal non-resolving hosts).
        ct_names: list[str] = []
        if self._use_ct:
            try:
                ct_names = fetch_certificate_transparency(self._domain)
            except SourceError as exc:
                self._stats.source_errors.append(str(exc))

        # Brute-force candidates.
        brute_names = list(bruteforce_candidates(self._domain, wordlist_entries))
        all_names: dict[str, None] = {name: None for name in brute_names}
        all_sources: dict[str, set[str]] = {
            name: {"wordlist"} for name in brute_names
        }
        for name in ct_names:
            all_names.setdefault(name, None)
            all_sources.setdefault(name, set()).add("crt.sh")
        self._stats.candidates = len(all_names)

        # Concurrent resolution pass over every unique candidate.
        records = self._resolve_many(all_names, self._stats.candidates)
        for record in records:
            record.sources = all_sources.get(record.name, set())

        # Wildcard filtering, takeover analysis, unresolved filter, sort.
        results: list[Subdomain] = []
        for record in records:
            if record.resolved and matches_wildcard(record, wildcard):
                record.wildcard = True
                if not self._include_wildcards:
                    self._stats.wildcard_filtered += 1
                    continue
            if record.resolved:
                self._analyze_alias(record)
                self._stats.resolved += 1
            elif self._include_unresolved:
                self._stats.unresolved += 1
            else:
                continue
            results.append(record)
            if self._result_callback is not None:
                self._result_callback(record)

        results.sort(key=lambda s: s.name)
        return results