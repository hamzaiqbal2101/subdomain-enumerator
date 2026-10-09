# Subdomain Enumerator

[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![CI](https://github.com/hamzaiqbal2101/subdomain-enumerator/actions/workflows/ci.yml/badge.svg)](https://github.com/hamzaiqbal2101/subdomain-enumerator/actions/workflows/ci.yml)
[![Tests](https://img.shields.io/badge/tests-132%20passing-brightgreen)](#development)

> ## AUTHORIZED USE ONLY
>
> This tool performs DNS reconnaissance. Use it **ONLY against domains you
> own** or **have explicit written permission to test** — for example:
>
> - Your own domains and infrastructure
> - Bug bounty programs (where the target is in scope)
> - Lab/CTF environments you are authorized to attack
>
> Unauthorized scanning may violate the target's terms of service and
> applicable law. For any real domain you do not control, run with
> **`--passive-only`**, which queries public OSINT sources and sends **no
> traffic to the target at all**.

A professional-grade subdomain enumeration tool written in Python. It discovers
the subdomains of a domain by combining **wordlist brute-forcing** with
**certificate-transparency OSINT** (crt.sh), filters out wildcard false
positives, and flags CNAME targets that are vulnerable to **subdomain
takeover**.

This is the fourth project in a cybersecurity portfolio:

1. [Password Strength Checker](https://github.com/hamzaiqbal2101/password-strength-checker)
2. [File Integrity Checker](https://github.com/hamzaiqbal2101/file-integrity-checker)
3. [File Encryptor](https://github.com/hamzaiqbal2101/file-encryptor)
4. **Subdomain Enumerator** (this project)
5. [Port Scanner](https://github.com/hamzaiqbal2101/portscanner)

---

## Responsible use

- **Recommended default for real domains: `--passive-only`.** Passive
  enumeration (crt.sh) sends zero traffic to the target's servers — it only
  queries public certificate-transparency logs. Use active wordlist
  brute-forcing **only** against your own infrastructure or explicitly
  authorized lab/bug-bounty environments.
- **Conservative by default.** The default concurrency is 20 threads
  (`--threads`, capped at 1000) and each DNS query has a 5-second timeout with
  up to 2 retries. Raise these limits only when you control the target's DNS
  and its operators expect testing traffic.
- **Discovery only — no exploitation.** This tool's scope is **enumeration and
  discovery**. It detects *potential* CNAME takeover candidates with passive
  DNS checks and explicitly does **not** automate any exploitation, takeover,
  or claim functionality. Takeover findings require manual, authorized HTTP
  verification before any action is taken.
- The same notice is printed by the CLI on every run (suppressed with
  `--quiet`).

## Features

- **Two discovery methods**
  - *Brute-force*: a bundled 499-label wordlist of common hostnames (`www`,
    `mail`, `api`, `dev`, ...) is combined with the root domain and resolved
    concurrently. The repo also ships a compact ~216-entry starter list in
    [`wordlists/common_subdomains.txt`](wordlists/common_subdomains.txt);
    supply any wordlist with `-w`.
  - *Certificate transparency*: queries [crt.sh](https://crt.sh) for every
    certificate ever issued for the domain and extracts the hostnames from
    them — this finds subdomains that no longer resolve or that brute-forcing
    would never guess.
- **Wildcard detection and filtering**: before enumerating, the tool probes the
  domain with random labels to detect a catch-all `*.domain` record. Hostnames
  whose answers are a subset of the wildcard's IPs are treated as wildcard
  echoes and filtered out of the results (use `--include-wildcards` to keep
  them).
- **Subdomain takeover analysis**: every resolved alias (CNAME) is checked
  against 21 known takeover-prone services (S3, Elastic Beanstalk, GitHub
  Pages, Azure App Service, Netlify, Heroku, and more). A CNAME whose target is
  now NXDOMAIN is flagged as a takeover candidate with a confidence score.
- **Concurrent resolution**: DNS queries run in a bounded thread pool
  (default 20 workers, conservative for the target's DNS) so even large
  wordlists complete quickly.
- **Graceful degradation**: if an OSINT source or individual queries fail, the
  run continues and the failures are recorded in the summary — a broken source
  never aborts the enumeration.
- **CI-ready output and exit codes**: `table`, `json`, `csv`, and `list`
  formats, file output with `-o`, and machine-checkable exit codes.
- **Offline-testable architecture**: the DNS wrapper and the crt.sh fetcher are
  injectable, so the 132-test suite runs without any network access.

## Installation

Requires Python 3.10+.

```bash
pip install -r requirements.txt
```

To install the console script:

```bash
pip install .
```

## Usage

The tool supports three modes. The default **combined** mode runs passive
discovery and active brute-force together; `--passive-only` and
`--active-only` select a single method (recommended to use `--passive-only`
for domains you do not control).

```bash
# COMBINED (default): passive crt.sh + active wordlist brute-force
subdomain-enumerator example.com

# Same target, given via the --domain flag
subdomain-enumerator --domain example.com

# PASSIVE ONLY: crt.sh OSINT, no traffic sent to the target
subdomain-enumerator example.com --passive-only

# ACTIVE ONLY: wordlist brute-force exclusively, no OSINT sources
subdomain-enumerator example.com --active-only

# Quiet mode: no authorization banner or progress bar
subdomain-enumerator -q example.com

# Write JSON results to a file
subdomain-enumerator example.com -f json -o results.json

# Passive-only: OSINT sources only, no active brute-force
subdomain-enumerator example.com --passive-only

# Active-only: wordlist brute-force exclusively, no OSINT sources
subdomain-enumerator example.com --active-only

# Skip the wordlist pass (crt.sh only)
subdomain-enumerator example.com --no-bruteforce

# Skip the crt.sh pass (brute-force only, fully offline DNS)
subdomain-enumerator example.com --no-crt

# Use a custom wordlist (the repo ships a starter list in wordlists/)
subdomain-enumerator example.com -w wordlists/common_subdomains.txt

# Include hostnames that no longer resolve (found via crt.sh)
subdomain-enumerator example.com --include-unresolved

# Keep records that match the domain's wildcard (false positives by default)
subdomain-enumerator example.com --include-wildcards

# Skip takeover analysis
subdomain-enumerator example.com --no-takeover

# Use specific recursive resolvers (comma-separated)
subdomain-enumerator example.com --resolver 1.1.1.1,8.8.8.8

# Tune concurrency and timeouts
subdomain-enumerator example.com --threads 100 --timeout 10 --retries 3
```

You can also run it as a module:

```bash
python -m subdomain_enumerator example.com
```

### Live output and summary

While a run is in progress the tool prints each verified hostname to **stderr**
as it is found (stdout stays clean for the final result):

```
[+] www.example.com 1.2.3.4 -> cdn.example.net
Resolved 87/499 candidate(s)
```

At the end a summary is printed, including the total candidates tested, the
counts found, and the wall-clock time elapsed:

```
Tested: 499 candidate(s)
Found: 3 resolved, 1 unresolved
Filtered: 0 wildcard echo(es), 1 DNS error(s)
Elapsed: 6.21s
Takeover candidates: 0
```

### Example output

A combined run against `example.com` prints the results table to stdout, live
discoveries and the summary to stderr:

```
$ subdomain-enumerator example.com
[+] www.example.com 104.20.23.154, 172.66.147.243
[+] api.example.com 93.184.216.34 -> api.example.net

Hostname                  IPs                                              CNAME          Source    Takeover
--------------------------------------------------------------------------------------------------------------
www.example.com           104.20.23.154, 172.66.147.243                   -              wordlist  -
api.example.com           93.184.216.34                                   api.example.net wordlist  LOW (unidentified service)

Tested: 499 candidate(s)
Found: 2 resolved, 0 unresolved
Filtered: 0 wildcard echo(es), 0 DNS error(s)
Elapsed: 6.21s
Takeover candidates: 1
```

With `-f json` the same results export as machine-readable records (hostname,
record type, resolved IPs, sources, takeover details):

```
[
  {
    "hostname": "api.example.com",
    "record_type": "CNAME",
    "ipv4": ["93.184.216.34"],
    "cname": "api.example.net",
    "sources": ["wordlist"],
    "resolved": true,
    "wildcard": false
  }
]
```

### Output formats

`table` (default):

```
Hostname                  IPs   CNAME       Source    Takeover
--------------------------------------------------------------------
www.example.com           1.2.3.4         wordlist  -
```

`json`, `csv`, and `list` (one hostname per line) are available via
`-f`/`--format`.

### Exit codes

| Code | Meaning                                                              |
|------|----------------------------------------------------------------------|
| 0    | Success (results found or not)                                       |
| 1    | Fatal DNS failure (the resolver could not be initialized)            |
| 2    | Command-line usage error                                             |
| 3    | Operational failure (invalid domain, missing wordlist, ...)          |

## How it works

The enumeration pipeline in `enumerator.py` is:

1. **Wildcard probe** — random labels are queried against the domain; any
   answer means `*.domain` exists and its IPs become the wildcard signature.
2. **OSINT pass** — crt.sh is queried for the domain's certificate history;
   unique hostnames are extracted.
3. **Brute-force pass** — each wordlist label is turned into
   `<label>.domain` (labels that collide with the root domain itself are
   skipped to avoid scanning the zone apex).
4. **Deduplication** — hostnames from both sources are merged; a name keeps a
   record of where it was discovered.
5. **Concurrent resolution** — every unique candidate is resolved (raw CNAME,
   then A and AAAA) in a bounded thread pool; per-query timeouts are retried.
6. **Wildcard filtering** — any resolved record whose IP set is a subset of
   the wildcard's IPs is treated as a wildcard echo and dropped.
7. **Takeover analysis** — each surviving alias's CNAME target is matched
   against the takeover signature table and tested for NXDOMAIN.
8. **Output** — remaining records are sorted and rendered in the requested
   format, with a summary of candidates, resolved, filtered, and failed.

### DNS resolution

`resolver.py` wraps `dnspython` rather than `socket.getaddrinfo` because the
latter cannot give us the raw CNAME record. Each hostname is queried with a
raw CNAME lookup (not followed), then A and AAAA lookups (which DO follow
chains). Retryable failures (timeout, no usable nameserver) are retried
`--retries` times before the query is recorded as failed. Names are treated as
*existing* if they return NXDOMAIN on the A query but have a CNAME — that is
exactly the dangling-alias signature takeover detection needs.

### Wildcard filtering

A `*.example.com` catch-all makes every name under the domain resolve to the
same IPs. Without detection, `subdomain-enumerator example.com` would report
hundreds of fake "live" hosts. The tool probes with random labels and builds
the set of wildcard IPs; a candidate whose entire answer set is contained in
that set is a wildcard echo and is filtered out.

### Subdomain takeover scoring

`takeover.py` recognizes 21 takeover-prone services by regex over the CNAME
target. Each candidate is scored:

- **high** — the target belongs to a known service AND is NXDOMAIN (its
  provisioning has lapsed; the classic takeover signature).
- **medium** — the target is NXDOMAIN but does not match a known service;
  worth investigating manually.
- **low** — the target belongs to a known service but still resolves; listed
  for completeness, **not** a vulnerability.

> A passive DNS check cannot *confirm* a takeover. The definitive test is an
> HTTP-level probe (e.g. an S3 bucket answering `NoSuchBucket`) or the
> service's own API. Treat high-confidence findings as candidates for manual
> verification, not as confirmed vulnerabilities.

## Design decisions

**Why dnspython instead of `socket`/`dns.resolver` from scratch?**
`dnspython` is the standard, actively maintained DNS library for Python. The
tool deliberately avoids re-implementing DNS. The `socket.getaddrinfo`
interface hides CNAME records, which are essential for takeover detection;
dnspython's `resolve(hostname, "CNAME")` returns them directly.

**Why crt.sh?**
crt.sh is a free certificate-transparency log index and requires no API key.
It frequently reveals subdomains that brute-forcing misses (long hashes,
internal names, decommissioned hosts). It is a *passive* source — nothing is
sent to the target's servers.

**Why concurrent resolution?**
DNS queries are latency-bound (tens of milliseconds each). With 20 workers by
default the tool resolves hundreds of candidates in seconds instead of minutes. The pool
is bounded to avoid exhausting file descriptors and to be polite to
resolvers.

**Why filter wildcards instead of reporting them?**
Wildcard echoes are false positives that make results noisy and statistically
meaningless. Filtering them produces a list of *distinct real hosts*, which is
what an engineer or analyst actually wants. `--include-wildcards` restores the
raw view when needed.

**Why a confidence score for takeovers?**
Passive DNS checks are heuristic. Scoring separates "almost certainly
dangling" from "maybe" from "actively in use", so a security reviewer can
prioritise verification effort. Every high-confidence finding still needs an
HTTP-level confirmation.

## Limitations

- **Passive-only detection.** No HTTP fingerprinting is performed. Takeover
  findings are candidates; confirming one requires an HTTP probe or the
  service's API (documented in the README of each finding's service).
- **crt.sh dependency.** The certificate-transparency pass depends on the
  public crt.sh service. When it is down or rate-limiting, the tool records a
  source warning and continues with the brute-force pass — results are then
  limited to wordlist discovery.
- **Wordlist quality.** Brute-forcing is only as good as the wordlist. The
  bundled 499 labels cover common hostnames; deep enumeration of a large
  organisation needs a larger, organisation-specific wordlist.
- **No recursive/hierarchical enumeration.** Only `<label>.<domain>` is
  generated, not `a.b.<domain>` (e.g. `api.north.example.com` is not guessed).
  crt.sh will often find such names anyway.
- **DNS heuristics.** Wildcard detection and NXDOMAIN-based takeover scoring
  are heuristics; unusual DNS setups (split-horizon DNS, per-label wildcards,
  DNS-based load balancing with rotating IPs) can produce false positives.
- **Legal/ethical scope.** This tool is a security-audit utility. Use it only
  against domains you own or are authorized to test.

## Development

```bash
# Install dev dependencies
pip install -r requirements.txt

# Run the test suite (offline)
python -m pytest -q

# Lint for unused imports and other static issues
python -m pyflakes subdomain_enumerator tests
```

The test suite (132 tests) is fully offline:

- Domain validation and wordlist loading
- The DNS wrapper: CNAME/A/AAAA resolution, NXDOMAIN and NoAnswer handling,
  dangling CNAMEs, retry/timeout behaviour, wildcard detection
- crt.sh JSON parsing (including broken responses)
- Takeover scoring against the signature table
- The enumeration pipeline: merging sources, wildcard filtering, stats
- Output formatters (table/json/csv/list)
- The CLI: exit codes, argument validation, quiet mode, output files

The tests replace the real DNS resolver and the crt.sh HTTP fetcher with
in-memory fakes, so `python -m pytest -q` runs anywhere with no network access.

## License

[MIT](LICENSE) © 2026 Hamza Iqbal