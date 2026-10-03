#!/usr/bin/env python3
"""Deterministic verification of external citations in Frontier YAML artifacts.

This tool exists because two findings reached ``verified_conclusion`` with fatal
defects that every structural gate in this repo passed:

* ``fnd-2026-0014`` quoted RFC 9052 section 9 with text that does not exist in
  RFC 9052. The map-key-sorting sentence was RFC 8949 section 4.2.1 text
  spliced into an RFC 9052 quotation.
* ``fnd-2026-0009`` claimed OpenSSH's sshd omits the FIPS 203 section 7.2 check
  citing ``file:line`` one layer above the function that actually performs it.

The common cause was that nobody re-fetched the cited sources before promoting or
disclosing the claim.

The tool extracts external citations and checks what is checkable
deterministically.  Tier 1 needs no network.  Tier 2 (HTTP reachability and
quote spot-checks) runs only under ``--online``.

Hard rules honoured by this implementation:

* Read-only.  This tool never writes to ``knowledge/``, ``missions/`` or
  ``src/``.  The only file it can write is the report passed to ``--report``.
* Never fabricate.  Anything that cannot be checked deterministically is
  reported ``UNVERIFIABLE`` and is never reported as FAIL or PASS.
* Exit codes: ``0`` no tier-1 findings, ``1`` tier-1 findings present, ``2``
  tool error.  A network outage alone never produces a non-zero exit.
* No credentials, no authentication, no non-public URLs.  Every Tier 2 request
  is anonymous and goes to a public host.

Usage::

    .venv\\Scripts\\python.exe tools\\verify_citations.py [--finding ID | --all]
                                        [--online] [--json] [--report PATH]
                                        [--stale-days N] [--selftest]
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
import tempfile
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Iterator, Sequence
from urllib.parse import urlsplit

import yaml

TOOL_NAME = "verify_citations"
TOOL_VERSION = "1.0.0"

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2

# --------------------------------------------------------------------------
# Status vocabularies
# --------------------------------------------------------------------------

# A citation that points at a withdrawn artifact is a real defect: the
# withdrawal is the evidence, and downstream reasoning built on it must be
# re-read.  "disputed" is included because fnd-2026-0010 carries status
# ``disputed`` while fnd-2026-0009 was rejected; a finding depending on a
# disputed/rejected sibling must be revisited before it is disclosed.
WITHDRAWN_STATUSES = frozenset({"rejected", "superseded", "archived", "disputed"})

# Statuses that assert a conclusion has been established.  A correction block
# contradicting that assertion is a contradiction worth surfacing.
ASSERTIVE_STATUSES = frozenset(
    {
        "verified",
        "verified_conclusion",
        "pass",
        "supported",
        "support",
        "reproduced",
        "complete",
        "final",
        "proved",
    }
)

DISCLOSED = frozenset({"public"})

# --------------------------------------------------------------------------
# Tier 1 check identifiers
# --------------------------------------------------------------------------

T1_URL_SCHEME = "url_scheme"
T1_URL_MALFORMED = "url_malformed"
T1_URL_HOST = "url_host"
T1_URL_NONCANONICAL = "url_noncanonical"
T1_SHA_SHAPE = "sha_shape"
T1_DANGLING_LINK = "link_dangling"
T1_WITHDRAWN_LINK = "link_withdrawn"
T1_CORRECTION_UNMARKED = "correction_unmarked"
T1_CORRECTION_CONTRADICTION = "correction_contradiction"
T1_STALENESS = "staleness"

TIER2_REACHABILITY = "url_reachability"
TIER2_QUOTE = "quote_spotcheck"

SEVERITY_ORDER = {"FAIL": 0, "WARN": 1, "REVIEW": 2, "UNVERIFIABLE": 3}


# --------------------------------------------------------------------------
# Result model
# --------------------------------------------------------------------------


@dataclass
class Finding:
    """One deterministic observation about one artifact."""

    check: str
    severity: str  # FAIL | WARN | REVIEW | UNVERIFIABLE
    tier: int
    artifact_id: str
    path: str
    detail: str
    evidence: str = ""
    observed: str | None = None  # populated by tier-2 network checks
    manual_review_required: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "check": self.check,
            "severity": self.severity,
            "tier": self.tier,
            "artifact": self.artifact_id,
            "path": self.path,
            "detail": self.detail,
            "evidence": self.evidence,
            "observed": self.observed,
            "manual_review_required": self.manual_review_required,
        }


# --------------------------------------------------------------------------
# YAML loading
# --------------------------------------------------------------------------


@dataclass
class Artifact:
    path: Path
    rel: str
    doc: dict[str, Any]
    load_error: str | None = None

    @property
    def id(self) -> str:
        value = self.doc.get("id")
        return str(value) if isinstance(value, str) and value else f"<no-id:{self.rel}>"

    @property
    def status(self) -> str | None:
        value = self.doc.get("status")
        return str(value) if isinstance(value, str) else None

    @property
    def disclosure(self) -> str | None:
        value = self.doc.get("disclosure")
        return str(value) if isinstance(value, str) else None

    @property
    def raw_text(self) -> str:
        try:
            return self.path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return ""


def _knowledge_dirs(root: Path) -> list[Path]:
    knowledge = root / "knowledge"
    if not knowledge.is_dir():
        return []
    # ``indices`` and ``notes`` are discovery aids, not evidence artifacts;
    # ``frontier.validate`` already skips them for the same reason.
    return [
        child
        for child in sorted(knowledge.iterdir())
        if child.is_dir() and child.name not in {"indices", "notes"}
    ]


def load_artifacts(root: Path, include_missions: bool) -> tuple[list[Artifact], list[Artifact]]:
    """Load every YAML evidence artifact.

    Returns ``(artifacts, broken)``.  ``broken`` holds files that could not be
    parsed; they are still checked for URL shape so a malformed file is never
    silently skipped.
    """
    folders = _knowledge_dirs(root)
    if include_missions:
        missions = root / "missions"
        if missions.is_dir():
            folders.extend(
                child for child in sorted(missions.iterdir()) if child.is_dir()
            )
            if (missions / "msn-2026-0020.md").exists():
                pass  # markdown missions are out of scope for YAML citation checks

    artifacts: list[Artifact] = []
    broken: list[Artifact] = []
    for folder in folders:
        for path in sorted(folder.rglob("*.yaml")):
            rel = str(path.relative_to(root)).replace("\\", "/")
            try:
                doc = yaml.safe_load(path.read_text(encoding="utf-8"))
            except Exception as exc:  # malformed YAML is a finding, not a crash
                broken.append(Artifact(path=path, rel=rel, doc={}, load_error=str(exc)))
                continue
            if not isinstance(doc, dict):
                broken.append(
                    Artifact(
                        path=path,
                        rel=rel,
                        doc={},
                        load_error=f"document root is {type(doc).__name__}, not a mapping",
                    )
                )
                continue
            artifacts.append(Artifact(path=path, rel=rel, doc=doc))
    return artifacts, broken


# --------------------------------------------------------------------------
# Structured-string walking
# --------------------------------------------------------------------------


def walk_strings(node: Any) -> Iterator[tuple[list[str], str]]:
    """Yield ``(path_in_doc, value)`` for every string inside a parsed YAML doc."""
    if isinstance(node, dict):
        for key, value in node.items():
            key_text = str(key)
            if isinstance(value, str):
                yield [key_text], value
            else:
                for sub_path, text in walk_strings(value):
                    yield [key_text, *sub_path], text
    elif isinstance(node, list):
        for index, value in enumerate(node):
            if isinstance(value, str):
                yield [str(index)], value
            else:
                for sub_path, text in walk_strings(value):
                    yield [str(index), *sub_path], text


# --------------------------------------------------------------------------
# Tier 1: URL shape
# --------------------------------------------------------------------------

URL_RE = re.compile(r"https?://[^\s\[\]\"'<>)\]}]+")

# Hosts whose URLs should always be written https.  A http citation is a
# transport downgrade and a tamper target for exactly the quotations this tool
# exists to protect.
KNOWN_HTTP_HOSTS = frozenset(
    {
        "github.com",
        "www.github.com",
        "raw.githubusercontent.com",
        "www.rfc-editor.org",
        "rfc-editor.org",
        "datatracker.ietf.org",
        "www.ietf.org",
        "ietf.org",
        "csrc.nist.gov",
        "nvlpubs.nist.gov",
        "pages.nist.gov",
        "doi.org",
        "dx.doi.org",
        "arxiv.org",
        "eprint.iacr.org",
        "ia.cr",
        "www.w3.org",
        "open-std.org",
        "www.open-std.org",
        "docs.rs",
        "crates.io",
        "pkg.go.dev",
        "godbolt.org",
        "www.openssl.org",
    }
)

# Placeholder / example hosts that must never appear as a real citation.
KNOWN_BAD_HOSTS = frozenset(
    {
        "example.com",
        "example.org",
        "example.net",
        "example.invalid",
        "localhost",
        "127.0.0.1",
        "0.0.0.0",
        "tld",
        "domain.com",
        "url.com",
        "yourdomain.com",
    }
)

KNOWN_BAD_HOST_RE = re.compile(
    r"^(?:example\.(?:com|org|net)|localhost|127\.0\.0\.1|tld)$", re.IGNORECASE
)


def clean_url(raw: str) -> str:
    return raw.rstrip(".,;:'\"")


def extract_urls(text: str) -> list[str]:
    return [clean_url(m.group(0)) for m in URL_RE.finditer(text)]


def check_url_shape(art: Artifact, findings: list[Finding]) -> None:
    """Tier 1: scheme, host and canonicality sanity. No network."""
    for path, value in walk_strings(art.doc):
        for url in extract_urls(value):
            location = _join(art.id, path)
            evidence = _truncate(value, 220)
            try:
                parts = urlsplit(url)
            except ValueError as exc:
                findings.append(
                    Finding(
                        check=T1_URL_MALFORMED,
                        severity="FAIL",
                        tier=1,
                        artifact_id=art.id,
                        path=art.rel,
                        detail=f"malformed URL at {location}: {url} ({exc})",
                        evidence=evidence,
                    )
                )
                continue

            if parts.scheme not in {"http", "https"}:
                findings.append(
                    Finding(
                        check=T1_URL_SCHEME,
                        severity="FAIL",
                        tier=1,
                        artifact_id=art.id,
                        path=art.rel,
                        detail=f"non-http(s) scheme at {location}: {url}",
                        evidence=evidence,
                    )
                )
                continue

            host = (parts.hostname or "").lower()
            if not host:
                findings.append(
                    Finding(
                        check=T1_URL_MALFORMED,
                        severity="FAIL",
                        tier=1,
                        artifact_id=art.id,
                        path=art.rel,
                        detail=f"URL has no host at {location}: {url}",
                        evidence=evidence,
                    )
                )
                continue

            if KNOWN_BAD_HOST_RE.match(host) or host in KNOWN_BAD_HOSTS:
                findings.append(
                    Finding(
                        check=T1_URL_HOST,
                        severity="FAIL",
                        tier=1,
                        artifact_id=art.id,
                        path=art.rel,
                        detail=(
                            f"placeholder/example host cited as a source at {location}: "
                            f"{url}"
                        ),
                        evidence=evidence,
                    )
                )

            if parts.scheme == "http":
                findings.append(
                    Finding(
                        check=T1_URL_SCHEME,
                        severity="WARN",
                        tier=1,
                        artifact_id=art.id,
                        path=art.rel,
                        detail=(
                            f"plain http citation at {location}: {url} "
                            f"(insecure transport for a cited source)"
                        ),
                        evidence=evidence,
                    )
                )

            issue = _noncanonical_url_problem(url)
            if issue:
                findings.append(
                    Finding(
                        check=T1_URL_NONCANONICAL,
                        severity="WARN",
                        tier=1,
                        artifact_id=art.id,
                        path=art.rel,
                        detail=f"{issue} at {location}: {url}",
                        evidence=evidence,
                    )
                )


def _noncanonical_url_problem(url: str) -> str | None:
    """Return a description of why a URL is not a durable citation form."""
    parts = urlsplit(url)
    host = (parts.hostname or "").lower()
    # Bare-host URL on a host that serves content at a sub-path.  A query
    # string is a legitimate document selector (e.g. a CBOR playground link
    # that encodes its vector in ``?bytes=``), so only path-empty *and*
    # query-empty counts as citing a site rather than a document.
    if not host:
        return None
    if parts.path in {"", "/"} and not parts.query and not parts.fragment:
        return "bare host URL with no path (cites a site, not a document)"
    if parts.fragment and not parts.fragment.strip():
        return "URL ends in an empty fragment"
    return None


# --------------------------------------------------------------------------
# Tier 1: SHA / commit shape
# --------------------------------------------------------------------------

# Only inspect hex that sits immediately after an explicit commit label.
# Blind 40-hex scanning over a research corpus is dominated by CBOR test
# vectors, CBOR byte strings, GHA run IDs and base64 fragments (a survey of the
# real corpus found 985 hex-looking strings of other lengths), so the trigger
# has to be positional or the check is pure noise.  fnd-2026-0009's failure was
# exactly a commit-pinned claim whose pinning was never validated.
COMMIT_LABEL_RE = re.compile(
    r"\b(?:commit|revision|rev|sha)\b\s*[:=#]?\s*([0-9a-fA-F]{5,80})(?![0-9A-Za-z])"
)

# git permits abbreviated object names (7-12 chars) and sha-256 object names
# (64).  Anything else in a commit position is a malformed or truncated hash.
VALID_COMMIT_LENGTHS = frozenset({7, 8, 9, 10, 11, 12, 40, 64})


def check_sha_shape(art: Artifact, findings: list[Finding]) -> None:
    """Tier 1: hex strings asserted to be a commit hash must have git shape."""
    for path, value in walk_strings(art.doc):
        for match in COMMIT_LABEL_RE.finditer(value):
            token = match.group(1)
            if len(token) in VALID_COMMIT_LENGTHS:
                continue
            findings.append(
                Finding(
                    check=T1_SHA_SHAPE,
                    severity="WARN",
                    tier=1,
                    artifact_id=art.id,
                    path=art.rel,
                    detail=(
                        f"commit token {token!r} (len {len(token)}) at "
                        f"{_join(art.id, path)} is not a valid git object id: expected "
                        f"a 7-12 char abbreviation, or 40 (sha-1) / 64 (sha-256)"
                    ),
                    evidence=_truncate(value, 220),
                )
            )
            break  # one report per string is enough


# --------------------------------------------------------------------------
# Tier 1: link self-consistency
# --------------------------------------------------------------------------


def iter_link_refs(art: Artifact) -> Iterator[tuple[str, str]]:
    """Yield ``(link_key, referenced_id)`` from ``links:``."""
    links = art.doc.get("links")
    if not isinstance(links, dict):
        return
    for key, values in links.items():
        if isinstance(values, list):
            for value in values:
                if isinstance(value, str) and value:
                    yield str(key), value


def check_links(
    art: Artifact, by_id: dict[str, Artifact], findings: list[Finding]
) -> None:
    """Tier 1: links resolve on disk, and do not silently rely on withdrawals."""
    for key, ref in iter_link_refs(art):
        if ref not in by_id:
            findings.append(
                Finding(
                    check=T1_DANGLING_LINK,
                    severity="FAIL",
                    tier=1,
                    artifact_id=art.id,
                    path=art.rel,
                    detail=(
                        f"links.{key} references {ref!r}, which does not exist in the "
                        f"loaded corpus"
                    ),
                    evidence="",
                )
            )
            continue
        target_status = by_id[ref].status
        if target_status in WITHDRAWN_STATUSES:
            findings.append(
                Finding(
                    check=T1_WITHDRAWN_LINK,
                    severity="FAIL",
                    tier=1,
                    artifact_id=art.id,
                    path=art.rel,
                    detail=(
                        f"links.{key} depends on {ref} whose status is "
                        f"{target_status!r}; reasoning over a withdrawn artifact must "
                        f"be re-read before this artifact is trusted, disclosed or "
                        f"promoted"
                    ),
                    evidence=f"{ref} -> {by_id[ref].rel}",
                )
            )


# --------------------------------------------------------------------------
# Tier 1: correction-block integrity
# --------------------------------------------------------------------------

CORRECTION_KEY_RE = re.compile(r"^correction", re.IGNORECASE)

# Words in a correction block that assert the corrected claim is dead.  A
# verified artifact whose own correction says the substance is false is an
# internal contradiction, not a nuance.
CONTRADICTION_WORDS = (
    "refuted",
    "withdrawn",
    "false",
    "disproved",
    "disproven",
    "contradicted",
    "misattributed",
    "misquotation",
    "does not exist",
    "not a quotation",
    "no longer supported",
    "does not perform",
)

RETRACTION_MARKERS = (
    "retracted",
    "misquotation",
    "not a quotation",
    "superseded text",
    "previously quoted",
    "as_previously_quoted",
    "withdrawn",
    "original",
    "do not cite",
    "no longer valid",
)


def iter_correction_blocks(doc: dict[str, Any]) -> Iterator[tuple[str, Any]]:
    for key, value in doc.items():
        if CORRECTION_KEY_RE.match(str(key)) and not isinstance(value, str):
            yield str(key), value


def block_text(value: Any) -> str:
    parts: list[str] = []

    def rec(node: Any) -> None:
        if isinstance(node, str):
            parts.append(node)
        elif isinstance(node, dict):
            for key, sub in node.items():
                parts.append(str(key))
                rec(sub)
        elif isinstance(node, list):
            for sub in node:
                rec(sub)

    rec(value)
    return "\n".join(parts)


def check_corrections(art: Artifact, findings: list[Finding]) -> None:
    """Tier 1: corrections are marked, and verified artifacts are self-consistent."""
    blocks = list(iter_correction_blocks(art.doc))
    if not blocks:
        return
    status = art.status
    for key, block in blocks:
        text = block_text(block)
        low = text.lower()

        # (a) A retracted quotation must be clearly marked inside the block.
        retracted_lines = [
            line
            for line in text.splitlines()
            if any(w in line.lower() for w in ("was:", "previously", "retracted", "as quoted"))
        ]
        if retracted_lines:
            marked = any(m in low for m in RETRACTION_MARKERS)
            if not marked:
                findings.append(
                    Finding(
                        check=T1_CORRECTION_UNMARKED,
                        severity="WARN",
                        tier=1,
                        artifact_id=art.id,
                        path=art.rel,
                        detail=(
                            f"{key} carries retracted/previous wording but the block "
                            f"contains no retraction marker; a reader cannot tell "
                            f"which text was retracted"
                        ),
                        evidence=_truncate(text, 240),
                        manual_review_required=True,
                    )
                )

        # (b) verified + correction that calls the substance false.
        if status in ASSERTIVE_STATUSES:
            hits = [w for w in CONTRADICTION_WORDS if w in low]
            if hits:
                findings.append(
                    Finding(
                        check=T1_CORRECTION_CONTRADICTION,
                        severity="REVIEW",
                        tier=1,
                        artifact_id=art.id,
                        path=art.rel,
                        detail=(
                            f"status {status!r} but {key} contains "
                            f"{', '.join(repr(h) for h in hits)}; confirm the surviving "
                            f"claim is still verified or downgrade the status"
                        ),
                        evidence=_truncate(text, 240),
                        manual_review_required=True,
                    )
                )


# --------------------------------------------------------------------------
# Tier 1: staleness
# --------------------------------------------------------------------------

AS_OF_RE = re.compile(r"\bas of\s+(\d{4})-(\d{2})-(\d{2})", re.IGNORECASE)
DEFAULT_STALE_DAYS = 180


def check_staleness(
    art: Artifact, findings: list[Finding], stale_days: int, today: date
) -> None:
    """Tier 1: a publicly disclosed artifact pinned to an old 'as of' date.

    Only ``disclosure: public`` artifacts are checked: those are the ones whose
    stale claim has already escaped the repo, so staleness has external cost.
    """
    if art.disclosure not in DISCLOSED:
        return
    for path, value in walk_strings(art.doc):
        for match in AS_OF_RE.finditer(value):
            year, month, day = (int(g) for g in match.groups())
            try:
                pinned = date(year, month, day)
            except ValueError:
                continue
            age = (today - pinned).days
            if age > stale_days:
                findings.append(
                    Finding(
                        check=T1_STALENESS,
                        severity="WARN",
                        tier=1,
                        artifact_id=art.id,
                        path=art.rel,
                        detail=(
                            f"disclosure=public and pinned to 'as of {pinned.isoformat()}' "
                            f"at {_join(art.id, path)}; {age} days old exceeds "
                            f"--stale-days={stale_days}; re-fetch before further "
                            f"disclosure"
                        ),
                        evidence=_truncate(value, 200),
                    )
                )


# --------------------------------------------------------------------------
# Tier 1 driver
# --------------------------------------------------------------------------


def run_tier1(
    artifacts: list[Artifact],
    broken: list[Artifact],
    by_id: dict[str, Artifact],
    findings: list[Finding],
    stale_days: int,
    today: date,
) -> None:
    for art in broken:
        findings.append(
            Finding(
                check="yaml_unparseable",
                severity="REVIEW",
                tier=1,
                artifact_id=f"<no-id:{art.rel}>",
                path=art.rel,
                detail=f"YAML did not parse; citation checks skipped: {art.load_error}",
            )
        )
    for art in artifacts:
        check_url_shape(art, findings)
        check_sha_shape(art, findings)
        check_links(art, by_id, findings)
        check_corrections(art, findings)
        check_staleness(art, findings, stale_days, today)


# --------------------------------------------------------------------------
# Tier 2: network
# --------------------------------------------------------------------------

RFC_HOSTS = {"www.rfc-editor.org", "rfc-editor.org"}
RFC_URL_RE = re.compile(r"/rfc(\d{3,5})(?:\.html?)?(?:[#/]|$)", re.IGNORECASE)

# A "quotation" is a long stretch of prose quoted from a specification.  We do
# not auto-fail on these; we flag them for a human to re-fetch, because only a
# human has confirmed which of the surrounding text is actually normative.
QUOTE_MIN_WORDS = 40
RFC_KEYWORDS = (
    "must",
    "must not",
    "should",
    "shall",
    "required",
    "requirement",
    "rfc",
    "section",
)
QUOTE_CONTEXT_RE = re.compile(
    r"quotation|quoted|quote\b|verbatim|states:\s*$|as_previously_quoted|"
    r"rfc_\d+_section|rfc \d+|section \d",
    re.IGNORECASE,
)


def find_quote_candidates(art: Artifact) -> list[tuple[str, str, str]]:
    """Return ``(field_path, text, near_url)`` for likely quotations."""
    out: list[tuple[str, str, str]] = []
    urls_in_doc = [u for _, v in walk_strings(art.doc) for u in extract_urls(v)]
    for path, value in walk_strings(art.doc):
        if len(value.split()) < QUOTE_MIN_WORDS:
            continue
        low = value.lower()
        if not any(k in low for k in RFC_KEYWORDS):
            continue
        if not QUOTE_CONTEXT_RE.search(value):
            continue
        out.append((".".join(path), value, urls_in_doc[0] if urls_in_doc else ""))
    return out


@dataclass
class ProbeResult:
    url: str
    state: str  # reachable | http-4xx | http-5xx | network-error | skipped
    detail: str = ""
    body: str | None = None


def _http_probe(url: str, timeout: float, max_bytes: int, want_body: bool = False) -> ProbeResult:
    """Anonymous HEAD-then-GET.  Never raises; never authenticates.

    ``want_body`` forces the GET path even when HEAD succeeds, because a
    reachable URL whose *content* must be inspected needs the bytes.
    """
    import urllib.error
    import urllib.request

    def _request(method: str):
        request = urllib.request.Request(
            url,
            method=method,
            headers={
                # Identity only.  Frontier's own tool, public URLs, no secrets.
                "User-Agent": f"{TOOL_NAME}/{TOOL_VERSION} (+citation verifier)",
                "Accept": "*/*",
            },
        )
        return urllib.request.urlopen(request, timeout=timeout)

    if not want_body:
        try:
            with _request("HEAD") as resp:
                code = resp.getcode() or 0
                if 200 <= code < 400:
                    return ProbeResult(url=url, state="reachable", detail=f"HEAD {code}")
        except urllib.error.HTTPError as exc:
            if exc.code == 405 or exc.code == 403 or exc.code == 501:
                pass  # HEAD disallowed; fall through to GET
            elif 400 <= exc.code < 500:
                return ProbeResult(url=url, state="http-4xx", detail=f"HEAD {exc.code}")
            elif 500 <= exc.code < 600:
                return ProbeResult(url=url, state="http-5xx", detail=f"HEAD {exc.code}")
        except Exception:
            pass  # network down, DNS fail, TLS fail -> GET below decides

    try:
        with _request("GET") as resp:
            code = resp.getcode() or 0
            body = resp.read(max_bytes).decode("utf-8", errors="replace")
            if 200 <= code < 400:
                return ProbeResult(url=url, state="reachable", detail=f"GET {code}", body=body)
            if 400 <= code < 500:
                return ProbeResult(url=url, state="http-4xx", detail=f"GET {code}")
            return ProbeResult(url=url, state="http-5xx", detail=f"GET {code}")
    except urllib.error.HTTPError as exc:
        code = exc.code
        if 400 <= code < 500:
            return ProbeResult(url=url, state="http-4xx", detail=f"GET {code}")
        if 500 <= code < 600:
            return ProbeResult(url=url, state="http-5xx", detail=f"GET {code}")
        return ProbeResult(url=url, state="network-error", detail=f"HTTPError {code}")
    except Exception as exc:
        return ProbeResult(url=url, state="network-error", detail=type(exc).__name__)


def _normalize_text(text: str) -> str:
    text = text.lower()
    text = text.replace("\u2019", "'").replace("\u2018", "'")
    text = text.replace("\u201c", '"').replace("\u201d", '"')
    text = text.replace("\u2014", " ").replace("\u2013", " ")
    # RFC plain text carries hard line wraps, page breaks and form feeds
    # mid-sentence.  Collapsing all whitespace to single spaces lets a real
    # quotation match the body text even though a line wrapped inside it.
    text = text.replace("\f", " ")
    text = re.sub(r"\s+", " ", text)
    return text


def _quote_probe_sentences(text: str) -> list[str]:
    """Split a candidate quotation into sentences usable for a substring test."""
    flat = _normalize_text(text)
    parts = re.split(r"(?<=[.;:])\s+", flat)
    out = []
    for part in parts:
        part = part.strip(" \"'")
        words = part.split()
        if 8 <= len(words) <= 60:
            out.append(part)
    return out


def _find_rfc_body(url: str, timeout: float) -> ProbeResult:
    parts = urlsplit(url)
    match = RFC_URL_RE.search(parts.path)
    if not match:
        return ProbeResult(url=url, state="skipped", detail="not an RFC URL")
    number = match.group(1)
    # Fetch the plain-text RFC; it is the canonical, stable artifact and it is
    # what a quotation should be checked against.
    txt_url = f"https://www.rfc-editor.org/rfc/rfc{number}.txt"
    # The plain text is fetched with its body: matching a quotation requires
    # the bytes, not just the status.
    result = _http_probe(txt_url, timeout, max_bytes=2_000_000, want_body=True)
    if result.state == "reachable" and result.body:
        return ProbeResult(url=txt_url, state=result.state, detail=result.detail, body=result.body)
    return result


def run_tier2(
    artifacts: list[Artifact],
    findings: list[Finding],
    *,
    timeout: float,
    online: bool,
    max_urls: int,
) -> dict[str, int]:
    """Tier 2.  ``online=False`` degrades to UNVERIFIABLE, never FAIL."""
    stats = {"reachable": 0, "http-4xx": 0, "http-5xx": 0, "network-error": 0}

    def emit(art: Artifact, check: str, severity: str, detail: str, evidence: str = "", manual: bool = False) -> None:
        findings.append(
            Finding(
                check=check,
                severity=severity,
                tier=2,
                artifact_id=art.id,
                path=art.rel,
                detail=detail,
                evidence=evidence,
                manual_review_required=manual,
            )
        )

    for art in artifacts:
        urls: list[str] = []
        for _, value in walk_strings(art.doc):
            urls.extend(extract_urls(value))
        # De-duplicate, preserve order.
        seen: set[str] = set()
        unique_urls = [u for u in urls if not (u in seen or seen.add(u))]

        for url in unique_urls[:max_urls]:
            if not online:
                emit(
                    art,
                    TIER2_REACHABILITY,
                    "UNVERIFIABLE",
                    f"citation not checked (offline): {url}",
                    evidence=url,
                )
                continue
            result = _http_probe(url, timeout, max_bytes=512_000)
            stats[result.state] = stats.get(result.state, 0) + 1
            if result.state == "reachable":
                emit(
                    art,
                    TIER2_REACHABILITY,
                    "UNVERIFIABLE",
                    f"reachable ({result.detail}), content NOT verified: {url}",
                    evidence=url,
                    manual=True,
                )
            elif result.state == "http-4xx":
                emit(
                    art,
                    TIER2_REACHABILITY,
                    "UNVERIFIABLE",
                    f"citation returned 4xx ({result.detail}); may be a moved or "
                    f"withdrawn source, needs a human: {url}",
                    evidence=url,
                    manual=True,
                )
            elif result.state == "http-5xx":
                emit(
                    art,
                    TIER2_REACHABILITY,
                    "UNVERIFIABLE",
                    f"citation returned 5xx ({result.detail}); not evidence of a bad "
                    f"citation: {url}",
                    evidence=url,
                )
            else:
                emit(
                    art,
                    TIER2_REACHABILITY,
                    "UNVERIFIABLE",
                    f"network error ({result.detail}); tool cannot judge the citation: "
                    f"{url}",
                    evidence=url,
                )

        # Quote spot-check, RFC only, and only for candidate quotations.
        for field_path, text, _ in find_quote_candidates(art):
            rfc_urls = [u for u in unique_urls if urlsplit(u).hostname in RFC_HOSTS]
            if not rfc_urls:
                emit(
                    art,
                    TIER2_QUOTE,
                    "UNVERIFIABLE",
                    f"quotation-like text at {field_path} has no adjacent RFC URL to "
                    f"check against; human must re-fetch the source",
                    evidence=_truncate(text, 240),
                    manual=True,
                )
                continue
            if not online:
                emit(
                    art,
                    TIER2_QUOTE,
                    "UNVERIFIABLE",
                    f"quotation-like text at {field_path} not checked (offline)",
                    evidence=_truncate(text, 240),
                    manual=True,
                )
                continue

            matched_any = False
            unresolved: list[str] = []
            # A quotation is treated as found when a strong majority of its
            # sentences appear verbatim in the fetched RFC body.  Requiring
            # 100% would flag genuine quotations that merely differ in
            # formatting (RFCs render hex literals in backticks, and one
            # sentence in the real corpus does exactly that).  Requiring a
            # *majority* keeps the misquotation at 0/N while tolerating
            # formatting drift.
            QUORUM = 0.6
            for rfc_url in rfc_urls[:4]:
                body = _find_rfc_body(rfc_url, timeout)
                if body.state != "reachable" or not body.body:
                    unresolved.append(f"{rfc_url}: {body.state}")
                    continue
                haystack = _normalize_text(body.body)
                sentences = _quote_probe_sentences(text)
                if not sentences:
                    unresolved.append(f"{rfc_url}: no usable sentence in quotation")
                    continue
                hits = sum(1 for s in sentences if s in haystack)
                ratio = hits / len(sentences)
                if ratio >= QUORUM:
                    matched_any = True
                    break
                # Partial match is informative but not a verdict.
                unresolved.append(f"{rfc_url}: {hits}/{len(sentences)} sentences found")
            if matched_any:
                emit(
                    art,
                    TIER2_QUOTE,
                    "UNVERIFIABLE",
                    f"quotation at {field_path} matches text in the cited RFC; "
                    f"attribution of each clause to a specific section is still a "
                    f"human judgement",
                    evidence=_truncate(text, 240),
                    manual=True,
                )
            else:
                emit(
                    art,
                    TIER2_QUOTE,
                    "UNVERIFIABLE",
                    f"quotation at {field_path} did not match the cited RFC text "
                    f"({'; '.join(unresolved) or 'no RFC fetch'}); treat as SUSPECT and "
                    f"re-read the source before relying on it",
                    evidence=_truncate(text, 240),
                    manual=True,
                )
    return stats


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------


def _join(artifact_id: str, path: Sequence[str]) -> str:
    return f"{artifact_id}:{'.'.join(path)}"


def _truncate(text: str, limit: int) -> str:
    flat = re.sub(r"\s+", " ", text).strip()
    if len(flat) <= limit:
        return flat
    return flat[: limit - 3] + "..."


def _parse_date(value: str | None) -> date | None:
    if not value:
        return None
    text = str(value).strip()
    try:
        return date.fromisoformat(text[:10])
    except ValueError:
        return None


# --------------------------------------------------------------------------
# Reporting
# --------------------------------------------------------------------------


def print_report(
    findings: list[Finding], artifacts: list[Artifact], online: bool, stale_days: int
) -> None:
    tier1 = [f for f in findings if f.tier == 1]
    tier2 = [f for f in findings if f.tier == 2]
    print(f"{TOOL_NAME} {TOOL_VERSION}")
    print(f"artifacts scanned: {len(artifacts)}")
    print(f"mode: {'online' if online else 'offline (tier 2 skipped)'}  stale-days={stale_days}")
    print()

    by_check: dict[str, list[Finding]] = defaultdict(list)
    for f in findings:
        by_check[f.check].append(f)

    for tier, label in ((1, "TIER 1 (offline, deterministic)"), (2, "TIER 2 (network)")):
        subset = [f for f in findings if f.tier == tier]
        print(f"== {label}: {len(subset)} observation(s)")
        if not subset:
            print("   (none)")
        else:
            grouped: dict[str, list[Finding]] = defaultdict(list)
            for f in subset:
                grouped[f.check].append(f)
            for check in sorted(grouped):
                items = grouped[check]
                sev_counts = defaultdict(int)
                for f in items:
                    sev_counts[f.severity] += 1
                sev_str = ", ".join(f"{k}={sev_counts[k]}" for k in sorted(sev_counts, key=lambda s: SEVERITY_ORDER.get(s, 9)))
                print(f"   - {check}: {len(items)} [{sev_str}]")
                for f in sorted(items, key=lambda x: (SEVERITY_ORDER.get(x.severity, 9), x.artifact_id))[:12]:
                    marker = "MANUAL" if f.manual_review_required else "      "
                    print(f"       [{f.severity:<12}] {marker} {f.artifact_id}: {f.detail}")
                if len(items) > 12:
                    print(f"       ... {len(items) - 12} more (see --json or --report)")
        print()

    fails = [f for f in tier1 if f.severity == "FAIL"]
    print(
        f"summary: {len(fails)} tier-1 FAIL, "
        f"{len(tier1) - len(fails)} tier-1 non-fail, {len(tier2)} tier-2 (informational)"
    )
    if online:
        print("note: network observations never change the exit code on their own.")


def _json_report(
    findings: list[Finding], artifacts: list[Artifact], online: bool
) -> dict[str, Any]:
    tier1 = [f for f in findings if f.tier == 1]
    fails = [f for f in tier1 if f.severity == "FAIL"]
    by_check: dict[str, int] = defaultdict(int)
    for f in findings:
        by_check[f.check] += 1
    return {
        "tool": TOOL_NAME,
        "version": TOOL_VERSION,
        "online": online,
        "artifacts_scanned": len(artifacts),
        "counts": {
            "total": len(findings),
            "tier1": len(tier1),
            "tier1_fail": len(fails),
            "tier2": len([f for f in findings if f.tier == 2]),
            "by_check": dict(by_check),
        },
        "findings": [f.to_dict() for f in findings],
    }


def write_report(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def render_text_report(
    artifacts: list[Artifact], findings: list[Finding], online: bool, stale_days: int
) -> str:
    import io
    import contextlib

    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer):
        print_report(findings, artifacts, online, stale_days)
    return buffer.getvalue()


# --------------------------------------------------------------------------
# Selftest
# --------------------------------------------------------------------------

GOOD_RFC_QUOTE = (
    "The keys in every map MUST be sorted in the bytewise lexicographic order of "
    "their deterministic encodings. This sorting requirement can result in "
    "canonical maps."
)
BAD_RFC_QUOTE = (
    "Encoding restrictions are aligned with Core Deterministic Encoding Requirements "
    "specified in Section 4.2.1 of RFC 8949. In particular: encoding MUST be done "
    "using definite lengths, the length of the encoded argument MUST be the minimum "
    "possible length, the keys in every map MUST be sorted in the bytewise "
    "lexicographic order of their deterministic encodings."
)


def _write_fixture(directory: Path, name: str, doc: dict[str, Any]) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / name
    path.write_text(yaml.safe_dump(doc, sort_keys=False, allow_unicode=True), encoding="utf-8")
    return path


def _fixture_envelope(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "id": "fnd-2026-9999",
        "type": "finding",
        "status": "verified_conclusion",
        "created_at": "2026-10-01T00:00:00Z",
        "updated_at": "2026-10-01T00:00:00Z",
        "summary": "selftest fixture",
        "epistemic_status": "verified_conclusion",
        "provenance": {"created_by": {"kind": "model-agent", "role": "selftest"}},
        "links": {},
    }
    base.update(overrides)
    return base


def build_selftest_corpus(root: Path) -> list[Artifact]:
    """Write a self-contained corpus with one known-bad artifact.

    The known-bad fixture reproduces the two real failures at once:

    * it quotes RFC 9052 section 9 with RFC 8949 section 4.2.1 text
      (misquotation), and
    * it links to a ``rejected`` artifact (withdrawn dependency).

    It also carries a malformed-length commit token in a commit context, an
    http citation, and a verified status alongside a correction block that calls
    its own substance false.
    """
    findings_dir = root / "knowledge" / "findings"
    observations_dir = root / "knowledge" / "observations"

    # A rejected artifact to be depended upon.
    _write_fixture(
        observations_dir,
        "obs-2026-9998.yaml",
        _fixture_envelope(
            id="obs-2026-9998",
            type="observation",
            status="rejected",
            epistemic_status="observation",
            summary="rejected fixture that a bad finding will cite",
        ),
    )

    # The known-bad finding.
    _write_fixture(
        findings_dir,
        "fnd-2026-9999.yaml",
        _fixture_envelope(
            summary="KNOWN-BAD: spliced RFC 8949 text into an RFC 9052 quotation",
            disclosure="public",
            provenance={
                "created_by": {"kind": "model-agent", "role": "selftest"},
                "sources": [
                    "http://www.rfc-editor.org/rfc/rfc9052",
                    "knowledge/observations/obs-2026-9998.yaml",
                ],
                "parent": "msn-2026-9999",
            },
            links={
                "observations": ["obs-2026-9998", "obs-2026-9997"],
                "reviews": ["rev-2026-9999"],
            },
            classification={"primary": "SPEC_VIOLATION per RFC 9052 section 9"},
            statement=(
                "RFC 9052 section 9 says: " + BAD_RFC_QUOTE
            ),
            scope=(
                "verified against OpenSSH master HEAD as of 2026-01-01, "
                "commit 0ef0f5a839831c213f24 (truncated)"
            ),
            correction_2026_10_02={
                "reason": "A re-check refuted the normative basis; the quotation is false.",
                "corrections": [
                    {
                        "id": "C1",
                        "severity": "fatal",
                        "was": BAD_RFC_QUOTE,
                        "now": "That text is RFC 8949 section 4.2.1, not RFC 9052 section 9.",
                    }
                ],
            },
        ),
    )
    return load_artifacts(root, include_missions=False)[0]


def selftest_check(
    name: str, findings: list[Finding], artifact_id: str, expected_checks: set[str]
) -> tuple[bool, str]:
    hits = {f.check for f in findings if f.artifact_id == artifact_id}
    missing = expected_checks - hits
    if missing:
        return False, f"{name}: expected checks not raised: {sorted(missing)}"
    return True, f"{name}: raised {sorted(hits)}"


def _selftest_rfc_discrimination() -> tuple[bool, str]:
    """Prove the RFC quote check separates the real misquotation.

    The map-key-sorting sentence is genuine RFC 8949 text and does not occur in
    RFC 9052.  If that holds live, the tool would flag a finding that
    attributed it to RFC 9052 -- the exact fnd-2026-0014 defect.
    """
    spliced = (
        "the keys in every map must be sorted in the bytewise lexicographic order "
        "of their deterministic encodings."
    )
    r8949 = _find_rfc_body("https://www.rfc-editor.org/rfc/rfc8949", 25)
    r9052 = _find_rfc_body("https://www.rfc-editor.org/rfc/rfc9052", 25)
    if r8949.state != "reachable" or not r8949.body:
        return True, "rfc discrimination: SKIPPED (RFC 8949 unreachable; not a failure)"
    if r9052.state != "reachable" or not r9052.body:
        return True, "rfc discrimination: SKIPPED (RFC 9052 unreachable; not a failure)"

    hay8949 = _normalize_text(r8949.body)
    hay9052 = _normalize_text(r9052.body)
    in_8949 = spliced in hay8949
    in_9052 = spliced in hay9052
    if in_8949 and not in_9052:
        return True, (
            "rfc discrimination: PASS (spliced sentence found in RFC 8949 and "
            "absent from RFC 9052, so misattributing it is detectable)"
        )
    return False, (
        "rfc discrimination: FAIL (spliced sentence in RFC8949="
        f"{in_8949}, in RFC9052={in_9052}); the check cannot separate the texts"
    )


def run_selftest(verbose: bool = True, with_network: bool = False) -> int:
    """Run Tier 1 against a self-contained fixture corpus. Returns exit code.

    ``with_network`` additionally fetches RFC 8949 and RFC 9052 to prove the
    quote discriminator separates the misquotation from the genuine quotation.
    """
    temp_root = Path(tempfile.mkdtemp(prefix="verify_citations_selftest_"))
    try:
        artifacts = build_selftest_corpus(temp_root)
        by_id = {a.id: a for a in artifacts}
        findings: list[Finding] = []
        run_tier1(
            artifacts,
            [],
            by_id,
            findings,
            stale_days=DEFAULT_STALE_DAYS,
            today=date(2026, 10, 3),
        )

        bad_id = "fnd-2026-9999"
        expected = {
            T1_URL_SCHEME,          # http:// citation
            T1_WITHDRAWN_LINK,      # links to rejected obs-2026-9998
            T1_DANGLING_LINK,       # links to obs-2026-9997 / rev-2026-9999 that do not exist
            T1_SHA_SHAPE,           # commit token 0ef0f5a8 (len 8) in commit context
            T1_CORRECTION_CONTRADICTION,  # verified + correction saying refuted/false
            T1_STALENESS,           # disclosure public + "as of 2026-01-01" (>180d)
        }
        results: list[tuple[bool, str]] = []
        results.append(
            selftest_check("known-bad fixture", findings, bad_id, expected)
        )

        # A clean artifact must produce zero findings, or every check is noise.
        clean_dir = temp_root / "knowledge" / "targets"
        _write_fixture(
            clean_dir,
            "tgt-2026-9999.yaml",
            _fixture_envelope(
                id="tgt-2026-9999",
                type="target",
                status="current",
                epistemic_status="idea",
                summary="clean fixture: https citation, resolvable links, no corrections",
                provenance={
                    "created_by": {"kind": "model-agent", "role": "selftest"},
                    "sources": ["https://www.rfc-editor.org/rfc/rfc8949#section-4.2.1"],
                },
                links={},
            ),
        )
        clean_artifacts = load_artifacts(temp_root, include_missions=False)[0]
        clean_by_id = {a.id: a for a in clean_artifacts}
        clean_findings: list[Finding] = []
        run_tier1(
            clean_artifacts,
            [],
            clean_by_id,
            clean_findings,
            stale_days=DEFAULT_STALE_DAYS,
            today=date(2026, 10, 3),
        )
        clean_noise = [f for f in clean_findings if f.artifact_id == "tgt-2026-9999"]
        if clean_noise:
            results.append(
                (False, f"clean fixture: expected 0 findings, got {len(clean_noise)}: "
                        + "; ".join(f.detail for f in clean_noise))
            )
        else:
            results.append((True, "clean fixture: 0 findings (no false positives)"))

        # Optional, network-gated proof that the RFC quote discriminator
        # actually separates the two real-world texts.  This is the check that
        # would have caught fnd-2026-0014 before it reached verified_conclusion.
        if with_network:
            results.append(_selftest_rfc_discrimination())

        passed = all(ok for ok, _ in results)
        if verbose:
            print("== selftest ==")
            for ok, message in results:
                print(f"   [{'PASS' if ok else 'FAIL'}] {message}")
            if verbose:
                print("   known-bad fixture raised:")
                for f in sorted(
                    (f for f in findings if f.artifact_id == bad_id),
                    key=lambda x: (SEVERITY_ORDER.get(x.severity, 9), x.check),
                ):
                    print(f"       [{f.severity:<12}] {f.check}: {f.detail}")
            print(f"   selftest: {'PASS' if passed else 'FAIL'}")
        return EXIT_OK if passed else EXIT_FINDINGS
    finally:
        shutil.rmtree(temp_root, ignore_errors=True)


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="verify_citations.py",
        description=(
            "Deterministic, read-only verification of external citations in "
            "Frontier YAML artifacts."
        ),
    )
    scope = parser.add_mutually_exclusive_group()
    scope.add_argument("--all", action="store_true", help="verify the whole corpus (default)")
    scope.add_argument("--finding", metavar="ID", help="verify a single artifact by id")
    parser.add_argument("--online", action="store_true", help="enable tier-2 network checks")
    parser.add_argument("--json", action="store_true", help="emit JSON on stdout")
    parser.add_argument("--report", metavar="PATH", help="write a text report to PATH")
    parser.add_argument(
        "--missions",
        action="store_true",
        help="also scan missions/ (default: knowledge/ only)",
    )
    parser.add_argument(
        "--stale-days",
        type=int,
        default=DEFAULT_STALE_DAYS,
        metavar="N",
        help=f"staleness threshold in days (default {DEFAULT_STALE_DAYS})",
    )
    parser.add_argument("--selftest", action="store_true", help="run fixture selftest and exit")
    parser.add_argument(
        "--selftest-network",
        action="store_true",
        help="with --selftest, also fetch the real RFCs to prove quote discrimination",
    )
    parser.add_argument("--timeout", type=float, default=15.0, help="per-request timeout (s)")
    parser.add_argument("--max-urls", type=int, default=50, help="max URLs per artifact")
    parser.add_argument(
        "--root", metavar="PATH", default=None, help="repository root (default: autodetect)"
    )
    return parser


def detect_root(explicit: str | None) -> Path:
    if explicit:
        return Path(explicit).resolve()
    here = Path(__file__).resolve().parent
    for candidate in [here, *here.parents]:
        if (candidate / "knowledge").is_dir() and (candidate / "src").is_dir():
            return candidate
    return here.parent


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.selftest:
        return run_selftest(with_network=args.selftest_network)

    root = detect_root(args.root)
    if not (root / "knowledge").is_dir():
        print(f"{TOOL_NAME}: no knowledge/ directory under {root}", file=sys.stderr)
        return EXIT_ERROR

    try:
        today = datetime.now(timezone.utc).date()
        artifacts, broken = load_artifacts(root, include_missions=args.missions)
        # Link resolution always spans missions as well, even when missions are
        # not themselves scanned.  A finding under knowledge/ routinely links to
        # the mission that produced it; scoping resolution to knowledge/ alone
        # would report every such link as dangling.
        resolution_scope, _ = load_artifacts(root, include_missions=True)
    except Exception as exc:
        print(f"{TOOL_NAME}: failed to load corpus: {exc}", file=sys.stderr)
        return EXIT_ERROR

    by_id = {a.id: a for a in resolution_scope}

    if args.finding:
        selected = [a for a in resolution_scope if a.id == args.finding]
        if not selected:
            print(f"{TOOL_NAME}: no artifact with id {args.finding!r}", file=sys.stderr)
            return EXIT_ERROR
        artifacts = selected
        broken = []

    findings: list[Finding] = []
    try:
        run_tier1(artifacts, broken if not args.finding else [], by_id, findings, args.stale_days, today)
        # Tier 2 always runs: offline it emits UNVERIFIABLE rows so the report
        # records exactly what is unchecked rather than silently omitting it.
        run_tier2(
            artifacts,
            findings,
            timeout=args.timeout,
            online=args.online,
            max_urls=args.max_urls,
        )
    except Exception as exc:
        print(f"{TOOL_NAME}: internal error: {exc}", file=sys.stderr)
        return EXIT_ERROR

    tier1_fails = [f for f in findings if f.tier == 1 and f.severity == "FAIL"]

    if args.json:
        print(json.dumps(_json_report(findings, artifacts, args.online), indent=2))
    else:
        print_report(findings, artifacts, args.online, args.stale_days)

    if args.report:
        text = render_text_report(artifacts, findings, args.online, args.stale_days)
        try:
            write_report(Path(args.report), text)
        except Exception as exc:
            print(f"{TOOL_NAME}: could not write report: {exc}", file=sys.stderr)
            return EXIT_ERROR

    return EXIT_FINDINGS if tier1_fails else EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())