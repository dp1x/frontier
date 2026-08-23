"""Hybrid compute router.

Decides where a workload executes based on workload characteristics and host
facts, not ideology: lightweight stays local (preferably RAM-disk scratch),
medium prefers free public CI, heavy escalates. Every decision should be
recorded on the experiment artifact that requested it.
"""

from __future__ import annotations

from dataclasses import dataclass

_MEGABYTE = 1024 * 1024

LOCAL_ISOLATION = "env-scrubbed-scratch"
GHA_ISOLATION = "github-runner"
EXTERNAL_ISOLATION = "external-isolated"


@dataclass
class HostFacts:
    scratch_free_bytes: int
    github_actions_available: bool
    docker_available: bool = False
    local_ok: bool = True


@dataclass(frozen=True)
class JobSpec:
    compute_class: str  # lightweight | medium | heavy
    estimated_disk_mb: int = 0
    untrusted: bool = False
    needs_matrix: bool = False
    allow_local_fallback: bool = True
    network: bool = False


@dataclass(frozen=True)
class Decision:
    location: str  # local | github-actions | escalate | blocked
    isolation: str
    reason: str
    untrusted: bool = False


def route(job: JobSpec, host: HostFacts) -> Decision:
    needed_bytes = job.estimated_disk_mb * _MEGABYTE
    fits_locally = host.local_ok and host.scratch_free_bytes >= needed_bytes

    if job.compute_class == "heavy":
        return Decision(
            location="escalate",
            isolation=EXTERNAL_ISOLATION,
            reason=(
                "workload exceeds the lightweight/medium envelope; "
                "external compute requires explicit justification on the mission"
            ),
            untrusted=job.untrusted,
        )

    if job.compute_class == "medium":
        if host.github_actions_available:
            return Decision(
                location="github-actions",
                isolation=GHA_ISOLATION,
                reason="substantial compile/matrix/suite work routed to free public runners",
                untrusted=job.untrusted,
            )
        if job.allow_local_fallback and fits_locally:
            return Decision(
                location="local",
                isolation=LOCAL_ISOLATION,
                reason="runners unavailable; local fallback permitted with sufficient capacity",
                untrusted=job.untrusted,
            )
        return Decision(
            location="blocked",
            isolation=LOCAL_ISOLATION,
            reason="no GitHub Actions available and scratch capacity is insufficient",
            untrusted=job.untrusted,
        )

    # lightweight
    if fits_locally:
        return Decision(
            location="local",
            isolation=LOCAL_ISOLATION,
            reason="small deterministic experiment; disposable local scratch suffices",
            untrusted=job.untrusted,
        )
    if host.github_actions_available:
        return Decision(
            location="github-actions",
            isolation=GHA_ISOLATION,
            reason="insufficient local scratch capacity; rerouted to runners",
            untrusted=job.untrusted,
        )
    return Decision(
        location="blocked",
        isolation=LOCAL_ISOLATION,
        reason="insufficient scratch capacity for the requested experiment",
        untrusted=job.untrusted,
    )
