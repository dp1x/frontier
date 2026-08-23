"""Hybrid compute router."""

from frontier.compute import HostFacts, JobSpec, route


def _host(**kwargs) -> HostFacts:
    facts = HostFacts(
        scratch_free_bytes=4 * 1024**3,
        github_actions_available=True,
        docker_available=False,
        local_ok=True,
    )
    for key, value in kwargs.items():
        setattr(facts, key, value)
    return facts


def test_lightweight_job_routes_local_when_capacity_exists():
    decision = route(
        JobSpec(compute_class="lightweight", estimated_disk_mb=50, untrusted=True),
        _host(),
    )
    assert decision.location == "local"
    assert decision.isolation == "env-scrubbed-scratch"


def test_medium_job_prefers_github_actions():
    decision = route(
        JobSpec(compute_class="medium", estimated_disk_mb=500, needs_matrix=True),
        _host(),
    )
    assert decision.location == "github-actions"


def test_medium_job_falls_back_local_when_gha_unavailable():
    decision = route(
        JobSpec(compute_class="medium", estimated_disk_mb=100, allow_local_fallback=True),
        _host(github_actions_available=False),
    )
    assert decision.location == "local"


def test_heavy_job_escalates_even_if_local_is_idle():
    decision = route(JobSpec(compute_class="heavy", estimated_disk_mb=8000), _host())
    assert decision.location == "escalate"


def test_insufficient_scratch_blocks_local_lightweight():
    decision = route(
        JobSpec(compute_class="lightweight", estimated_disk_mb=5000),
        _host(scratch_free_bytes=100 * 1024**2, github_actions_available=False),
    )
    assert decision.location == "blocked"
    assert "capacity" in decision.reason.lower() or "scratch" in decision.reason.lower()


def test_untrusted_never_gets_unisolated_local():
    decision = route(
        JobSpec(compute_class="lightweight", untrusted=True, estimated_disk_mb=10),
        _host(),
    )
    assert decision.isolation != "none"
    assert decision.untrusted is True
