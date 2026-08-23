# Embargoed missions (gitignored except this README)

Missions whose objectives or findings are security-sensitive are stored here
with status `escalate/security-sensitive` or `disclosure: embargoed`. This
directory is in `.gitignore`; only this README is tracked.

Workflow: move the mission file here, stop automated continuation and
disclosure, notify the human. The human decides whether the mission proceeds,
is redacted back into public knowledge, or is terminated. A mission that was
ever security-sensitive can never become the parent of an automatic
follow-up mission.
