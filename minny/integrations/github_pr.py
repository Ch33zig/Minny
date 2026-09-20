"""A pull request for a rule the blue agent proposed and the gate accepted.

The review is the product here. A rule that passed a held out detection
threshold and a false positive budget is a change a human should read before
it runs in production, so what leaves Minny is a branch, a rule file and a
body carrying the evaded variant, the gate results and the false positive
numbers. Merging stays a human action: there is no auto merge tool in this
module and there is no intent to add one.

Two rules from 04-COMPOSIO.md section 7 are enforced here rather than
remembered:

* **"Related to #N", never "Closes #N" or "Fixes #N".** A merge must not
  close the gap issue before the merged rule has actually been replayed
  against the variant it was written for.
* **No raw source records.** The body carries line numbers and Minny links,
  never log text and never anything from the mailbox. `egress.check` runs on
  the assembled body before it goes anywhere.

In mock mode the body is assembled exactly as it would be posted and stored
as an artifact, so the pull request is reviewable on screen without a repo.
Nothing about it is a placeholder except the repository it names, which is
labelled as unconfigured rather than invented.
"""

from __future__ import annotations

import hashlib
import os
import uuid
from datetime import datetime
from pathlib import Path

from minny import paths
from minny.integrations import client, config, egress, store

_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
_MOCK_FIXTURES = _REPO_ROOT / "fixtures" / "mock"

RULE_FILE = "detection-rules/rules.yaml"

# A stable namespace so the remediation marker for a rule is the same string
# on every run. Idempotency depends on it: 04-COMPOSIO.md section 9 recovers
# a lost response by finding this marker rather than creating a second PR.
MARKER_NAMESPACE = uuid.UUID("4d696e6e-0000-4000-8000-636f6d706f73")


def repo() -> dict:
    """The destination repository, from stored policy.

    Unset values stay visibly unset. A plausible looking owner and repo
    nobody can open is worse than a field that says it is not configured.
    """
    owner = os.environ.get("MINNY_GITHUB_OWNER")
    name = os.environ.get("MINNY_GITHUB_REPO")
    return {
        "owner": owner,
        "repo": name,
        "base": os.environ.get("MINNY_GITHUB_BASE") or "main",
        "configured": bool(owner and name),
        "slug": f"{owner}/{name}" if owner and name else None,
    }


def gap_issue() -> int | None:
    """The tracked gap issue, when there is one.

    Returns None rather than a number, because a fabricated issue number in a
    pull request body is the exact detail that costs a demo its credibility.
    """
    raw = os.environ.get("MINNY_GITHUB_GAP_ISSUE")
    try:
        return int(raw) if raw else None
    except ValueError:
        return None


def load_proposal(rule_id: str) -> dict | None:
    for source in (paths.data_dir() / "blue_proposals.json", _MOCK_FIXTURES / "blue_proposals.json"):
        proposals = store.read_json(source)
        if isinstance(proposals, dict):
            proposals = proposals.get("proposals")
        if not isinstance(proposals, list):
            continue
        for proposal in proposals:
            if isinstance(proposal, dict) and proposal.get("id") == rule_id:
                return proposal
    return None


def _metrics() -> dict:
    metrics = store.read_json(paths.metrics_path()) or store.read_json(
        _MOCK_FIXTURES / "metrics.json"
    )
    return metrics if isinstance(metrics, dict) else {}


def marker(rule_id: str) -> str:
    return f"<!-- minny:remediation:{uuid.uuid5(MARKER_NAMESPACE, rule_id)} -->"


def branch_for(proposal: dict) -> str:
    """Deterministic, and it changes when the rule text changes.

    Same rule, same branch, so a retry after a lost response reuses it rather
    than opening a second review. A different `when` clause is a different
    change and gets its own branch.
    """
    digest = hashlib.sha256(
        f"{proposal.get('id')}|{proposal.get('when')}".encode("utf-8")
    ).hexdigest()[:8]
    return f"minny/rule-{str(proposal.get('id') or 'unknown').lower()}-{digest}"


def _yaml_value(value) -> str:
    """Python's `True` is not YAML's `true`, and this block gets committed."""
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def rule_yaml(proposal: dict) -> str:
    """The rule as it would be appended to `detection-rules/rules.yaml`."""
    gate = proposal.get("gate") or {}
    lines = [
        f"- id: {proposal.get('id')}",
        f"  name: {proposal.get('name')}",
        f"  severity: {proposal.get('severity') or 'medium'}",
        f"  proposed_by: {proposal.get('proposed_by') or 'blue_agent'}",
        f"  created_ts: \"{proposal.get('created_ts')}\"",
        f"  when: {proposal.get('when')}",
        f"  explain: \"{proposal.get('explain')}\"",
        "  gate:",
    ]
    for check in ("heldout_detection", "benign_fp_delta", "baseline_window_hits"):
        values = gate.get(check)
        if isinstance(values, dict):
            rendered = ", ".join(f"{k}: {_yaml_value(v)}" for k, v in values.items())
            lines.append(f"    {check}: {{ {rendered} }}")
    lines.append(f"    accepted: {str(bool(gate.get('accepted'))).lower()}")
    return "\n".join(lines)


def _gate_rows(gate: dict) -> list[str]:
    rows = ["| Check | Threshold | Measured | Result |", "|---|---|---|---|"]
    labels = {
        "heldout_detection": ("held out detection", "threshold"),
        "benign_fp_delta": ("benign false positive delta", "budget"),
        "baseline_window_hits": ("hits in the baseline window", "required"),
    }
    for key, (label, bound_key) in labels.items():
        values = gate.get(key)
        if not isinstance(values, dict):
            continue
        bound = values.get(bound_key)
        measured = values.get("measured")
        passed = "pass" if values.get("pass") else "fail"
        rows.append(f"| {label} | {bound} | {measured} | {passed} |")
    return rows


def build_body(proposal: dict) -> str:
    """The exact body. Assembled from the proposal, the gate and the metrics.

    Everything in it is re-derivable: the rule text, the gate numbers the
    blue agent measured, and the false positive figures from the evaluation
    run named in `metrics.json`. There is no prose here about data nobody can
    re-run.
    """
    rule_id = str(proposal.get("id") or "unknown")
    gate = proposal.get("gate") or {}
    before_after = proposal.get("before_after") or {}
    metrics = _metrics()
    false_positives = metrics.get("false_positives") or {}
    base = config.base_url()

    issue = gap_issue()
    relation = (
        f"Related to #{issue}."
        if issue
        else (
            "No gap issue is tracked for this rule yet, so this pull request "
            "references none rather than an invented number."
        )
    )

    family = proposal.get("evaded_family")
    family_name = proposal.get("evaded_family_name")
    operators = ", ".join(proposal.get("evaded_operators") or []) or "none recorded"

    fp = before_after.get("benign_alerts_per_day") or {}
    detection = before_after.get("family_detection") or {}
    overall = before_after.get("overall_detection") or {}

    body = [
        marker(rule_id),
        "",
        f"## {proposal.get('name') or rule_id}",
        "",
        f"Proposed by the blue agent after a red team variant evaded the shipped "
        f"detector. {relation} Merging this is a human decision and nothing in "
        f"Minny merges it automatically.",
        "",
        "### What evaded detection",
        "",
        f"- Family: `{family}` {family_name or ''}".rstrip(),
        f"- Operators: {operators}",
        f"- Rationale: {proposal.get('rationale') or 'not recorded'}",
        "",
        "### The rule",
        "",
        "```yaml",
        rule_yaml(proposal),
        "```",
        "",
        "### Gate results",
        "",
        *_gate_rows(gate),
        "",
        f"Accepted by the gate: **{str(bool(gate.get('accepted'))).lower()}**.",
    ]

    if gate.get("rejected_reason"):
        body += ["", f"Rejection reason: {gate['rejected_reason']}"]

    body += [
        "",
        "### False positives",
        "",
        f"- Benign alerts per day, before: {fp.get('before', 'not measured')}",
        f"- Benign alerts per day, after: {fp.get('after', 'not measured')}",
        f"- Benign stream: {false_positives.get('benign_stream', 'not recorded')}",
        f"- Alerts in that stream: {false_positives.get('alerts_total', 'not recorded')}",
        "",
        "### Detection, before and after",
        "",
        f"- This family: {detection.get('before', 'n/a')} to {detection.get('after', 'n/a')}",
        f"- Overall: {overall.get('before', 'n/a')} to {overall.get('after', 'n/a')}",
        f"- Evaluation command: `{metrics.get('command', 'python eval.py --seed 42')}`",
        f"- Rule revision under test: `{metrics.get('rule_revision', 'not recorded')}`",
        "",
        "### Provenance and limits",
        "",
        "- The variant that motivated this rule is synthetic, generated by the "
        "red team and labelled as such in every view.",
        "- Evidence stays in Minny. This body carries line numbers and links, "
        "never log text and nothing from any mailbox.",
        f"- Incidents and evidence: {base}/#monitor",
        f"- Blue agent panel, gate results and the rejected rules beside this "
        f"one: {base}/#blue",
        "- Merging starts verification. A rule is only marked verified after "
        "the merged file is replayed against the held out variants.",
    ]
    return "\n".join(body)


def build_request(proposal: dict) -> dict:
    """Everything that would be sent, as one reviewable object."""
    rule_id = str(proposal.get("id") or "unknown")
    destination = repo()
    return {
        "rule_id": rule_id,
        "title": f"Minny: {proposal.get('name') or rule_id} ({rule_id})",
        "body": build_body(proposal),
        "head": branch_for(proposal),
        "base": destination["base"],
        "path": RULE_FILE,
        "rule_yaml": rule_yaml(proposal),
        "marker": marker(rule_id),
        "repo": destination,
        "related_issue": gap_issue(),
        "merge": "manual, always",
    }


def open_pull_request(rule_id: str) -> dict:
    """Open the review, or produce the exact request instead. Never raises."""
    proposal = load_proposal(rule_id)
    if proposal is None:
        return {
            "state": config.ERROR,
            "ok": False,
            "error_code": "unknown_rule",
            "message": f"no proposal with id {rule_id}",
        }

    gate = proposal.get("gate") or {}
    if not gate.get("accepted"):
        # A rejected rule is a better story than an accepted one and it still
        # does not get a pull request.
        return {
            "state": config.ERROR,
            "ok": False,
            "error_code": "rule_not_accepted",
            "message": (
                f"{rule_id} did not pass the gate, so it does not get a review. "
                f"{gate.get('rejected_reason') or ''}"
            ).strip(),
            "gate": gate,
        }

    request = build_request(proposal)

    try:
        egress.check(request["body"], store=store.read_email_store())
        egress.check(request["title"], store=store.read_email_store())
    except egress.EgressRefused as refused:
        return {
            "state": config.ERROR,
            "ok": False,
            "error_code": f"egress_refused:{refused.reason}",
            "message": (
                "the assembled pull request carried a source record and was "
                "not opened. The rule and the gate results are unaffected."
            ),
        }

    destination = request["repo"]
    if not destination["configured"] and config.should_attempt_live(config.GITHUB_PR):
        return _artifact(
            request,
            state=config.ERROR,
            ok=False,
            error_code="repo_not_configured",
            message=(
                "GitHub is connected but no rules repository is selected. Set "
                "MINNY_GITHUB_OWNER and MINNY_GITHUB_REPO."
            ),
        )

    result = client.execute(
        config.GITHUB_PR,
        {
            "owner": destination["owner"],
            "repo": destination["repo"],
            "title": request["title"],
            "body": request["body"],
            "head": request["head"],
            "base": request["base"],
            "draft": False,
        },
        fixture="github_create_a_pull_request.json",
    )

    data = result.data if isinstance(result.data, dict) else {}
    url = data.get("html_url") if result.state == config.CONNECTED else None
    number = data.get("number") if result.state == config.CONNECTED else None

    artifact = _artifact(
        request,
        state=result.state,
        ok=result.ok,
        error_code=result.error_code,
        message=result.message,
        url=url,
        number=number,
    )
    store.record_delivery(
        {
            "capability": config.GITHUB_PR.id,
            "target": rule_id,
            "state": result.state,
            "ok": result.ok,
            "error_code": result.error_code,
            "message": result.message,
            "url": url,
            "detection_unaffected": True,
        }
    )
    store.upsert_pr_artifact(rule_id, artifact)
    return artifact


def _artifact(request: dict, **outcome) -> dict:
    artifact = {
        **request,
        **outcome,
        "created_at": datetime.now().astimezone().isoformat(timespec="seconds"),
    }
    artifact.setdefault("url", None)
    artifact.setdefault("number", None)
    artifact["posted"] = artifact.get("state") == config.CONNECTED and bool(
        artifact.get("ok")
    )
    return artifact


def artifacts() -> dict:
    return store.read_pr_artifacts()
