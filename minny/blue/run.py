"""The blue agent, end to end (milestone M6).

    python -m minny.blue.run --seed 42

Reads what the red team got away with, proposes one rule per evaded operator,
validates each against the three-part gate, appends the ones that pass to
`detection-rules/rules.yaml` and writes every verdict to
`data/blue_proposals.json` for `GET /api/blue/proposals`.

Two proposals come out of a default run and they are meant to disagree.

`slow_guess` switched S3 off completely: 0 of 46 variants carrying it against
54 of 54 in the matched control. The rule proposed against it counts failed
logins per day from a host the account does not own, and it passes all three
checks.

`param_rename` gets the rule a defender writes on the day: a substring match
on the literal payload the March attacker used. It parses, it reproduces the
real incident exactly, it is silent on seven months of baseline traffic, and
it catches nothing the red team generates, because every `param_rename`
variant renames the parameter it keys on. It is rejected on the first check
and the rejection is the point.

Nothing here needs an API key. The proposer is seeded and deterministic by
default, and `--planner auto` hands the parameter choice to Claude when
ANTHROPIC_API_KEY is set, exactly as the red team's planner does.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path

import pandas as pd
import yaml

from minny import paths
from minny.baselines.model import Baselines
from minny.blue import evidence as evidence_module, gate, heldout, propose as proposer
from minny.build_events import BASELINE_CUTOFF
from minny.detect.events import from_frame
from minny.eval import stream
from minny.redteam.catalog import INCIDENT_LINES
from minny.redteam.families import FAMILIES

# The two the evaluation pointed at, in the order the demo tells them.
DEFAULT_OPERATORS: tuple[str, ...] = ("slow_guess", "param_rename")

FIXTURE_PATH = Path(__file__).resolve().parent.parent.parent / "fixtures" / "mock"

_RULE_ID = re.compile(r"^R(\d+)$")

# Recorded in the proposal rather than the absolute path the command
# happened to resolve. The file is committed, so its repository path is the
# same fact on every machine and a local one is noise in a shared fixture.
RULES_FILE = "detection-rules/rules.yaml"


def now_ts() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


# ------------------------------------------------------------- rules.yaml


def load_rules(path: Path) -> list:
    if not path.exists():
        return []
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    return document if isinstance(document, list) else []


def next_rule_id(documents: list, taken: set) -> str:
    """One past the highest id in the file, skipping ids claimed this run."""
    numbers = [0]
    for entry in documents:
        match = _RULE_ID.match(str((entry or {}).get("id", "")))
        if match:
            numbers.append(int(match.group(1)))
    for entry in taken:
        match = _RULE_ID.match(str(entry))
        if match:
            numbers.append(int(match.group(1)))
    return f"R{max(numbers) + 1:03d}"


def already_present(documents: list, when: str) -> str | None:
    """The id of a rule that already says this, if the file holds one.

    The file is append-only and the proposer is deterministic, so running the
    command twice would otherwise write the same rule under a second id and
    the detector would raise every finding twice.
    """
    for entry in documents:
        if isinstance(entry, dict) and str(entry.get("when", "")).strip() == when.strip():
            return str(entry.get("id"))
    return None


def append_rule(path: Path, document: dict) -> None:
    """Append one entry, leaving everything already in the file untouched.

    Appending text rather than re-serialising the document keeps the file's
    header comments, which explain to the next reader what the grammar is and
    why nothing in it is ever executed.
    """
    body = yaml.safe_dump(
        [document], sort_keys=False, allow_unicode=True, width=10_000
    )
    with open(path, "a", encoding="utf-8") as handle:
        handle.write("\n" + body)


# ------------------------------------------------------------- one proposal


def family_of(variants: list) -> tuple[str | None, list]:
    counts = Counter(variant["family"] for variant in variants)
    if not counts:
        return None, []
    return counts.most_common(1)[0][0], sorted(counts)


def record(
    *,
    rule_id: str,
    operator: str,
    proposal: proposer.Proposal,
    evidence,
    verdict: gate.GateResult,
    heldout_variants: list,
    created_ts: str,
    appended_to: str | None,
) -> dict:
    """One entry of blue_proposals.json.

    The keys D's proposal card already renders come first and keep their
    names. Everything after them is additive: the provenance of the evidence,
    the held-out set's shape, and the per-variant rows behind the gate's
    percentages, so a reader can check a number rather than take it.
    """
    spec = proposal.spec
    family, families = family_of(list(evidence.variants))
    return {
        "id": rule_id,
        "name": spec.name,
        "severity": spec.severity,
        "proposed_by": "blue_agent",
        "created_ts": created_ts,
        "evaded_family": family,
        "evaded_family_name": FAMILIES.get(family) if family else None,
        "evaded_families": families,
        "evaded_operator": operator,
        "evaded_operators": [operator],
        "rationale": spec.rationale,
        "when": proposal.when,
        "explain": spec.explain,
        "parse": proposal.parse.as_dict(),
        "proposer": spec.proposer,
        "strategy": spec.strategy,
        "derivation": spec.derivation,
        "in_sample": proposal.in_sample,
        "evidence": evidence.summary(),
        "heldout": heldout.summary(heldout_variants, operator),
        "gate": verdict.to_json(),
        "before_after": verdict.before_after,
        "real_incident": verdict.real_incident,
        "status": "accepted" if verdict.accepted else "rejected",
        "appended_to": appended_to,
        "pull_request": None,
        "rows": verdict.rows,
    }


def propose_one(
    *,
    operator: str,
    rule_id: str,
    seed: int,
    count: int,
    planner: str,
    variants: list,
    benign: list,
    baseline_events: list,
    march_events: list,
    frame,
    baselines,
    metrics: dict | None,
    days: int,
    threshold: float,
    budget: int,
    echo=print,
) -> tuple[dict, dict | None]:
    """Evidence, proposal, held-out set, gate. Returns the record and the rule."""
    evidence = evidence_module.build(
        operator=operator,
        variants=variants,
        benign=benign,
        frame=frame,
        baselines=baselines,
        metrics=metrics,
    )
    echo(
        f"evidence    {operator}: {len(evidence.variants)} training variants "
        f"from {', '.join(evidence.personas)} at seed "
        f"{', '.join(str(s) for s in evidence.seeds)}, "
        f"{len(evidence.benign)} benign events sampled"
    )

    proposal = proposer.propose(
        operator=operator,
        evidence=evidence,
        baselines=baselines,
        seed=seed,
        planner=planner,
    )
    echo(f"proposed    {rule_id} ({proposal.spec.proposer}): {proposal.when}")

    created_ts = now_ts()
    if not proposal.parse.ok:
        # Rejected before the gate, which is the cheapest rejection there is.
        # Nothing is replayed and nothing is generated.
        echo(f"rejected    {rule_id} does not parse: {proposal.parse.error}")
        verdict = gate.rejected_at_parse(
            proposal.parse.error, threshold=threshold, budget=budget
        )
        return (
            record(
                rule_id=rule_id,
                operator=operator,
                proposal=proposal,
                evidence=evidence,
                verdict=verdict,
                heldout_variants=[],
                created_ts=created_ts,
                appended_to=None,
            ),
            None,
        )

    held = heldout.generate(operator=operator, seed=seed, count=count)
    heldout.assert_disjoint(held, evidence.seeds)
    echo(
        f"held out    {len(held)} {operator} variants, seeds "
        f"{min(v['seed'] for v in held)}-{max(v['seed'] for v in held)}, "
        f"personas {', '.join(sorted({v['persona'] for v in held}))}"
    )

    document = proposal.spec.document(rule_id, created_ts)
    verdict = gate.run(
        document=document,
        variants=held,
        benign=benign,
        baseline_events=baseline_events,
        baselines=baselines,
        days=days,
        evaded=evidence.suppression,
        march_events=march_events,
        labeled_lines=INCIDENT_LINES,
        threshold=threshold,
        budget=budget,
    )
    checks = verdict.checks
    echo(
        f"gate        held-out {checks['heldout_detection']['measured']:.2f} "
        f"({checks['heldout_detection']['caught']}/"
        f"{checks['heldout_detection']['variants']}), benign delta "
        f"{checks['benign_fp_delta']['measured']}, baseline hits "
        f"{checks['baseline_window_hits']['measured']} -> "
        f"{'accepted' if verdict.accepted else 'rejected'}"
    )
    if not verdict.accepted:
        echo(f"            {verdict.rejected_reason}")

    entry = record(
        rule_id=rule_id,
        operator=operator,
        proposal=proposal,
        evidence=evidence,
        verdict=verdict,
        heldout_variants=held,
        created_ts=created_ts,
        appended_to=None,
    )
    document = dict(document)
    document["gate"] = verdict.to_json()
    return entry, (document if verdict.accepted else None)


# -------------------------------------------------------------- the command


def run(
    *,
    seed: int,
    operators: tuple[str, ...],
    count: int,
    planner: str,
    threshold: float,
    budget: int,
    append: bool,
    echo=print,
) -> list[dict]:
    baselines = Baselines.load(paths.require(paths.baselines_path()))
    frame = pd.read_parquet(paths.require(paths.events_path()))
    cutoff = pd.Timestamp(BASELINE_CUTOFF)
    march = frame[frame["ts"] >= cutoff]
    benign = stream.benign_events(march)
    march_events = stream.march_events(march)
    days = len(stream.days_covered(benign))
    baseline_events = list(from_frame(frame[frame["ts"] < cutoff]))
    echo(
        f"streams     {len(benign):,} benign March events over {days} days, "
        f"{len(baseline_events):,} baseline-window events"
    )

    variants = evidence_module.load_variants()
    metrics = evidence_module.load_metrics()
    rules_path = paths.rules_path()
    existing = load_rules(rules_path)

    proposals: list[dict] = []
    claimed: set = set()
    for operator in operators:
        rule_id = next_rule_id(existing, claimed)
        claimed.add(rule_id)
        entry, document = propose_one(
            operator=operator,
            rule_id=rule_id,
            seed=seed,
            count=count,
            planner=planner,
            variants=variants,
            benign=benign,
            baseline_events=baseline_events,
            march_events=march_events,
            frame=frame,
            baselines=baselines,
            metrics=metrics,
            days=days,
            threshold=threshold,
            budget=budget,
            echo=echo,
        )
        if document is not None:
            twin = already_present(existing, document["when"])
            if twin:
                entry["id"] = twin
                entry["appended_to"] = RULES_FILE
                entry["already_present"] = True
                claimed.discard(rule_id)
                echo(f"rules       {twin} already says this; nothing appended")
            elif append:
                append_rule(rules_path, document)
                existing.append(document)
                entry["appended_to"] = RULES_FILE
                echo(f"rules       appended {document['id']} to {rules_path}")
            else:
                echo(f"rules       {document['id']} accepted, append skipped")
        proposals.append(entry)
    return proposals


def summarize(proposals: list[dict]) -> str:
    out = []
    for entry in proposals:
        checks = entry["gate"]
        out.append(f"{entry['id']} {entry['status']:<9} {entry['when']}")
        for name in ("heldout_detection", "benign_fp_delta", "baseline_window_hits"):
            check = checks[name]
            measured = check.get("measured")
            out.append(
                f"    {name:<22} "
                f"{'n/a' if measured is None else measured} "
                f"{'pass' if check.get('pass') else 'FAIL'}"
            )
        if checks.get("rejected_reason"):
            out.append(f"    reason  {checks['rejected_reason']}")
    return "\n".join(out)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument(
        "--operators",
        default=",".join(DEFAULT_OPERATORS),
        help="comma separated evaded operators to propose against",
    )
    parser.add_argument(
        "--count", type=int, default=40, help="held-out variants per operator"
    )
    parser.add_argument(
        "--planner",
        choices=("deterministic", "llm", "auto"),
        default="deterministic",
        help="auto asks Claude for the parameters when ANTHROPIC_API_KEY is "
        "set, else the seeded proposer",
    )
    parser.add_argument("--threshold", type=float, default=gate.HELDOUT_THRESHOLD)
    parser.add_argument("--budget", type=int, default=gate.FP_BUDGET)
    parser.add_argument("--out", default=None, help="defaults to the data dir")
    parser.add_argument(
        "--no-append",
        action="store_true",
        help="run the gate without writing to detection-rules/rules.yaml",
    )
    parser.add_argument(
        "--no-write",
        action="store_true",
        help="print the verdicts without writing blue_proposals.json",
    )
    parser.add_argument(
        "--no-fixture",
        action="store_true",
        help="skip the copy in fixtures/mock that the mock demo reads",
    )
    args = parser.parse_args(argv)

    proposals = run(
        seed=args.seed,
        operators=tuple(
            name.strip() for name in args.operators.split(",") if name.strip()
        ),
        count=args.count,
        planner=args.planner,
        threshold=args.threshold,
        budget=args.budget,
        append=not args.no_append,
    )

    print()
    print(summarize(proposals))

    if not args.no_write:
        out_dir = Path(args.out) if args.out else paths.data_dir()
        out_dir.mkdir(parents=True, exist_ok=True)
        out_path = out_dir / "blue_proposals.json"
        body = json.dumps(proposals, indent=2)
        out_path.write_text(body, encoding="utf-8")
        print()
        print(f"wrote       {out_path}")
        if not args.no_fixture:
            FIXTURE_PATH.mkdir(parents=True, exist_ok=True)
            fixture = FIXTURE_PATH / "blue_proposals.json"
            fixture.write_text(body, encoding="utf-8")
            print(f"wrote       {fixture}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
