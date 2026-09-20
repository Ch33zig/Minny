"""Generate the labeled variant set (milestone M4).

    python -m minny.redteam.generate --seed 42 --count 200

Writes `data/variants.json` (an array of variant labels in the shape of
00-CONTRACTS.md section 8, each carrying the lines it rendered) plus
`data/variants_rejected.json` for anything the critic turned down.

Families and personas are cycled rather than sampled, so a run of 200 covers
all twelve combinations evenly instead of leaving the eval to explain a thin
cell. Everything downstream of the seed is deterministic: the same command
produces byte-identical files on any machine, with no API key.
"""

from __future__ import annotations

import argparse
import json
import random
from datetime import datetime
from collections import Counter
from pathlib import Path

from minny import observability as obs
from minny import paths
from minny.parser import parse_line
from minny.redteam import plan as planning
from minny.redteam.catalog import load_catalog, load_size_table
from minny.redteam.critic import review
from minny.redteam.families import FAMILIES, build_steps
from minny.redteam.operators import OPERATORS
from minny.redteam.render import FIRST_INJECTED_LINE, SizeTable, render

FAMILY_IDS: tuple[str, ...] = tuple(FAMILIES)


def _variant_label(plan, lines, report) -> dict:
    """The contract's section 8 shape, plus the lines and the extra context.

    The extra fields are additive on purpose: the eval needs the IPs to score
    attribution, and D's judge panel needs to know which planner produced a
    variant before it puts a synthetic badge on screen.
    """
    return {
        "variant_id": plan.variant_id,
        "seed": plan.seed,
        "family": plan.family,
        "family_name": plan.family_name,
        "persona": plan.persona,
        "operators": list(plan.operators),
        "attacker": plan.attacker,
        "attacker_ip": plan.attacker_ip,
        "victim": plan.victim,
        "victim_ip": plan.victim_ip,
        "takeover_ip": plan.takeover_ip,
        "target": plan.target,
        "post_id": plan.post_id,
        "param_style": plan.param_style,
        "planner": plan.planner,
        "injected_lines": [line.line for line in lines],
        "first_malicious_line": lines[0].line if lines else None,
        "first_malicious_ts": lines[0].ts.isoformat() if lines else None,
        "last_malicious_ts": lines[-1].ts.isoformat() if lines else None,
        "critic": report.to_json(),
        "lines": [
            {
                "line": line.line,
                "raw": line.raw,
                "ts": line.ts.isoformat(),
                "kind": line.kind,
                "phase": line.phase,
            }
            for line in lines
        ],
    }


def generate_one(
    *,
    seed: int,
    index: int,
    family: str,
    persona: str,
    proposal: dict | None = None,
    first_line: int = FIRST_INJECTED_LINE,
    derive_operators: bool = True,
    start: datetime | None = None,
    catalog=None,
    size_table: SizeTable | None = None,
) -> dict:
    """Plan, render and critique exactly one variant.

    The batch generator and the judge panel both come through here, so a
    variant built live from a judge's dropdowns is the same object, through
    the same critic, as one from `--seed 42`. A second path would be a second
    set of bugs, and the one nobody exercises is the one on stage.

    `start` overrides the planner's seeded placement in March. The judge panel
    needs it: a variant dated behind a running replay's cursor is accepted by
    the queue and then never emitted, because its moment has already passed.
    """
    catalog = catalog if catalog is not None else load_catalog()
    size_table = size_table if size_table is not None else SizeTable(load_size_table())

    # Three stages, three spans. Planning can reach an API, rendering is
    # pure CPU and the critic replays what it just built, so one span across
    # all of it would average a network call into a loop and hide whichever
    # one is actually slow.
    with obs.span("redteam.generate_one", family=family, persona=persona) as active:
        with obs.span("experiment.plan", llm=bool(proposal)):
            plan = planning.plan_variant(
                index=index,
                seed=seed,
                family=family,
                persona=persona,
                catalog=catalog,
                proposal=proposal,
                derive_operators=derive_operators,
            )
        rng = random.Random(planning.stream_seed(seed, index, family, "render"))
        with obs.span("telemetry.compile") as compile_span:
            lines = render(
                build_steps(plan),
                catalog=catalog,
                size_table=size_table,
                start=start or plan.start_ts,
                first_line=first_line,
                rng=rng,
                business_hours="business_hours" in plan.operators,
            )
            compile_span.set_data("lines", len(lines))
        with obs.span("telemetry.validate") as critic_span:
            report, _events = review(
                lines, plan, catalog=catalog, size_table=size_table
            )
            critic_span.set_data("accepted", bool(getattr(report, "accepted", False)))
        active.update(
            variant_id=plan.variant_id,
            lines=len(lines),
            accepted=bool(getattr(report, "accepted", False)),
        )
        return _variant_label(plan, lines, report)


def generate(
    *,
    seed: int,
    count: int,
    planner: str = "deterministic",
    derive_operators: bool = True,
    max_attempts: int | None = None,
) -> tuple[list[dict], list[dict]]:
    catalog = load_catalog()
    size_table = SizeTable(load_size_table())
    use_llm = planner == "llm" or (
        planner == "auto" and planning.anthropic_available()
    )
    if planner == "llm" and not planning.anthropic_available():
        raise SystemExit(
            "--planner llm needs ANTHROPIC_API_KEY. The deterministic planner "
            "is the default and needs nothing."
        )
    cache: dict = {}

    accepted: list[dict] = []
    rejected: list[dict] = []
    next_line = FIRST_INJECTED_LINE
    attempts = max_attempts if max_attempts is not None else count * 2

    with obs.span("redteam.generate", count=count, planner=planner) as batch:
        for attempt in range(1, attempts + 1):
            if len(accepted) >= count:
                break
            family = FAMILY_IDS[(attempt - 1) % len(FAMILY_IDS)]
            persona = planning.PERSONAS[(attempt - 1) % len(planning.PERSONAS)]

            proposal = (
                planning.propose_parameters(
                    family=family, persona=persona, catalog=catalog, cache=cache
                )
                if use_llm
                else None
            )
            label = generate_one(
                seed=seed,
                index=attempt,
                family=family,
                persona=persona,
                proposal=proposal,
                first_line=next_line,
                derive_operators=derive_operators,
                catalog=catalog,
                size_table=size_table,
            )
            if label["critic"]["accepted"]:
                accepted.append(label)
                # Only accepted variants consume IDs. A rejected one is never
                # injected, so reserving a block for it would leave holes the
                # eval would have to explain.
                next_line += len(label["injected_lines"])
            else:
                label["injected_lines"] = []
                rejected.append(label)

        batch.update(accepted=len(accepted), rejected=len(rejected))
    return accepted, rejected


def blind_sample(
    variants: list[dict], *, seed: int, synthetic: int, real: int
) -> tuple[list[str], list[dict]]:
    """Mix synthetic lines into real ones and sort by time.

    The answer key is returned separately so the sample can be read without
    it. This is the check that decides whether the corpus is worth anything:
    if the synthetic lines are pickable by size, spelling or user/IP pairing,
    the renderer is wrong and the eval numbers measure the renderer's tells
    rather than the detector's reach.
    """
    import pandas as pd

    rng = random.Random(seed)
    pool = [line for variant in variants for line in variant["lines"]]
    picked = rng.sample(pool, min(synthetic, len(pool)))

    frame = pd.read_parquet(
        paths.require(paths.events_path()), columns=["line", "raw", "ts"]
    )
    march = frame[frame["ts"] >= "2026-03-01"]
    rows = march.sample(n=real, random_state=seed)

    entries = [
        {"raw": row.raw, "synthetic": False, "id": int(row.line)}
        for row in rows.itertuples()
    ] + [
        {"raw": line["raw"], "synthetic": True, "id": line["line"]}
        for line in picked
    ]
    # Sort on the instant written in the line, not on the parquet `ts`
    # column. events.parquet stores the timestamp in America/New_York, which
    # for a date before 8 March renders an hour earlier than the text of the
    # same line; mixing the two sort keys put the sample slightly out of
    # order, and an ordering artifact in a blind sample points at whichever
    # line it lands next to.
    for entry in entries:
        entry["ts"] = parse_line(entry["id"], entry["raw"]).ts.isoformat()
    entries.sort(key=lambda entry: (entry["ts"][:19], entry["id"]))

    return [entry["raw"] for entry in entries], entries


def summarize(accepted: list[dict], rejected: list[dict]) -> str:
    by_family = Counter(v["family"] for v in accepted)
    by_persona = Counter(v["persona"] for v in accepted)
    by_operator = Counter(op for v in accepted for op in v["operators"])
    reasons = Counter(
        (v["critic"]["rejected_reason"] or "").split(":")[0] for v in rejected
    )

    out = [
        f"accepted   {len(accepted)}",
        f"rejected   {len(rejected)}",
        f"lines      {sum(len(v['injected_lines']) for v in accepted)}",
        "by family  " + ", ".join(f"{k}={by_family[k]}" for k in sorted(by_family)),
        "by persona " + ", ".join(f"{k}={by_persona[k]}" for k in sorted(by_persona)),
        "by operator",
    ]
    for name in OPERATORS:
        out.append(f"    {name:<20} {by_operator[name]}")
    if rejected:
        out.append("rejections")
        for reason, n in reasons.most_common():
            out.append(f"    {reason:<20} {n}")
    return "\n".join(out)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--count", type=int, default=200)
    parser.add_argument("--out", default=None, help="defaults to the data dir")
    parser.add_argument(
        "--planner",
        choices=("deterministic", "llm", "auto"),
        default="deterministic",
        help="auto uses Claude when ANTHROPIC_API_KEY is set, else the seed",
    )
    parser.add_argument(
        "--declare-requested",
        action="store_true",
        help="declare the operators that were asked for rather than the ones "
        "the plan actually carries: a deliberately faulty generator, for "
        "watching the critic's sixth check fire on real output",
    )
    parser.add_argument(
        "--blind-check",
        type=int,
        default=0,
        metavar="N",
        help="also write a blind realism sample of N synthetic lines mixed "
        "into real March traffic",
    )
    args = parser.parse_args()

    accepted, rejected = generate(
        seed=args.seed,
        count=args.count,
        planner=args.planner,
        derive_operators=not args.declare_requested,
    )

    out_dir = Path(args.out) if args.out else paths.data_dir()
    out_dir.mkdir(parents=True, exist_ok=True)
    variants_path = out_dir / "variants.json"
    variants_path.write_text(json.dumps(accepted, indent=2), encoding="utf-8")
    rejected_path = out_dir / "variants_rejected.json"
    rejected_path.write_text(json.dumps(rejected, indent=2), encoding="utf-8")

    print(summarize(accepted, rejected))
    print(f"wrote      {variants_path}")
    print(f"wrote      {rejected_path}")

    if args.blind_check:
        lines, key = blind_sample(
            accepted, seed=args.seed, synthetic=args.blind_check, real=40
        )
        sample_path = out_dir / "blind_sample.txt"
        key_path = out_dir / "blind_sample_key.json"
        sample_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        key_path.write_text(json.dumps(key, indent=2), encoding="utf-8")
        print(f"wrote      {sample_path} and its answer key")


if __name__ == "__main__":
    main()
