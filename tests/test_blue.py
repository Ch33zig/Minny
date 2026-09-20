"""The blue agent and the gate that decides whether it was any good (M6).

Four of these are the reason the milestone exists.

The `csrf` rule **parses**. That matters: it is rejected by the gate, on
evidence, and not by a grammar that happened to be too narrow to express it.
It reproduces the March incident exactly and it catches nothing the red team
generates, which is the difference between detecting an attack and
remembering one.

An accepted rule is **silent on the baseline window**. Those seven months are
the definition of normal for every baseline the detector uses, so a rule
firing there is a false positive by construction, and the check runs against
the file the detector actually loads rather than against a copy.

The held-out set is **generated from seeds and personas the proposer never
saw**. Without that the first gate check measures nothing at all.

A rule that does not parse is **rejected before the gate runs**. The test
makes the generator explode if it is reached, because "rejected early" is a
claim about control flow and not about a verdict.
"""

from __future__ import annotations

import json

import pandas as pd
import pytest
import yaml

from minny import paths
from minny.baselines.model import Baselines
from minny.blue import evidence as evidence_module, gate, heldout, propose as proposer
from minny.blue import run as runner
from minny.build_events import BASELINE_CUTOFF
from minny.detect import rules as dsl
from minny.detect.events import from_frame
from minny.eval import stream
from minny.redteam.catalog import INCIDENT_LINES, load_catalog, load_size_table
from minny.redteam.render import SizeTable

needs_dataset = pytest.mark.skipif(
    not paths.events_path().exists() or not paths.baselines_path().exists(),
    reason="set MINNY_DATA_DIR to the main checkout's data directory",
)

pytestmark = needs_dataset

# Four held-out variants and a thin benign stream. The gate's real numbers
# come from `python -m minny.blue.run`; these tests check that the machinery
# answers the right question, which four variants are enough to show.
HELDOUT = 4
BENIGN_SAMPLE = 1500


@pytest.fixture(scope="module")
def baselines():
    return Baselines.load(paths.baselines_path())


@pytest.fixture(scope="module")
def frame():
    return pd.read_parquet(paths.events_path())


@pytest.fixture(scope="module")
def benign(frame):
    march = frame[frame["ts"] >= pd.Timestamp(BASELINE_CUTOFF)]
    return evidence_module.sample(stream.benign_events(march), BENIGN_SAMPLE)


@pytest.fixture(scope="module")
def variants():
    return evidence_module.load_variants()


@pytest.fixture(scope="module")
def catalog():
    return load_catalog()


@pytest.fixture(scope="module")
def size_table():
    return SizeTable(load_size_table())


@pytest.fixture(scope="module")
def evidence_for(variants, benign, frame, baselines):
    metrics = evidence_module.load_metrics()

    def build(operator):
        return evidence_module.build(
            operator=operator,
            variants=variants,
            benign=benign,
            frame=frame,
            baselines=baselines,
            metrics=metrics,
        )

    return build


def held_out(operator, catalog, size_table, count=HELDOUT):
    return heldout.generate(
        operator=operator,
        seed=42,
        count=count,
        catalog=catalog,
        size_table=size_table,
    )


def incident_events(frame):
    return list(from_frame(frame[frame["line"].isin(sorted(INCIDENT_LINES))]))


# ------------------------------------------------------- the planned rejection


def test_the_csrf_rule_parses(evidence_for):
    """It has to reach the gate to be rejected by it.

    Depth 2 and five nodes, well inside the caps, using the `query` field and
    the `contains` operator the grammar carries for exactly this rule.
    """
    proposal = proposer.propose(
        operator="param_rename",
        evidence=evidence_for("param_rename"),
        baselines=None,
        seed=42,
    )
    assert proposal.when == 'template == "/intranet/forum/new" AND query contains "csrf"'
    assert proposal.parse.ok
    assert proposal.parse.depth == 2
    assert proposal.parse.nodes == 5


def test_the_csrf_rule_reproduces_the_march_incident(frame, baselines):
    """The rule works. That is what makes the rejection interesting."""
    ruleset = gate.ruleset_for(
        {
            "id": "R900",
            "name": "csrf payload",
            "severity": "high",
            "when": 'template == "/intranet/forum/new" AND query contains "csrf"',
            "explain": "{user} posted {template} with a csrf parameter.",
        }
    )
    lines = sorted(
        {
            line
            for event in incident_events(frame)
            for alert in ruleset.evaluate(event, baselines, ())
            for line in alert["evidence_lines"]
        }
    )
    assert lines == [168330, 168331]


def test_the_csrf_rule_fails_the_held_out_check(
    evidence_for, benign, baselines, catalog, size_table
):
    """Perfect on the incident it was written from, zero on anything new."""
    proposal = proposer.propose(
        operator="param_rename",
        evidence=evidence_for("param_rename"),
        baselines=baselines,
        seed=42,
    )
    document = proposal.spec.document("R900", "2026-09-20T02:31:00-04:00")
    ruleset = gate.ruleset_for(document)

    variants = held_out("param_rename", catalog, size_table)
    assert variants, "the held-out generator produced nothing to score"
    rows = [
        gate.score_variant(variant, benign, baselines, ruleset, "R900")
        for variant in variants
    ]

    check = gate.check_heldout(rows, evaded_signal="S5")
    assert check["caught"] == 0
    assert check["measured"] == 0.0
    assert check["pass"] is False
    # Not a near miss and not an accident of sampling: the string the rule
    # keys on is absent from every line these variants rendered.
    assert not any("csrf" in line["raw"] for v in variants for line in v["lines"])


# ------------------------------------------------------ the accepted rule


def accepted_rules() -> list:
    document = yaml.safe_load(paths.rules_path().read_text(encoding="utf-8"))
    return [
        entry
        for entry in (document or [])
        if isinstance(entry, dict)
        and (entry.get("gate") or {}).get("accepted") is True
    ]


def test_the_accepted_rule_is_silent_on_the_baseline_window(frame, baselines):
    """157,818 events the baselines were fitted on, and not one hit.

    Run against detection-rules/rules.yaml itself. A rule that passed the
    gate and then reached the file in a different shape would be a rule
    nobody validated.
    """
    rules = accepted_rules()
    assert rules, "no accepted rule in detection-rules/rules.yaml"

    events = list(from_frame(frame[frame["ts"] < pd.Timestamp(BASELINE_CUTOFF)]))
    assert len(events) == 157_818

    for document in rules:
        ruleset = gate.ruleset_for(document)
        assert ruleset.rules[0].ok, ruleset.errors
        check = gate.check_baseline(document["id"], events, baselines, ruleset)
        assert check["measured"] == 0, f"{document['id']} fired on {check['lines']}"
        assert check["pass"] is True


def test_the_accepted_rule_catches_held_out_variants(
    evidence_for, benign, baselines, catalog, size_table
):
    proposal = proposer.propose(
        operator="slow_guess",
        evidence=evidence_for("slow_guess"),
        baselines=baselines,
        seed=42,
    )
    assert proposal.parse.ok
    document = proposal.spec.document("R901", "2026-09-20T02:14:00-04:00")
    ruleset = gate.ruleset_for(document)

    variants = held_out("slow_guess", catalog, size_table)
    assert variants
    rows = [
        gate.score_variant(variant, benign, baselines, ruleset, "R901")
        for variant in variants
    ]
    check = gate.check_heldout(rows, evaded_signal="S3")

    assert check["pass"] is True
    assert check["measured"] >= gate.HELDOUT_THRESHOLD
    # The signal the operator switched off stayed off. The rule is new
    # evidence on those variants rather than the old signal under a new name.
    assert all("S3" not in row["signals_before"] for row in rows)


# --------------------------------------------------------- the held-out split


def test_the_held_out_set_uses_different_seeds(variants, catalog, size_table):
    held = held_out("slow_guess", catalog, size_table, count=6)
    training = evidence_module.training_variants(variants, operator="slow_guess")

    training_seeds = {variant["seed"] for variant in training}
    held_seeds = {variant["seed"] for variant in held}
    assert training_seeds == {42}
    assert held_seeds
    assert not (held_seeds & training_seeds)
    # And it says so rather than trusting the arithmetic.
    heldout.assert_disjoint(held, training_seeds)
    with pytest.raises(ValueError):
        heldout.assert_disjoint(held, held_seeds)


def test_the_held_out_set_uses_different_personas(variants, catalog, size_table):
    held = held_out("slow_guess", catalog, size_table, count=6)
    training = evidence_module.training_variants(variants, operator="slow_guess")

    assert {v["persona"] for v in training} <= set(evidence_module.TRAINING_PERSONAS)
    assert {v["persona"] for v in held} <= set(evidence_module.HELDOUT_PERSONAS)
    assert not set(evidence_module.TRAINING_PERSONAS) & set(
        evidence_module.HELDOUT_PERSONAS
    )


def test_held_out_lines_never_collide_with_the_training_batch(
    variants, catalog, size_table
):
    held = held_out("param_rename", catalog, size_table, count=6)
    training_lines = {line for v in variants for line in v["injected_lines"]}
    held_lines = {line for v in held for line in v["injected_lines"]}

    assert held_lines
    assert not (held_lines & training_lines)
    assert min(held_lines) >= heldout.HELDOUT_FIRST_LINE


# ------------------------------------------------- rejected before the gate


def test_a_rule_that_does_not_parse_is_rejected_before_the_gate(
    monkeypatch, evidence_for, benign, baselines, frame
):
    """No held-out set is generated and nothing is replayed.

    The generator is replaced with a landmine. If the runner reaches it, the
    rule reached the gate, and the claim that a parse failure is the cheapest
    rejection in the system is false.
    """
    broken = proposer.RuleSpec(
        name="a rule nobody can read",
        severity="high",
        explain="{user} did something.",
        predicates=(
            proposer.Predicate(kind="field", field="hostname", op="==", value="x"),
        ),
        rationale="deliberately off-grammar",
        strategy="broken",
    )

    def fake_propose(**kwargs):
        return proposer.Proposal(
            operator=kwargs["operator"],
            spec=broken,
            parse=dsl.parse_expression(broken.when),
            in_sample={"parses": False},
        )

    def landmine(**kwargs):
        raise AssertionError("the gate ran on a rule that does not parse")

    monkeypatch.setattr(runner.proposer, "propose", fake_propose)
    monkeypatch.setattr(runner.heldout, "generate", landmine)

    entry, document = runner.propose_one(
        operator="slow_guess",
        rule_id="R902",
        seed=42,
        count=HELDOUT,
        planner="deterministic",
        variants=evidence_module.load_variants(),
        benign=benign,
        baseline_events=[],
        march_events=[],
        frame=frame,
        baselines=baselines,
        metrics=None,
        days=31,
        threshold=gate.HELDOUT_THRESHOLD,
        budget=gate.FP_BUDGET,
        echo=lambda *args, **kwargs: None,
    )

    assert document is None
    assert entry["status"] == "rejected"
    assert entry["parse"]["ok"] is False
    assert "hostname" in entry["parse"]["error"]
    for name in ("heldout_detection", "benign_fp_delta", "baseline_window_hits"):
        check = entry["gate"][name]
        # A measurement that was never taken is null, which is a different
        # statement from a measured zero.
        assert check["measured"] is None
        assert check["pass"] is False
    assert "does not parse" in entry["gate"]["rejected_reason"]


# ------------------------------------------------------------ the proposer


def test_the_proposer_is_deterministic(evidence_for, baselines):
    evidence = evidence_for("slow_guess")
    first = proposer.propose(
        operator="slow_guess", evidence=evidence, baselines=baselines, seed=42
    )
    second = proposer.propose(
        operator="slow_guess", evidence=evidence, baselines=baselines, seed=42
    )
    assert first.when == second.when
    assert first.spec.proposer == "deterministic"
    assert first.spec.derivation == second.spec.derivation


def test_the_proposal_stays_inside_the_caps(evidence_for, baselines):
    for operator in ("slow_guess", "param_rename"):
        proposal = proposer.propose(
            operator=operator,
            evidence=evidence_for(operator),
            baselines=baselines,
            seed=42,
        )
        assert proposal.parse.ok, proposal.parse.error
        assert proposal.parse.depth <= dsl.MAX_DEPTH
        assert proposal.parse.nodes <= dsl.MAX_NODES


def test_the_count_predicate_is_evaluated_last(evidence_for, baselines):
    """Short-circuiting is why the gate can afford to replay seven months.

    The expression means the same thing in either order. In this one the
    cheap comparison is what most events fail, so the rolling history is
    never walked for them.
    """
    proposal = proposer.propose(
        operator="slow_guess",
        evidence=evidence_for("slow_guess"),
        baselines=baselines,
        seed=42,
    )
    assert proposal.when.index("ip_owner") < proposal.when.index("count(")


def test_the_model_path_is_gated_on_the_api_key(monkeypatch, evidence_for, baselines):
    """No key, no network, and the seeded proposal still comes out.

    The whole command has to run on a machine with no ANTHROPIC_API_KEY, so
    the seeded proposer is the default path rather than a fallback bolted on
    afterwards, and `auto` degrades to it silently.
    """
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    assert proposer.anthropic_available() is False

    evidence = evidence_for("slow_guess")
    auto = proposer.propose(
        operator="slow_guess",
        evidence=evidence,
        baselines=baselines,
        seed=42,
        planner="auto",
    )
    assert auto.spec.proposer == "deterministic"
    assert auto.parse.ok

    with pytest.raises(SystemExit, match="ANTHROPIC_API_KEY"):
        proposer.propose(
            operator="slow_guess",
            evidence=evidence,
            baselines=baselines,
            seed=42,
            planner="llm",
        )


def test_proposed_parameters_are_checked_against_the_grammar(evidence_for, baselines):
    """Parameters come back as data and are assembled here, never executed.

    A predicate the grammar has no shape for is refused while it is still a
    mapping. A field name it does not know survives assembly and dies at the
    parser, which is the rejection the gate never has to pay for.
    """
    fallback = proposer.propose(
        operator="slow_guess",
        evidence=evidence_for("slow_guess"),
        baselines=baselines,
        seed=42,
    ).spec

    with pytest.raises(proposer.ProposalError):
        proposer.spec_from_mapping(
            {"predicates": [{"kind": "regex", "value": ".*"}]},
            strategy="auth_burst",
            fallback=fallback,
        )

    spec = proposer.spec_from_mapping(
        {
            "name": "invented field",
            "severity": "high",
            "explain": "{user}",
            "rationale": "why",
            "join": "AND",
            "predicates": [
                {"kind": "field", "field": "hostname", "op": "==", "value": "x"}
            ],
        },
        strategy="auth_burst",
        fallback=fallback,
    )
    assert spec.proposer == "llm"
    assert dsl.parse_expression(spec.when).ok is False


def test_an_unknown_operator_names_the_ones_that_exist(evidence_for, baselines):
    with pytest.raises(ValueError, match="slow_guess"):
        proposer.propose(
            operator="no_cleanup",
            evidence=evidence_for("slow_guess"),
            baselines=baselines,
            seed=42,
        )


# ------------------------------------------------------- the published file


def test_rule_ids_continue_past_what_the_file_already_holds():
    existing = [{"id": "R001"}, {"id": "R007"}, {"id": "not a rule"}]
    assert runner.next_rule_id(existing, set()) == "R008"
    assert runner.next_rule_id(existing, {"R008"}) == "R009"


def test_the_same_rule_is_never_appended_twice(tmp_path):
    target = tmp_path / "rules.yaml"
    target.write_text("# header\n", encoding="utf-8")
    document = {
        "id": "R002",
        "name": "n",
        "severity": "high",
        "when": "ip_owner != $u AND count(status=401, user=$u, window=24h) >= 3",
        "explain": "x",
    }
    runner.append_rule(target, document)
    loaded = runner.load_rules(target)

    assert runner.already_present(loaded, document["when"]) == "R002"
    assert runner.already_present(loaded, "status == 200") is None
    assert "# header" in target.read_text(encoding="utf-8")


def test_the_published_proposals_carry_one_of_each():
    """What GET /api/blue/proposals serves, and what the mock demo shows."""
    fixture = runner.FIXTURE_PATH / "blue_proposals.json"
    proposals = json.loads(fixture.read_text(encoding="utf-8"))

    assert isinstance(proposals, list)
    statuses = {entry["status"] for entry in proposals}
    assert statuses == {"accepted", "rejected"}

    accepted = next(e for e in proposals if e["status"] == "accepted")
    rejected = next(e for e in proposals if e["status"] == "rejected")

    assert accepted["gate"]["accepted"] is True
    assert accepted["gate"]["heldout_detection"]["pass"] is True
    assert accepted["gate"]["benign_fp_delta"]["measured"] == 0
    assert accepted["gate"]["baseline_window_hits"]["measured"] == 0
    assert accepted["appended_to"] == runner.RULES_FILE

    assert "csrf" in rejected["when"]
    assert rejected["parse"]["ok"] is True
    assert rejected["gate"]["heldout_detection"]["pass"] is False
    assert rejected["gate"]["benign_fp_delta"]["pass"] is True
    assert rejected["gate"]["baseline_window_hits"]["pass"] is True
    assert rejected["appended_to"] is None
    # The rejection has to say which check failed and why, because the
    # rejections are the part of this that proves the gate is not a stamp.
    assert "Held-out detection" in rejected["gate"]["rejected_reason"]


def test_every_proposal_reports_what_it_was_measured_on():
    fixture = runner.FIXTURE_PATH / "blue_proposals.json"
    for entry in json.loads(fixture.read_text(encoding="utf-8")):
        held = entry["heldout"]
        assert held["variants"] == entry["gate"]["heldout_detection"]["variants"]
        assert 42 not in held["seeds"]
        assert set(held["personas"]) <= set(evidence_module.HELDOUT_PERSONAS)
        assert entry["evidence"]["training_seeds"] == [42]
        assert entry["evidence"]["training_personas"] == list(
            evidence_module.TRAINING_PERSONAS
        )
