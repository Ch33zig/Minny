"""Guarantees the eval and the judge panel are entitled to rely on.

Three of these are the ones that decide whether the numbers mean anything:
the critic rejects a fabricated size, the critic rejects a declared operator
that is not in the output, and every generated variant parses under the same
parser the real log goes through. If any of them ever goes red, the
per-operator metrics table is measuring something other than what it claims.
"""

from __future__ import annotations

import os
import random
import subprocess
import sys
from dataclasses import replace
from datetime import datetime, timedelta

import pytest

from minny import paths
from minny.parser import parse_line
from minny.redteam import operators as ops
from minny.redteam.catalog import load_catalog, load_size_table
from minny.redteam.critic import review
from minny.redteam.families import FAMILIES, build_steps
from minny.redteam.generate import generate
from minny.redteam.plan import PERSONAS, UNSEEN_IPS, plan_variant, stream_seed
from minny.redteam.render import (
    FIRST_INJECTED_LINE,
    LOG_UTC_OFFSET,
    SizeTable,
    Step,
    format_ts,
    render,
    rewrite,
    schedule,
)

REAL_LINE = (
    "10.0.8.45 - david_m [15/Mar/2026:11:26:59 -0400] "
    '"GET /finance/reports/q1_draft_CONFIDENTIAL.zip HTTP/1.1" 200 8459200'
)

needs_dataset = pytest.mark.skipif(
    not paths.events_path().exists() or not paths.size_table_path().exists(),
    reason="set MINNY_DATA_DIR to the main checkout's data directory",
)


# --------------------------------------------------------------------------
# Rendering, with no dataset needed.
# --------------------------------------------------------------------------


def test_rendered_line_parses_and_keeps_the_skeleton():
    ts = datetime(2026, 3, 20, 14, 5, 9, tzinfo=LOG_UTC_OFFSET)
    raw = rewrite(
        REAL_LINE,
        ip="10.0.5.12",
        user="sarah_j",
        ts=ts,
        path="/dashboard",
        status=200,
        size=2048,
    )
    event = parse_line(FIRST_INJECTED_LINE, raw)

    assert event.ip == "10.0.5.12"
    assert event.user == "sarah_j"
    assert event.base == "/dashboard"
    assert event.size == 2048
    # Inherited from the real line rather than reconstructed.
    assert event.method == "GET"
    assert raw.endswith("HTTP/1.1\" 200 2048")


def test_timestamp_spelling_matches_the_dataset():
    ts = datetime(2026, 3, 15, 11, 26, 59, tzinfo=LOG_UTC_OFFSET)
    assert format_ts(ts) == "15/Mar/2026:11:26:59 -0400"


def test_size_table_rejects_a_size_that_never_occurs():
    table = SizeTable(
        {
            "by_path": {"/api/auth/login": {"401": 88}},
            "variable_size_paths": {"/dashboard": {"200": [2000, 2050, 2100]}},
        }
    )
    assert table.is_consistent("/api/auth/login", 401, 88)
    assert not table.is_consistent("/api/auth/login", 401, 89)
    assert table.is_consistent("/dashboard", 200, 2050)
    assert not table.is_consistent("/dashboard", 200, 2101)
    # An unknown pair is not a free pass.
    assert not table.is_consistent("/dashboard", 500, 1024)


def test_size_table_falls_back_to_the_template():
    """avatar_1042 is the only avatar in the corpus, at 1205 bytes.

    A variant escalating through any other post still needs a size for its
    avatar, and 1205 is the only one the data supports.
    """
    table = SizeTable(
        {
            "by_path": {"/assets/avatar_1042.png": {"200": 1205}},
            "variable_size_paths": {},
        }
    )
    assert table.bounds("/assets/avatar_1067.png", 200) == (1205, 1205)
    assert table.sample("/assets/avatar_1067.png", 200, random.Random(1)) == 1205


def test_schedule_never_goes_backwards_even_with_zero_gaps():
    start = datetime(2026, 3, 10, 9, 0, tzinfo=LOG_UTC_OFFSET)
    stamps = schedule(start, [0, 0, 0, 0])
    assert stamps == sorted(stamps)
    assert len(set(stamps)) == len(stamps)


def test_business_hours_layout_rolls_off_the_weekend():
    # 2026-03-14 is a Saturday.
    start = datetime(2026, 3, 14, 11, 0, tzinfo=LOG_UTC_OFFSET)
    stamps = schedule(start, [0, 3600, 3600], business_hours=True, rng=random.Random(3))
    for stamp in stamps:
        assert stamp.weekday() < 5
        assert ops.BUSINESS_START <= stamp.time() < ops.BUSINESS_END


# --------------------------------------------------------------------------
# End to end, against the real artifacts.
# --------------------------------------------------------------------------


@pytest.fixture(scope="module")
def catalog():
    return load_catalog()


@pytest.fixture(scope="module")
def size_table():
    return SizeTable(load_size_table())


@pytest.fixture(scope="module")
def batch():
    accepted, rejected = generate(seed=42, count=24)
    return accepted, rejected


def _render_one(family, persona, catalog, size_table, *, seed=42, index=1):
    plan = plan_variant(
        index=index, seed=seed, family=family, persona=persona, catalog=catalog
    )
    lines = render(
        build_steps(plan),
        catalog=catalog,
        size_table=size_table,
        start=plan.start_ts,
        first_line=FIRST_INJECTED_LINE,
        rng=random.Random(stream_seed(seed, index, family, "render")),
        business_hours="business_hours" in plan.operators,
    )
    return plan, lines


@needs_dataset
def test_every_generated_variant_round_trips_through_the_parser(batch):
    accepted, _ = batch
    assert accepted, "the generator produced nothing to check"
    for variant in accepted:
        for line in variant["lines"]:
            event = parse_line(line["line"], line["raw"])
            assert event.raw == line["raw"]
            assert event.ts.isoformat() == line["ts"]


@needs_dataset
def test_injected_ids_can_never_collide_with_a_real_event(batch):
    accepted, _ = batch
    ids = [n for variant in accepted for n in variant["injected_lines"]]
    assert min(ids) >= FIRST_INJECTED_LINE
    assert len(set(ids)) == len(ids)


@needs_dataset
def test_critic_rejects_a_fabricated_size(catalog, size_table):
    plan, lines = _render_one("F2", "careful_insider", catalog, size_table)
    accepted, _ = review(lines, plan, catalog=catalog, size_table=size_table)
    assert accepted.accepted

    victim = lines[0]
    tampered = [
        replace(victim, raw=victim.raw.rsplit(" ", 1)[0] + " 31337"),
        *lines[1:],
    ]
    report, _ = review(tampered, plan, catalog=catalog, size_table=size_table)
    assert not report.accepted
    assert report.rejected_reason.startswith("size_table:")
    assert "size_table" not in report.checks_passed


@needs_dataset
def test_critic_rejects_a_declared_operator_that_is_absent(catalog, size_table):
    """F2 has no failed logins, so slow_guess cannot possibly be in it."""
    plan, lines = _render_one("F2", "careful_insider", catalog, size_table)
    lying = replace(plan, operators=(*plan.operators, "slow_guess"))

    report, _ = review(lines, lying, catalog=catalog, size_table=size_table)
    assert not report.accepted
    assert report.rejected_reason.startswith("operators_present:")
    assert "slow_guess" in report.rejected_reason


@needs_dataset
def test_critic_rejects_a_slow_guess_rendered_as_a_burst(catalog, size_table):
    """The failure mode the sixth check exists for, end to end."""
    plan, lines = _render_one("F1", "careful_insider", catalog, size_table, index=3)
    slow = replace(plan, operators=tuple({*plan.operators, "slow_guess"}))

    start = lines[0].ts
    burst = [
        replace(line, ts=start + timedelta(seconds=4 * n))
        for n, line in enumerate(lines)
    ]
    burst = [
        replace(
            line,
            raw=rewrite(
                line.raw,
                ip=parse_line(line.line, line.raw).ip,
                user=parse_line(line.line, line.raw).user,
                ts=line.ts,
                path=parse_line(line.line, line.raw).path,
                status=parse_line(line.line, line.raw).status,
                size=parse_line(line.line, line.raw).size,
            ),
        )
        for line in burst
    ]

    report, _ = review(burst, slow, catalog=catalog, size_table=size_table)
    assert not report.accepted
    assert "slow_guess" in report.rejected_reason


@needs_dataset
def test_every_declared_operator_is_visible_in_the_output(batch, catalog):
    accepted, _ = batch
    for variant in accepted:
        events = [parse_line(l["line"], l["raw"]) for l in variant["lines"]]
        plan = _PlanView(variant)
        assert not ops.missing_operators(
            variant["operators"], events, plan, catalog
        ), variant["variant_id"]


class _PlanView:
    """The three fields the operator verifiers read, straight off a label."""

    def __init__(self, variant: dict) -> None:
        self.attacker = variant["attacker"]
        self.victim = variant["victim"]
        self.target = variant["target"]


@needs_dataset
def test_victim_is_authorized_and_attacker_is_not(batch, catalog):
    accepted, _ = batch
    for variant in accepted:
        meta = catalog.targets[variant["target"]]
        assert variant["victim"] in meta["authorized"], variant["variant_id"]
        assert variant["attacker"] in meta["denied"], variant["variant_id"]


@needs_dataset
def test_generation_is_reproducible_from_the_seed():
    first, _ = generate(seed=11, count=6)
    second, _ = generate(seed=11, count=6)
    assert first == second

    other, _ = generate(seed=12, count=6)
    assert other != first, "a different seed produced an identical batch"


@needs_dataset
def test_generation_is_reproducible_across_processes():
    """Same seed, different PYTHONHASHSEED, same bytes.

    An in-process comparison cannot see this: Python salts string hashing
    once per interpreter, so anything that iterates a set of strings while
    consuming the rng is stable within a run and different between runs.
    That is how a seeded generator quietly stops being reproducible.
    """
    script = (
        "import hashlib, json;"
        "from minny.redteam.generate import generate;"
        "a, _ = generate(seed=11, count=12);"
        "print(hashlib.sha256(json.dumps(a).encode()).hexdigest())"
    )
    digests = set()
    for hash_seed in ("0", "1", "12345"):
        env = {**os.environ, "PYTHONHASHSEED": hash_seed}
        result = subprocess.run(
            [sys.executable, "-c", script],
            capture_output=True,
            text=True,
            env=env,
            check=True,
        )
        digests.add(result.stdout.strip())
    assert len(digests) == 1, "the batch depends on the interpreter's hash seed"


@needs_dataset
def test_declaring_requested_operators_makes_the_critic_fire():
    """Run the generator deliberately faulty; the sixth check must catch it.

    Without this the critic is only ever exercised on fixtures, and a check
    that has never rejected real output is a check nobody has tested.
    """
    _accepted, rejected = generate(seed=5, count=40, derive_operators=False)
    assert rejected, "the faulty mode produced nothing for the critic to reject"
    assert all(
        variant["critic"]["rejected_reason"].startswith("operators_present:")
        for variant in rejected
    )


@needs_dataset
def test_renderer_offset_matches_every_real_line():
    """The brief predicted -0500 before 8 March. The dataset disagrees.

    Rendering a winter offset would make every synthetic March line
    identifiable at a glance, so this pins the constant to the data.
    """
    import pandas as pd

    frame = pd.read_parquet(paths.events_path(), columns=["raw"])
    offsets = {raw.split()[4].rstrip("]") for raw in frame["raw"].head(20000)}
    offsets |= {raw.split()[4].rstrip("]") for raw in frame["raw"].tail(20000)}
    assert offsets == {"-0400"}
    assert format_ts(datetime(2026, 1, 5, tzinfo=LOG_UTC_OFFSET)).endswith("-0400")


@needs_dataset
def test_takeover_hosts_are_unused_but_look_like_the_network(catalog):
    real_subnets = {ip.rsplit(".", 1)[0] for ip in catalog.ip_owner}
    for ip in UNSEEN_IPS:
        assert ip not in catalog.ip_owner, f"{ip} belongs to somebody"
        assert ip.rsplit(".", 1)[0] in real_subnets, f"{ip} is off the network"


@needs_dataset
def test_all_families_and_personas_render(catalog, size_table):
    for index, family in enumerate(FAMILIES, start=1):
        for persona in PERSONAS:
            plan, lines = _render_one(
                family, persona, catalog, size_table, index=index
            )
            report, _ = review(lines, plan, catalog=catalog, size_table=size_table)
            assert report.accepted, (family, persona, report.rejected_reason)


@needs_dataset
def test_render_refuses_a_shape_with_no_real_precedent(catalog, size_table):
    """A path the corpus has never served is a forgery, not a variant."""
    steps = [Step("exfil", "david_m", "10.0.8.45", "/nope/secret.txt", 200, 0, "F2")]
    with pytest.raises(KeyError):
        render(
            steps,
            catalog=catalog,
            size_table=size_table,
            start=datetime(2026, 3, 10, 9, 0, tzinfo=LOG_UTC_OFFSET),
            first_line=FIRST_INJECTED_LINE,
            rng=random.Random(0),
        )
