"""The variants the gate scores on, which the proposer never saw (M6).

The first gate check is only worth running on attacks that are new to the
rule. Reusing the training variants would measure whether the proposer can
copy a threshold out of a table it was handed, which it always can.

So the held-out set differs from the training set in both of the ways
00-CONTRACTS.md section 10 asks for:

* **different seeds.** Every held-out variant is generated from its own seed,
  derived from the run's seed and its attempt number, and none of them is the
  seed the training batch used. `assert_disjoint` enforces that rather than
  trusting the arithmetic.
* **different personas.** Training takes `careful_insider`; the held-out set
  takes the other two. Persona is not cosmetic in this generator: it sets how
  likely each evasion is, how long the attacker waits and whether they clean
  up, so a held-out variant is a different shape of attack and not only a
  different roll.

Event IDs start well above the training batch so a held-out line can never
collide with a training line or with a real one, which keeps `line` usable as
the universal event ID the contract says it is.
"""

from __future__ import annotations

from minny.blue.evidence import HELDOUT_PERSONAS
from minny.redteam.catalog import load_catalog, load_size_table
from minny.redteam.generate import generate_one
from minny.redteam.operators import APPLICABLE
from minny.redteam.render import SizeTable

# The seed-42 batch occupies 180801 to 182610. Starting here leaves room for
# the training set to grow by an order of magnitude before the two could
# overlap.
HELDOUT_FIRST_LINE = 190001

FAMILY_ORDER: tuple[str, ...] = ("F1", "F2", "F3", "F4")


def families_for(operator: str) -> tuple[str, ...]:
    """The families this operator can appear in, in a fixed order.

    APPLICABLE holds frozensets and Python salts string hashing per process,
    so iterating one directly would cycle the families in a different order
    in every interpreter and the held-out set would stop being reproducible.
    """
    applicable = APPLICABLE[operator]
    return tuple(name for name in FAMILY_ORDER if name in applicable)


def seed_for(seed: int, attempt: int) -> int:
    """A per-variant seed that cannot collide with the training seed."""
    return seed * 100 + attempt


def assert_disjoint(variants: list[dict], training_seeds) -> None:
    overlap = {variant["seed"] for variant in variants} & set(training_seeds)
    if overlap:
        raise ValueError(
            f"held-out variants reuse the training seed(s) "
            f"{', '.join(str(seed) for seed in sorted(overlap))}; the gate "
            f"would be scoring the proposer on its own examples"
        )


def generate(
    *,
    operator: str,
    seed: int = 42,
    count: int = 40,
    personas: tuple[str, ...] = HELDOUT_PERSONAS,
    first_line: int = HELDOUT_FIRST_LINE,
    max_attempts: int | None = None,
    catalog=None,
    size_table=None,
) -> list[dict]:
    """Generate held-out variants carrying the operator.

    The operator is not requested from the planner, it is drawn by the
    persona's own weights and then read back off the finished plan, which is
    the same reconciliation the batch generator does. A variant that came out
    without the operator is simply not part of this set; forcing it would
    produce an attack the persona would never have run.
    """
    catalog = catalog if catalog is not None else load_catalog()
    size_table = size_table if size_table is not None else SizeTable(load_size_table())
    families = families_for(operator)
    if not families:
        raise ValueError(f"{operator} applies to no family")

    attempts = max_attempts if max_attempts is not None else count * 6
    accepted: list[dict] = []
    next_line = first_line

    for attempt in range(1, attempts + 1):
        if len(accepted) >= count:
            break
        persona = personas[(attempt - 1) % len(personas)]
        family = families[(attempt - 1) % len(families)]
        label = generate_one(
            seed=seed_for(seed, attempt),
            index=attempt,
            family=family,
            persona=persona,
            first_line=next_line,
            catalog=catalog,
            size_table=size_table,
        )
        if not label["critic"]["accepted"] or operator not in label["operators"]:
            continue
        label["variant_id"] = f"h_{len(accepted) + 1:04d}"
        accepted.append(label)
        next_line += len(label["injected_lines"])

    return accepted


def summary(variants: list[dict], operator: str) -> dict:
    """What the proposal file records about the set it was scored on."""
    from collections import Counter

    return {
        "operator": operator,
        "variants": len(variants),
        "seeds": sorted({variant["seed"] for variant in variants}),
        "personas": sorted({variant["persona"] for variant in variants}),
        "by_persona": dict(Counter(v["persona"] for v in variants)),
        "by_family": dict(Counter(v["family"] for v in variants)),
        "variant_ids": [variant["variant_id"] for variant in variants],
        "first_line": min(
            (min(v["injected_lines"]) for v in variants if v["injected_lines"]),
            default=None,
        ),
        "last_line": max(
            (max(v["injected_lines"]) for v in variants if v["injected_lines"]),
            default=None,
        ),
    }
