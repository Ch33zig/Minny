"""Red team: generate labeled attack variants to stress the detector (M4).

Read `generate.py` first — it is the only entry point:

    python -m minny.redteam.generate --seed 42 --count 200

The rest of the package is the pipeline behind it. `plan` picks parameters,
`families` turns a plan into ordered steps, `render` turns steps into log
lines, `operators` defines the evasions and proves they landed, and `critic`
rejects anything that does not hold up.
"""

from minny.redteam.critic import CriticReport, review
from minny.redteam.families import FAMILIES, build_steps
from minny.redteam.operators import APPLICABLE, OPERATORS
from minny.redteam.plan import PERSONAS, AttackPlan, plan_variant
from minny.redteam.render import SizeTable, render

__all__ = [
    "APPLICABLE",
    "AttackPlan",
    "CriticReport",
    "FAMILIES",
    "OPERATORS",
    "PERSONAS",
    "SizeTable",
    "build_steps",
    "plan_variant",
    "render",
    "review",
]
