"""The blue agent (milestone M6).

Reads an evasion the red team found, proposes a detection rule as parameters
inside the DSL, and accepts it only if it passes all three checks of the
validation gate: it catches held-out variants the proposer never saw, it
costs no more than the false-positive budget on benign March, and it is
silent on the seven-month baseline window.

    python -m minny.blue.run --seed 42

`minny.blue.evidence` decides what the proposer is allowed to look at,
`minny.blue.propose` turns that into rule parameters, `minny.blue.heldout`
generates the variants the gate scores on, and `minny.blue.gate` runs the
three checks. Nothing in here executes a rule; everything goes through the
grammar and the evaluator in `minny.detect.rules`.
"""

from minny.blue.gate import GateResult
from minny.blue.propose import Predicate, Proposal, RuleSpec

__all__ = ["GateResult", "Predicate", "Proposal", "RuleSpec"]
