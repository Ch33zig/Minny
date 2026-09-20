"""Choose the parameters of one variant (milestone M4).

A plan is attacker, victim, target, IPs, a forum post, an operator list and a
set of timing offsets. It is JSON, and nothing in it is a log line.

**The model never writes a log line.** It picks values out of enums that come
from the dataset itself, and deterministic code renders everything. That is
what keeps the output safe to publish, and it is also what makes the harness
reproducible: `--seed 42` gives the same 200 variants on any machine with no
API key and no network.

The seeded planner is therefore the default path, not a fallback bolted on
afterwards. Claude is an optional source of parameter *diversity* (it picks
combinations a weighted die would rarely roll), and every value it returns is
validated against the same enums before it is used. Anything unusable falls
back to the seeded choice for that field, so a bad response degrades the
variety of the batch and never its validity.
"""

from __future__ import annotations

import hashlib
import json
import os
import random
from dataclasses import asdict, dataclass, field, replace
from datetime import datetime, timedelta

from minny.redteam.catalog import (
    CANONICAL_ATTACKER,
    CANONICAL_TARGET,
    CANONICAL_VICTIM,
    Catalog,
)
from minny.redteam.families import FAMILIES
from minny.redteam.operators import (
    APPLICABLE,
    INNOCUOUS_PARAM_KEYS,
    OPERATORS,
    PARAM_STYLE_ATTACK,
    PARAM_STYLE_RENAMED,
    PARAM_STYLE_TOPIC_ONLY,
)
from minny.redteam.render import LOG_UTC_OFFSET

PERSONAS: tuple[str, ...] = (
    "impatient_insider",
    "careful_insider",
    "outsider_with_stolen_credentials",
)

# March 2026 is the held-out window the eval measures on. Chains can run for
# three days, so the latest start leaves room for one to finish inside March.
INJECT_START = datetime(2026, 3, 2, 0, 0, tzinfo=LOG_UTC_OFFSET)
INJECT_END = datetime(2026, 3, 27, 0, 0, tzinfo=LOG_UTC_OFFSET)

# Hosts that belong to nobody, for own_ip_takeover.
#
# Every one sits on a /24 that real employees are already on (the corpus
# only ever uses 10.0.5 through 10.0.9) with a host octet that occurs
# nowhere in 180,800 lines. The first draft used 10.0.10.x and 10.0.12.x and
# the blind realism check picked those lines out immediately: a subnet that
# appears nowhere else is a rendering tell, not an attack signal, and the
# difference between the two is the whole point of the exercise. Zero padding
# a single digit octet imitates nicole_h's real 10.0.9.05.
UNSEEN_IPS: tuple[str, ...] = (
    "10.0.5.41",
    "10.0.6.09",
    "10.0.6.58",
    "10.0.7.04",
    "10.0.7.62",
    "10.0.8.17",
    "10.0.9.28",
    "10.0.9.73",
)

ANTHROPIC_MODEL = "claude-opus-5"

# How likely each persona is to reach for each operator, before applicability
# and coherence trim the list. `no_cover_download` is weighted up across all
# three because it only applies to F4, and a quarter of a quarter of the
# batch is too thin a cell for its row in the per-operator table to mean
# anything. These are the personas' whole definition: an
# impatient insider guesses fast and leaves the post up, a careful one waits
# and cleans up, an outsider is on a host nobody recognises.
PERSONA_WEIGHTS: dict[str, dict[str, float]] = {
    "impatient_insider": {
        "slow_guess": 0.05,
        "own_ip_takeover": 0.15,
        "param_rename": 0.25,
        "victim_swap": 0.30,
        "target_swap": 0.30,
        "business_hours": 0.20,
        "delay_gap": 0.10,
        "no_cleanup": 0.60,
        "no_cover_download": 0.55,
    },
    "careful_insider": {
        "slow_guess": 0.85,
        "own_ip_takeover": 0.45,
        "param_rename": 0.85,
        "victim_swap": 0.40,
        "target_swap": 0.40,
        "business_hours": 0.75,
        "delay_gap": 0.80,
        "no_cleanup": 0.15,
        "no_cover_download": 0.60,
    },
    "outsider_with_stolen_credentials": {
        "slow_guess": 0.60,
        "own_ip_takeover": 0.95,
        "param_rename": 0.50,
        "victim_swap": 0.50,
        "target_swap": 0.50,
        "business_hours": 0.35,
        "delay_gap": 0.45,
        "no_cleanup": 0.70,
        "no_cover_download": 0.50,
    },
}

RECON_PROBABILITY: dict[str, float] = {
    "impatient_insider": 0.80,
    "careful_insider": 0.15,
    "outsider_with_stolen_credentials": 0.50,
}


@dataclass(frozen=True)
class AttackPlan:
    """Everything the renderer needs, and nothing it does not."""

    variant_id: str
    seed: int
    family: str
    persona: str
    attacker: str
    attacker_ip: str
    victim: str
    victim_ip: str
    takeover_ip: str
    target: str
    post_id: int
    topic: str
    recon_topics: tuple[str, ...]
    param_style: str
    renamed_key: str
    operators: tuple[str, ...]
    start_ts: datetime
    timing: dict = field(default_factory=dict)
    planner: str = "deterministic"

    @property
    def family_name(self) -> str:
        return FAMILIES[self.family]

    def to_json(self) -> dict:
        data = asdict(self)
        data["start_ts"] = self.start_ts.isoformat()
        data["recon_topics"] = list(self.recon_topics)
        data["operators"] = list(self.operators)
        return data


def plan_variant(
    *,
    index: int,
    seed: int,
    family: str,
    persona: str,
    catalog: Catalog,
    proposal: dict | None = None,
    derive_operators: bool = True,
) -> AttackPlan:
    """Build one plan. Same arguments in, same plan out, always."""
    rng = random.Random(stream_seed(seed, index, family, persona))
    proposal = proposal or {}

    target = _pick_target(rng, catalog, proposal.get("target"))
    victim = _pick_victim(rng, catalog, target, proposal.get("victim"))
    attacker = _pick_attacker(rng, catalog, target, victim, proposal.get("attacker"))

    requested = _requested_operators(rng, persona, family, proposal.get("operators"))
    own_ip = "own_ip_takeover" in requested
    attacker_ip = catalog.user_ip[attacker]
    victim_ip = catalog.user_ip[victim]
    takeover_ip = rng.choice(UNSEEN_IPS) if own_ip else attacker_ip

    param_style = _pick_param_style(rng, requested, proposal.get("param_style"))
    renamed_key = _pick_enum(
        rng, INNOCUOUS_PARAM_KEYS, proposal.get("renamed_key")
    )

    topics = list(catalog.forum_topics)
    rng.shuffle(topics)
    recon_count = _recon_count(rng, persona, family)
    timing = _timing(rng, persona, requested, recon_count)
    start_ts = _start_ts(rng, "business_hours" in requested)

    plan = AttackPlan(
        variant_id=f"v_{index:04d}",
        seed=seed,
        family=family,
        persona=persona,
        attacker=attacker,
        attacker_ip=attacker_ip,
        victim=victim,
        victim_ip=victim_ip,
        takeover_ip=takeover_ip,
        target=target,
        post_id=rng.choice(catalog.forum_post_ids),
        topic=topics[0],
        recon_topics=tuple(topics[1:3]),
        param_style=param_style,
        renamed_key=renamed_key,
        operators=(),
        start_ts=start_ts,
        timing=timing,
        planner="llm" if proposal else "deterministic",
    )

    # The declared operator list is *derived* from the finished plan rather
    # than copied from what was requested. Asking for target_swap and then
    # being handed the canonical target would otherwise put a label on the
    # variant that the rendered lines do not support, and the per-operator
    # table would silently count it.
    #
    # `derive_operators=False` skips that reconciliation and declares what was
    # asked for. It exists so the generator can be run as a deliberately
    # faulty one and the critic's sixth check can be watched doing its job on
    # real output rather than only on a fixture.
    if not derive_operators:
        return replace(
            plan, operators=tuple(n for n in OPERATORS if n in requested)
        )
    return _with_effective_operators(plan, requested)


def _with_effective_operators(plan: AttackPlan, requested: set[str]) -> AttackPlan:
    effective = set()
    if "slow_guess" in requested and "slow_guess" in _available(plan.family):
        effective.add("slow_guess")
    if plan.takeover_ip != plan.attacker_ip:
        effective.add("own_ip_takeover")
    if plan.param_style != PARAM_STYLE_ATTACK and "param_rename" in _available(
        plan.family
    ):
        effective.add("param_rename")
    if plan.victim != CANONICAL_VICTIM:
        effective.add("victim_swap")
    if plan.target != CANONICAL_TARGET:
        effective.add("target_swap")
    for name in ("business_hours", "delay_gap", "no_cleanup", "no_cover_download"):
        if name in requested and name in _available(plan.family):
            effective.add(name)

    ordered = tuple(name for name in OPERATORS if name in effective)
    return replace(plan, operators=ordered)


def stream_seed(seed: int, index: int, family: str, persona: str) -> int:
    """A stable per-variant seed.

    Python salts str.__hash__ per process, so hashing the key directly would
    make `--seed 42` mean something different on every run. blake2b does not.
    """
    key = f"{seed}:{index}:{family}:{persona}".encode("utf-8")
    return int.from_bytes(hashlib.blake2b(key, digest_size=8).digest(), "big")


def _available(family: str) -> tuple[str, ...]:
    """The operators this family can carry, in the contract's fixed order.

    A tuple rather than a set, and the order is not cosmetic. The weighted
    draw below consumes one rng value per operator, so iterating a set of
    strings would consume them in hash order, and Python salts string
    hashing per process, which quietly made `--seed 42` produce a different
    batch in every interpreter.
    """
    return tuple(name for name in OPERATORS if family in APPLICABLE[name])


def _pick_enum(rng: random.Random, options, proposed):
    if proposed in options:
        return proposed
    return rng.choice(tuple(options))


def _pick_target(rng: random.Random, catalog: Catalog, proposed) -> str:
    options = catalog.confidential_targets()
    if proposed in options:
        return proposed
    # Leave a real control group on the canonical target. If almost every
    # variant were swapped, `target_swap`'s row in the metrics table would
    # have nothing to be compared against.
    if CANONICAL_TARGET in options and rng.random() < 0.4:
        return CANONICAL_TARGET
    return rng.choice(options)


def _pick_victim(rng: random.Random, catalog: Catalog, target: str, proposed) -> str:
    """The victim must already be allowed to read the target.

    A variant whose victim was never authorised is not a stealthier attack,
    it is an incoherent one, and the critic would reject it.
    """
    authorized = catalog.authorized(target)
    if proposed in authorized:
        return proposed
    if CANONICAL_VICTIM in authorized and rng.random() < 0.5:
        return CANONICAL_VICTIM
    return rng.choice(authorized)


def _pick_attacker(
    rng: random.Random, catalog: Catalog, target: str, victim: str, proposed
) -> str:
    denied = tuple(u for u in catalog.denied(target) if u != victim)
    if proposed in denied:
        return proposed
    if CANONICAL_ATTACKER in denied and rng.random() < 0.35:
        return CANONICAL_ATTACKER
    return rng.choice(denied)


def _requested_operators(
    rng: random.Random, persona: str, family: str, proposed
) -> set[str]:
    available = _available(family)
    if isinstance(proposed, list):
        picked = {name for name in proposed if name in available}
        if picked:
            return picked
    weights = PERSONA_WEIGHTS[persona]
    return {name for name in available if rng.random() < weights[name]}


def _pick_param_style(rng: random.Random, requested: set[str], proposed) -> str:
    if "param_rename" not in requested:
        return PARAM_STYLE_ATTACK
    if proposed in (PARAM_STYLE_RENAMED, PARAM_STYLE_TOPIC_ONLY):
        return proposed
    # Dropping the extra key entirely is the stronger evasion, so it is the
    # more common one.
    return PARAM_STYLE_TOPIC_ONLY if rng.random() < 0.6 else PARAM_STYLE_RENAMED


def _recon_count(rng: random.Random, persona: str, family: str) -> int:
    if family not in {"F2", "F4"}:
        return 0
    if rng.random() >= RECON_PROBABILITY[persona]:
        return 0
    return rng.choice((1, 2))


def _timing(
    rng: random.Random, persona: str, requested: set[str], recon_count: int
) -> dict:
    slow = "slow_guess" in requested
    delayed = "delay_gap" in requested
    business = "business_hours" in requested

    # A slow burst inside business hours has to fit in one eight-hour day or
    # the layout rolls it onto the next, which is still a valid slow_guess
    # but a stranger story.
    fails = rng.randint(3, 5) if slow and business else rng.randint(3, 8)
    if slow:
        gaps = [rng.randint(1800, 7200) for _ in range(fails)]
    else:
        gaps = [rng.randint(2, 8) for _ in range(fails)]
    gaps[0] = 0

    return {
        "auth_gaps": gaps,
        "login_success_gap_s": rng.randint(1800, 5400) if slow else rng.randint(3, 20),
        "dashboard_gap_s": rng.randint(2, 9),
        "access_gap_s": rng.randint(1200, 9000) if delayed else rng.randint(20, 180),
        "logout_gap_s": rng.randint(30, 400),
        "probe_gap_s": rng.randint(3600, 43200),
        "recon_gaps": [rng.randint(600, 4200) for _ in range(recon_count)],
        "payload_gap_s": rng.randint(900, 5400),
        "author_view_gap_s": rng.randint(2, 12),
        "victim_arrival_s": rng.randint(1200, 14400),
        "view_to_action_s": rng.randint(1200, 5400) if delayed else rng.randint(1, 4),
        "avatar_gap_s": rng.randint(2, 6),
        "escalation_to_exfil_s": (
            rng.randint(12600, 43200) if delayed else rng.randint(600, 3000)
        ),
        "cleanup_gap_s": rng.randint(600, 5400),
        "cover_delay_s": rng.randint(21600, 50400),
    }


def _start_ts(rng: random.Random, business_hours: bool) -> datetime:
    span = int((INJECT_END - INJECT_START).total_seconds())
    start = INJECT_START + timedelta(seconds=rng.randrange(span))
    if business_hours:
        # Start somewhere inside a working morning rather than at the top of
        # the window; the layout will still move it to a weekday.
        return start.replace(
            hour=rng.randrange(9, 14),
            minute=rng.randrange(60),
            second=rng.randrange(60),
        )
    # Off-hours starts are deliberately common. The dataset contains routine
    # after-midnight access by authorised readers, so an overnight chain is
    # not itself suspicious and the detector must not get it for free.
    return start.replace(
        hour=rng.randrange(24), minute=rng.randrange(60), second=rng.randrange(60)
    )


# --------------------------------------------------------------------------
# Optional Claude-assisted parameter choice.
# --------------------------------------------------------------------------

# Derived from attack-plan.schema.json, flattened the way a strict structured
# output wants it: every property required, no additionalProperties, and no
# nullable unions to negotiate. Unusable values are dropped by the validators
# above rather than being rejected wholesale, so one odd field costs one
# field's worth of diversity.
def parameter_schema(catalog: Catalog) -> dict:
    return {
        "type": "object",
        "properties": {
            "attacker": {"type": "string", "enum": list(catalog.users)},
            "victim": {"type": "string", "enum": list(catalog.users)},
            "target": {
                "type": "string",
                "enum": list(catalog.confidential_targets()),
            },
            "operators": {
                "type": "array",
                "items": {"type": "string", "enum": list(OPERATORS)},
            },
            "param_style": {
                "type": "string",
                "enum": [PARAM_STYLE_ATTACK, PARAM_STYLE_RENAMED, PARAM_STYLE_TOPIC_ONLY],
            },
            "renamed_key": {"type": "string", "enum": list(INNOCUOUS_PARAM_KEYS)},
            "rationale": {"type": "string"},
        },
        "required": [
            "attacker",
            "victim",
            "target",
            "operators",
            "param_style",
            "renamed_key",
            "rationale",
        ],
        "additionalProperties": False,
    }


SYSTEM_PROMPT = """You are helping stress test an insider-threat detector on \
a synthetic corporate web access log. You choose parameters for one attack \
variant. You never write a log line, a payload, or any code: deterministic \
code renders every line from the parameters you return.

Pick a combination that is coherent (the victim must be an authorized reader \
of the target, the attacker must be someone the target denies) and that is \
not the obvious one. Variety across a batch is the point: we are measuring \
which detection assumptions hold, so unusual but plausible combinations are \
worth more than the textbook shape."""


def anthropic_available() -> bool:
    return bool(os.environ.get("ANTHROPIC_API_KEY"))


def propose_parameters(
    *, family: str, persona: str, catalog: Catalog, cache: dict | None = None
) -> dict | None:
    """Ask Claude for parameters. Returns None on any failure, never raises."""
    if not anthropic_available():
        return None

    cache_key = f"{family}:{persona}"
    if cache is not None and cache_key in cache:
        return cache[cache_key]

    try:
        import anthropic
    except ImportError:
        return None

    prompt = (
        f"Family {family} ({FAMILIES[family]}), persona {persona}.\n"
        f"Operators that apply to this family: {sorted(_available(family))}.\n"
        "Return the parameters for one variant."
    )

    client = anthropic.Anthropic()
    try:
        response = client.messages.create(
            model=ANTHROPIC_MODEL,
            max_tokens=16000,
            thinking={"type": "adaptive"},
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": prompt}],
            output_config={
                "format": {
                    "type": "json_schema",
                    "schema": parameter_schema(catalog),
                }
            },
        )
    except anthropic.RateLimitError:
        return None
    except anthropic.APIStatusError:
        return None
    except anthropic.APIConnectionError:
        return None

    text = next((b.text for b in response.content if b.type == "text"), None)
    if not text:
        return None
    try:
        proposal = json.loads(text)
    except json.JSONDecodeError:
        return None

    if cache is not None:
        cache[cache_key] = proposal
    return proposal
