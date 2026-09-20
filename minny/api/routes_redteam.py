"""Red team and evaluation routes (track C), mounted under /api by the app.

Routes are declared without the /api prefix because `minny.api.app` adds it.
Declaring it here too would serve them at /api/api and nobody would notice
until the UI was already wired up.

Three endpoints, and they are deliberately different kinds of thing.
`/metrics` serves a file the evaluation wrote and refuses to invent one.
`/redteam/generate` runs the real generator live, through the same critic the
batch goes through, because a judge clicking a button should exercise the
system rather than a demo path built beside it. `/blue/proposals` serves M6's
output and an empty list until M6 exists.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta

from minny.parser import parse_line
import threading
from pathlib import Path

from fastapi import APIRouter
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from minny import paths
from minny.redteam.catalog import load_catalog
from minny.redteam.families import FAMILIES
from minny.redteam.generate import generate_one
from minny.redteam.operators import APPLICABLE, OPERATORS
from minny.redteam.plan import PERSONAS
from minny.redteam.render import FIRST_INJECTED_LINE

router = APIRouter(tags=["redteam"])

EVAL_COMMAND = "python eval.py --seed 42"

# Judge-panel variants are numbered from here so their IDs never collide with
# the batch's v_0001 upwards, and so a synthetic badge on screen can be traced
# to the request that made it.
FIRST_LIVE_INDEX = 9001

# One lock around the two counters. FastAPI runs a sync handler in a thread
# pool, so two judges clicking at once would otherwise render two variants
# onto the same event IDs and the second would overwrite the first in every
# downstream view.
_lock = threading.Lock()
_next_index = FIRST_LIVE_INDEX
_next_line: int | None = None


class GenerateRequest(BaseModel):
    """The judge panel's body. `family` and `persona` carry defaults.

    00-CONTRACTS.md section 12 names attacker, victim, target, operators and
    persona. The UI additionally sends `family`, and defaulting to F4 means a
    body with neither still produces the full chain, which is the one worth
    watching.
    """

    attacker: str
    victim: str
    target: str
    operators: list[str] = Field(default_factory=list)
    persona: str = "careful_insider"
    family: str = "F4"
    seed: int = 42


def _error(status: int, code: str, message: str) -> JSONResponse:
    return JSONResponse(
        status_code=status, content={"error": {"code": code, "message": message}}
    )


def _load(path: Path):
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


@router.get("/metrics")
def get_metrics():
    """The evaluation's own output, never a default.

    An absent file is a 503 naming the command, not an empty object. A metrics
    panel rendering zeros because nobody ran the evaluation looks exactly like
    a detector that caught nothing.
    """
    document = _load(paths.metrics_path())
    if document is None:
        return _error(
            503,
            "artifact_missing",
            f"metrics.json has not been generated. Run `{EVAL_COMMAND}`. If you "
            f"are in a worktree, set MINNY_DATA_DIR to the main checkout's "
            f"data directory.",
        )
    return document


@router.get("/blue/proposals")
def get_blue_proposals():
    """M6's proposed rules with their gate results, accepted and rejected.

    The file is served exactly as the blue agent wrote it, which is an array.
    Until it exists there is nothing to iterate, so the empty case is an
    object saying so rather than a bare list that reads as a finished run
    producing no proposals.
    """
    document = _load(paths.data_dir() / "blue_proposals.json")
    if document is None:
        return {"proposals": []}
    return document


def _validate(request: GenerateRequest, catalog) -> JSONResponse | None:
    """Reject an incoherent combination rather than quietly substituting one.

    The planner falls back to a seeded choice for any value it cannot use,
    which is right for a batch of 200 and wrong here: a judge who picks a
    victim with no access to the file would be handed a label naming somebody
    else and no indication that the request was ignored.
    """
    if request.family not in FAMILIES:
        return _error(
            400,
            "unknown_family",
            f"{request.family} is not a family. Known: {', '.join(FAMILIES)}.",
        )
    if request.persona not in PERSONAS:
        return _error(
            400,
            "unknown_persona",
            f"{request.persona} is not a persona. Known: {', '.join(PERSONAS)}.",
        )

    # Checked before authorization so the clearer message wins. An account
    # cannot be denied a file it is authorized to read, so this would
    # otherwise always surface as one of the two below.
    if request.attacker == request.victim:
        return _error(
            400,
            "same_account",
            "The attacker and the victim cannot be the same account.",
        )

    usable = catalog.usable_targets()
    if request.target not in usable:
        return _error(
            400,
            "unknown_target",
            f"{request.target} is not a file the access matrix can support an "
            f"attack on. It needs an authorized reader and someone denied. "
            f"Usable: {', '.join(usable)}.",
        )

    authorized = catalog.authorized(request.target)
    denied = catalog.denied(request.target)
    if request.victim not in authorized:
        return _error(
            400,
            "victim_not_authorized",
            f"{request.victim} was never an authorized reader of "
            f"{request.target}, so there is no access to steal. Authorized: "
            f"{', '.join(authorized)}.",
        )
    if request.attacker not in denied:
        return _error(
            400,
            "attacker_not_denied",
            f"{request.attacker} was not denied {request.target}, so there is "
            f"nothing to escalate to. Denied: {', '.join(denied)}.",
        )
    for name in request.operators:
        if name not in OPERATORS:
            return _error(
                400,
                "unknown_operator",
                f"{name} is not an operator. Known: {', '.join(OPERATORS)}.",
            )
        if request.family not in APPLICABLE[name]:
            return _error(
                400,
                "operator_not_applicable",
                f"{name} has nothing to act on in {request.family}. It applies "
                f"to {', '.join(sorted(APPLICABLE[name]))}.",
            )
    return None


def _first_free_line() -> int:
    """Start above every event ID the batch already rendered.

    A live variant sharing an event ID with one from `variants.json` would put
    two different log lines behind one evidence link, which is the one thing
    the whole numbering scheme exists to prevent.
    """
    corpus = _load(paths.data_dir() / "variants.json") or []
    used = [line for variant in corpus for line in variant.get("injected_lines", [])]
    return max([FIRST_INJECTED_LINE, *[n + 1 for n in used]])


def _inject(label: dict) -> dict:
    """Hand the rendered lines to the live replay if there is somewhere to put them.

    Looked up rather than imported at module load, so the day track B adds the
    queue this route starts injecting with no edit here, and until then it
    says plainly that it did not.
    """
    try:
        from minny.api import routes_detect
    except Exception:  # noqa: BLE001 - a missing router is not an error here
        routes_detect = None

    # The replay engine calls this inject_events. An earlier draft of this
    # route looked for enqueue_variant, a name that never existed, so the
    # judge panel rendered a variant and then quietly reported that nothing
    # was streaming it.
    hook = getattr(routes_detect, "inject_events", None)
    if hook is None:
        return {
            "injected": False,
            "reason": "the live replay has no injection queue yet, so the "
            "variant is rendered, critiqued and labeled but nothing is "
            "streaming it. Replay it with `python eval.py`.",
        }

    # The renderer emits records carrying the raw log line plus its own
    # bookkeeping, not parsed fields. Handing those straight to the queue
    # injects events with no user, address or status, which arrive on the
    # stream and raise nothing, because every signal reads fields that are
    # not there. Parse each line with the same parser the dataset went
    # through, so a judge's variant is indistinguishable from real traffic.
    events = []
    for record in label.get("lines") or []:
        raw = record.get("raw")
        if not raw:
            continue
        try:
            event = parse_line(int(record.get("line", 0)), raw)
        except ValueError:
            continue
        events.append(
            {
                "line": event.line,
                "raw": event.raw,
                "ts": event.ts,
                "ip": event.ip,
                "user": event.user,
                "method": event.method,
                "path": event.path,
                "base": event.base,
                "query": event.query,
                "status": event.status,
                "size": event.size,
                "template": event.template,
                "obj_id": event.obj_id,
            }
        )

    if not events:
        return {"injected": False, "reason": "the variant rendered no lines"}

    try:
        result = hook(events, variant_id=label.get("variant_id"), synthetic=True)
    except Exception as exc:  # noqa: BLE001 - report it, do not fail the request
        return {"injected": False, "reason": f"the replay queue refused it: {exc}"}
    return {
        "injected": True,
        "reason": None,
        "queued": result.get("queued") if isinstance(result, dict) else None,
    }



LIVE_LEAD_WALL_S = 4.0
LIVE_LEAD_MIN_S = 300


def _live_start():
    """Place a judge's variant just ahead of the running replay cursor.

    The planner seeds a variant somewhere in March. That is right for the
    evaluation, where every variant is replayed from the start of the window,
    and wrong here: a replay that has already reached the 20th accepts events
    dated the 8th into the queue and then never emits them, because their
    moment has passed. The judge presses the button and nothing happens.

    Returns None when nothing is running, so the seeded placement stands.
    """
    try:
        from minny.api import routes_detect

        state = routes_detect.SERVICE.engine().state()
    except Exception:  # noqa: BLE001 - no replay is a normal condition here
        return None

    if not state.get("running"):
        return None
    cursor = state.get("cursor_ts")
    if not cursor:
        return None
    try:
        moment = datetime.fromisoformat(cursor)
    except (TypeError, ValueError):
        return None
    # The lead has to be measured in wall time, not log time. At six log
    # hours per wall second a ninety second lead is gone in twenty five
    # milliseconds, so the cursor passes the variant before the render
    # finishes and the queue holds events whose moment has been and gone.
    speed = float(state.get("speed_hours_per_second") or 1.0)
    lead = max(LIVE_LEAD_MIN_S, speed * 3600.0 * LIVE_LEAD_WALL_S)
    return moment + timedelta(seconds=lead)


@router.post("/redteam/generate")
def generate_variant(request: GenerateRequest):
    """Build one variant live and return its label.

    Same generator, same renderer, same critic as `--seed 42`. A rejected
    variant comes back with a 200 and its rejection reason, because the critic
    turning something down in front of a judge is a better demonstration than
    an error page.
    """
    global _next_index, _next_line

    catalog = load_catalog()
    failure = _validate(request, catalog)
    if failure is not None:
        return failure

    proposal = {
        "attacker": request.attacker,
        "victim": request.victim,
        "target": request.target,
        "operators": list(request.operators),
    }

    with _lock:
        if _next_line is None:
            _next_line = _first_free_line()
        index, first_line = _next_index, _next_line
        label = generate_one(
            seed=request.seed,
            index=index,
            family=request.family,
            persona=request.persona,
            proposal=proposal,
            start=_live_start(),
            first_line=first_line,
        )
        _next_index += 1
        _next_line += len(label["injected_lines"])

    if not label["critic"]["accepted"]:
        return {
            **label,
            "injected": False,
            "reason": f"the critic rejected it: {label['critic']['rejected_reason']}",
        }
    return {**label, **_inject(label)}
