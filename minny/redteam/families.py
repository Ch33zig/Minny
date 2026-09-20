"""The four attack families, as ordered lists of steps (milestone M4).

The IDs are fixed by 00-CONTRACTS.md section 8 and every one of them is a
piece of the real 13-15 March incident rather than an invention:

* **F1 credential_takeover**: failed logins as the victim, then a success,
  then the access her account is entitled to make.
* **F2 content_privilege_escalation**: a post, the victim viewing it, a
  privileged action under her session, and the attacker's first success on a
  file he had been refused.
* **F3 cover_download**: the victim's account driven from the attacker's
  host to pull the asset a second time.
* **F4 full_chain**: F1 then F2 then F3, which is the shape of the breach.

A step has no timestamp, no size and no line number. It has a gap from the
step before it, and render.py turns gaps into a timeline. Keeping the two
apart is what lets `business_hours` reshape a whole variant without any
family knowing that operator exists.
"""

from __future__ import annotations

from typing import TYPE_CHECKING
from urllib.parse import urlencode

from minny.redteam.catalog import (
    DASHBOARD_PATH,
    FORUM_NEW_PATH,
    LOGIN_PATH,
    LOGOUT_PATH,
    PRIVILEGED_PATH,
)
from minny.redteam.operators import (
    ATTACK_PARAM_VALUES,
    INNOCUOUS_PARAMS,
    PARAM_STYLE_ATTACK,
    PARAM_STYLE_RENAMED,
    avatar_path,
)
from minny.redteam.render import Step

if TYPE_CHECKING:  # pragma: no cover - import cycle guard, typing only
    from minny.redteam.plan import AttackPlan

FAMILIES: dict[str, str] = {
    "F1": "credential_takeover",
    "F2": "content_privilege_escalation",
    "F3": "cover_download",
    "F4": "full_chain",
}

# Step kinds. The critic and the eval both read these, so they are as much a
# contract as the family IDs.
AUTH_FAIL = "auth_fail"
AUTH_SUCCESS = "auth_success"
DASHBOARD = "dashboard"
DENIED_PROBE = "denied_probe"
POST_RECON = "post_recon"
POST_PAYLOAD = "post_payload"
AUTHOR_VIEW = "author_view"
VICTIM_VIEW = "victim_view"
PRIVILEGED_ACTION = "privileged_action"
AVATAR_FETCH = "avatar_fetch"
EXFIL = "exfil"
CLEANUP = "cleanup"
COVER_EXFIL = "cover_exfil"
TAKEOVER_EXFIL = "takeover_exfil"
LOGOUT = "logout"


def forum_view_path(post_id: int) -> str:
    return f"/intranet/forum/view/{post_id}"


def forum_edit_path(post_id: int) -> str:
    return f"/intranet/forum/edit/{post_id}"


def post_path(topic: str, param_style: str, renamed_key: str, attempt: int) -> str:
    """The request line a forum post produces, and nothing more.

    There is no post body anywhere in this system. The dataset records
    requests, never contents, so a "malicious post" exists here only as a
    POST with some query parameters, which is also the whole reason this
    output is safe to publish.
    """
    params = [("topic", topic)]
    if param_style == PARAM_STYLE_ATTACK:
        params.append(ATTACK_PARAM_VALUES[min(attempt, len(ATTACK_PARAM_VALUES) - 1)])
    elif param_style == PARAM_STYLE_RENAMED:
        params.append((renamed_key, INNOCUOUS_PARAMS[renamed_key]))
    return f"{FORUM_NEW_PATH}?{urlencode(params)}"


def build_steps(plan: "AttackPlan") -> list[Step]:
    builders = {
        "F1": _credential_takeover,
        "F2": _content_privilege_escalation,
        "F3": _cover_download,
        "F4": _full_chain,
    }
    return builders[plan.family](plan)


def _credential_takeover(plan: "AttackPlan", phase: str = "F1") -> list[Step]:
    timing = plan.timing
    steps: list[Step] = [
        Step(AUTH_FAIL, plan.victim, plan.takeover_ip, LOGIN_PATH, 401, gap, phase)
        for gap in timing["auth_gaps"]
    ]
    steps.append(
        Step(
            AUTH_SUCCESS,
            plan.victim,
            plan.takeover_ip,
            LOGIN_PATH,
            200,
            timing["login_success_gap_s"],
            phase,
        )
    )
    steps.append(
        Step(
            DASHBOARD,
            plan.victim,
            plan.takeover_ip,
            DASHBOARD_PATH,
            200,
            timing["dashboard_gap_s"],
            phase,
        )
    )
    steps.append(
        Step(
            TAKEOVER_EXFIL,
            plan.victim,
            plan.takeover_ip,
            plan.target,
            200,
            timing["access_gap_s"],
            phase,
        )
    )
    steps.append(
        Step(
            LOGOUT,
            plan.victim,
            plan.takeover_ip,
            LOGOUT_PATH,
            302,
            timing["logout_gap_s"],
            phase,
        )
    )
    return steps


def _content_privilege_escalation(plan: "AttackPlan", phase: str = "F2") -> list[Step]:
    timing = plan.timing
    steps: list[Step] = [
        # The denial is the point of the family. Without a prior 403 the
        # later 200 is not a first success on a file he was refused, it is
        # just a download.
        Step(
            DENIED_PROBE,
            plan.attacker,
            plan.attacker_ip,
            plan.target,
            403,
            timing["probe_gap_s"],
            phase,
        )
    ]

    # Reconnaissance attempts. The two that failed in the real incident carry
    # the only 500 and the only 400 in 180,800 lines, which makes them the
    # loudest thing an attacker can do; an impatient persona still does it.
    recon_statuses = (500, 400)
    for attempt, gap in enumerate(timing["recon_gaps"]):
        steps.append(
            Step(
                POST_RECON,
                plan.attacker,
                plan.attacker_ip,
                post_path(
                    plan.recon_topics[attempt],
                    plan.param_style,
                    plan.renamed_key,
                    attempt,
                ),
                recon_statuses[attempt],
                gap,
                phase,
            )
        )

    steps.append(
        Step(
            POST_PAYLOAD,
            plan.attacker,
            plan.attacker_ip,
            post_path(plan.topic, plan.param_style, plan.renamed_key, 2),
            302,
            timing["payload_gap_s"],
            phase,
        )
    )
    steps.append(
        Step(
            AUTHOR_VIEW,
            plan.attacker,
            plan.attacker_ip,
            forum_view_path(plan.post_id),
            200,
            timing["author_view_gap_s"],
            phase,
        )
    )
    steps.append(
        Step(
            VICTIM_VIEW,
            plan.victim,
            plan.victim_ip,
            forum_view_path(plan.post_id),
            200,
            timing["victim_arrival_s"],
            phase,
        )
    )
    steps.append(
        Step(
            PRIVILEGED_ACTION,
            plan.victim,
            plan.victim_ip,
            PRIVILEGED_PATH,
            200,
            timing["view_to_action_s"],
            phase,
        )
    )
    steps.append(
        Step(
            AVATAR_FETCH,
            plan.victim,
            plan.victim_ip,
            avatar_path(plan.post_id),
            200,
            timing["avatar_gap_s"],
            phase,
        )
    )
    steps.append(
        Step(
            EXFIL,
            plan.attacker,
            plan.attacker_ip,
            plan.target,
            200,
            timing["escalation_to_exfil_s"],
            phase,
        )
    )
    if "no_cleanup" not in plan.operators:
        steps.append(
            Step(
                CLEANUP,
                plan.attacker,
                plan.attacker_ip,
                forum_edit_path(plan.post_id),
                302,
                timing["cleanup_gap_s"],
                phase,
            )
        )
    return steps


def _cover_download(plan: "AttackPlan", phase: str = "F3") -> list[Step]:
    timing = plan.timing
    return [
        Step(
            AUTH_SUCCESS,
            plan.victim,
            plan.takeover_ip,
            LOGIN_PATH,
            200,
            timing["cover_delay_s"],
            phase,
        ),
        Step(
            DASHBOARD,
            plan.victim,
            plan.takeover_ip,
            DASHBOARD_PATH,
            200,
            timing["dashboard_gap_s"],
            phase,
        ),
        Step(
            COVER_EXFIL,
            plan.victim,
            plan.takeover_ip,
            plan.target,
            200,
            timing["access_gap_s"],
            phase,
        ),
        Step(
            LOGOUT,
            plan.victim,
            plan.takeover_ip,
            LOGOUT_PATH,
            302,
            timing["logout_gap_s"],
            phase,
        ),
    ]


def _full_chain(plan: "AttackPlan") -> list[Step]:
    """Guessing, escalation, theft, then the account used to cover it.

    The guessing phase stops at the failures on purpose. In the real incident
    the burst on the 13th and 14th never succeeded; the successful login came
    on the night of the 15th, after the file had already been taken. Carrying
    that shape means F4's only 200 under the victim's name is the cover
    session, which is exactly what `no_cover_download` removes.
    """
    timing = plan.timing
    steps = [
        Step(AUTH_FAIL, plan.victim, plan.takeover_ip, LOGIN_PATH, 401, gap, "F1")
        for gap in timing["auth_gaps"]
    ]
    steps.extend(_content_privilege_escalation(plan, phase="F2"))
    if "no_cover_download" not in plan.operators:
        steps.extend(_cover_download(plan, phase="F3"))
    return steps
