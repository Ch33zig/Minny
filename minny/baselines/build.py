"""Per-user behavioural baselines (milestone M2).

    python -m minny.baselines.build

Writes data/baselines.json to the shape in docs/handoff/00-CONTRACTS.md
section 4, fitted on ``ts < 2026-03-01`` and nothing else.

The cutoff is the entire point of this module. The 13-15 March incident sits
inside the held-out window, so if one March event leaks into the fit then the
detector has already seen the attack it is meant to catch and every number
downstream is worthless. The comparison is on aware datetimes and never on
strings: the dataset spans a DST change, so August lines carry -04:00 while
March lines carry -05:00 and lexical ordering of the ISO text is simply wrong.
"""

from __future__ import annotations

import argparse
import json
import statistics
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

import pandas as pd

from minny import paths

# Single-sourced from the artifact builder so the held-out window can never
# drift between the access matrix and the baselines compared against it.
from minny.build_events import BASELINE_CUTOFF

# Anything under this prefix is privileged by policy, not by observation.
PRIVILEGED_PREFIXES: tuple[str, ...] = ("/api/admin/",)

# A template that answers 200 to a POST and appears fewer than this many times
# across seven months is not a business feature, it is an administrative
# endpoint. The rarest legitimate template in the fitted window appears 1,778
# times, so 100 sits more than an order of magnitude below anything normal and
# comfortably above zero. That gap is the justification: there is nothing to
# tune between 100 and 1,778.
RARE_POST_SUCCESS_K = 100

# The window S3 uses. Recorded per user so baselines.json itself carries the
# evidence that the threshold produces no baseline-window hits.
AUTH_FAIL_WINDOW_S = 30


def _query_keys(query) -> tuple[str, ...]:
    """The parameter names actually present on a request.

    Parquet widens the query map into a struct over the union of every key in
    the file, so a parameter that was absent arrives as a None value rather
    than a missing key. Treating None as present would put every parameter
    name into every template's allow-list and silently disable S5.
    """
    if query is None:
        return ()
    return tuple(sorted(key for key, value in query.items() if value is not None))


def _max_in_window(timestamps: list, window_s: int) -> int:
    """Largest number of timestamps that ever fall inside one sliding window."""
    ordered = sorted(timestamps)
    best = 0
    start = 0
    for end in range(len(ordered)):
        while (ordered[end] - ordered[start]).total_seconds() > window_s:
            start += 1
        best = max(best, end - start + 1)
    return best


def _gap_stats(timestamps: list) -> dict:
    ordered = sorted(timestamps)
    gaps = [
        (later - earlier).total_seconds()
        for earlier, later in zip(ordered, ordered[1:])
    ]
    return {
        "count": len(ordered),
        "median_gap_s": round(statistics.median(gaps), 1) if gaps else None,
        "min_gap_s": round(min(gaps), 1) if gaps else None,
    }


def build_baselines(
    frame: pd.DataFrame,
    cutoff: datetime = BASELINE_CUTOFF,
    rare_post_success_k: int = RARE_POST_SUCCESS_K,
) -> dict:
    """Fit every per-user and global statistic on the pre-March window."""
    boundary = pd.Timestamp(cutoff)
    fitted = frame[frame["ts"] < boundary]
    if fitted.empty:
        raise AssertionError(f"no events below the baseline cutoff {boundary}")

    max_fitted = fitted["ts"].max()
    if not max_fitted < boundary:
        raise AssertionError(
            f"baseline fit leaked past the cutoff: max fitted ts {max_fitted} "
            f"is not below {boundary}"
        )

    ips: dict[str, set[str]] = defaultdict(set)
    succeeded: dict[str, set[str]] = defaultdict(set)
    forbidden: dict[str, set[str]] = defaultdict(set)
    seen: dict[str, set[str]] = defaultdict(set)
    hours: dict[str, Counter] = defaultdict(Counter)
    months: dict[str, set] = defaultdict(set)
    first_seen: dict[str, pd.Timestamp] = {}
    last_seen: dict[str, pd.Timestamp] = {}
    auth_fail_ts: dict[str, list] = defaultdict(list)
    auth_fail_by_host: dict[tuple, list] = defaultdict(list)

    template_freq: Counter = Counter()
    param_keys: dict[str, set[str]] = defaultdict(set)
    post_success: Counter = Counter()

    for row in fitted.itertuples(index=False):
        template_freq[row.template] += 1
        param_keys[row.template].update(_query_keys(row.query))
        if row.method == "POST" and row.status == 200:
            post_success[row.template] += 1

        user = row.user
        if user is None:
            continue

        ips[user].add(row.ip)
        seen[user].add(row.template)
        hours[user][row.ts.hour] += 1
        months[user].add((row.ts.year, row.ts.month))
        if user not in first_seen:
            first_seen[user] = row.ts
        last_seen[user] = row.ts

        if row.status == 200:
            succeeded[user].add(row.template)
        elif row.status == 403:
            forbidden[user].add(row.template)
        elif row.status == 401:
            auth_fail_ts[user].append(row.ts)
            auth_fail_by_host[(user, row.ip)].append(row.ts)

    burst_key = "max_in_{}s".format(AUTH_FAIL_WINDOW_S)
    users: dict[str, dict] = {}
    for user in sorted(ips):
        auth_fail = _gap_stats(auth_fail_ts[user])
        # The number S3 has to clear. Recording it here means the threshold is
        # justified by the file itself rather than by a claim on a slide.
        auth_fail[burst_key] = max(
            (
                _max_in_window(stamps, AUTH_FAIL_WINDOW_S)
                for (owner, _ip), stamps in auth_fail_by_host.items()
                if owner == user
            ),
            default=0,
        )
        users[user] = {
            "ips": sorted(ips[user]),
            # Allowed means at least one 200. Denied means at least one 403 and
            # no 200 ever: a user who was refused once and later succeeded is
            # the finding, not the baseline.
            "allowed_paths": sorted(succeeded[user]),
            "denied_paths": sorted(forbidden[user] - succeeded[user]),
            "templates_seen": sorted(seen[user]),
            # Explanation text only. This never triggers an alert: legitimate
            # off-hours access is everywhere in this dataset, including an
            # authorised reader pulling the confidential zip at 00:19 from her
            # own address, and a signal that fires on her turns the demo into
            # an argument about false positives.
            "hour_hist": {str(h): hours[user][h] for h in sorted(hours[user])},
            "months_observed": len(months[user]),
            "first_seen": first_seen[user].isoformat(),
            "last_seen": last_seen[user].isoformat(),
            "auth_fail": auth_fail,
        }

    # Reverse map. An address used by two people in the baseline has no single
    # owner, and unknown is null rather than a guess.
    owner_of: dict[str, set[str]] = defaultdict(set)
    for user, addresses in ips.items():
        for address in addresses:
            owner_of[address].add(user)
    ip_owner = {
        address: (sorted(owners)[0] if len(owners) == 1 else None)
        for address, owners in sorted(owner_of.items())
    }

    privileged = sorted(
        template
        for template in template_freq
        if template.startswith(PRIVILEGED_PREFIXES)
        or (
            post_success[template] > 0
            and template_freq[template] < rare_post_success_k
        )
    )

    return {
        "fit_window": {
            "start": fitted["ts"].min().isoformat(),
            "end": boundary.isoformat(),
            "max_fitted_ts": max_fitted.isoformat(),
        },
        "event_count": int(len(fitted)),
        "ip_owner": ip_owner,
        "users": users,
        "global": {
            "template_freq": dict(sorted(template_freq.items())),
            "param_keys": {k: sorted(v) for k, v in sorted(param_keys.items())},
            # Only templates the fitted window actually contains can be listed
            # here. Enumerating the admin endpoint out of March would be a leak
            # in the detector's own favour, which is worse than an empty list:
            # the rule below is what the runtime check evaluates, and it fires
            # on an endpoint the baseline has never seen.
            "privileged_templates": privileged,
            "privileged_rule": {
                "prefixes": list(PRIVILEGED_PREFIXES),
                "rare_post_success_k": rare_post_success_k,
                "rationale": (
                    "Everything under /api/admin/ is privileged by policy. "
                    "Beyond that, a POST returning 200 on a template seen "
                    "fewer than k times in seven months is an administrative "
                    "endpoint: the rarest legitimate template in the fitted "
                    "window appears 1778 times, so k=100 has an order of "
                    "magnitude of clearance on either side."
                ),
            },
            "auth_fail_window_s": AUTH_FAIL_WINDOW_S,
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--events", default=str(paths.events_path()))
    parser.add_argument("--out", default=str(paths.baselines_path()))
    parser.add_argument("--k", type=int, default=RARE_POST_SUCCESS_K)
    args = parser.parse_args()

    frame = pd.read_parquet(paths.require(Path(args.events)))
    document = build_baselines(frame, rare_post_success_k=args.k)

    window = document["fit_window"]
    print(f"cutoff      {window['end']}")
    print(f"max fitted  {window['max_fitted_ts']}  (assert: below the cutoff)")
    print(f"fitted      {document['event_count']:,} of {len(frame):,} events")

    odd = {u: d["ips"] for u, d in document["users"].items() if len(d["ips"]) != 1}
    if odd:
        # Not fatal, but it changes what S1 means, so it has to be loud.
        print(f"WARNING     users without exactly one baseline IP: {odd}")
    else:
        print(f"ips         {len(document['users'])} users, exactly one IP each")

    burst_key = "max_in_{}s".format(AUTH_FAIL_WINDOW_S)
    worst = max(
        (d["auth_fail"][burst_key], u) for u, d in document["users"].items()
    )
    print(
        f"auth_fail   worst baseline burst is {worst[0]} 401s in "
        f"{AUTH_FAIL_WINDOW_S}s ({worst[1]}); S3 fires at 3"
    )
    print(
        f"privileged  {document['global']['privileged_templates']} "
        f"(k={args.k}, prefixes={list(PRIVILEGED_PREFIXES)})"
    )

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(document, indent=2), encoding="utf-8")
    print(f"wrote       {out} ({out.stat().st_size / 1e3:.0f} KB)")


if __name__ == "__main__":
    main()
