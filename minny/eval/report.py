"""The evaluation as a person reads it (milestone M5).

metrics.json is what D renders and what the stage quotes, but the command has
to be readable on its own: the person running it at 02:30 needs to see which
evasion worked without opening a JSON file and counting braces.

Every figure printed here is read back out of the built metrics dictionary
rather than recomputed from the outcomes. Two code paths producing the same
number is two chances for them to disagree, and the one on screen is the one
that would be wrong.
"""

from __future__ import annotations

import textwrap

WIDTH = 88

# Wide enough for outsider_with_stolen_credentials. A persona that wraps
# breaks the column alignment of every row under it.
NAME_W = 34


def _pct(value) -> str:
    return "n/a" if value is None else f"{value * 100:5.1f}%"


def _secs(value) -> str:
    """Log-time seconds, rendered at the scale the number actually lives at."""
    if value is None:
        return "n/a"
    if value < 90:
        return f"{value:.0f}s"
    if value < 5400:
        return f"{value / 60:.1f}m"
    return f"{value / 3600:.1f}h"


def _rule(char: str = "-") -> str:
    return char * WIDTH


def _table(title: str, rows: dict, *, intro: str | None = None) -> list[str]:
    out = ["", title, _rule()]
    if intro:
        out.append(intro)
        out.append("")
    out.append(
        f"{'name':<{NAME_W}}{'n':>5}{'caught':>8}{'rate':>8}"
        f"{'attacker':>10}{'victim':>8}{'both':>7}{'median':>8}"
    )
    for name, row in rows.items():
        out.append(
            f"{name:<{NAME_W}}{row['n']:>5}{row['detected']:>8}{_pct(row['rate']):>8}"
            f"{row['attacker_correct']:>10}{row['victim_correct']:>8}"
            f"{row['both_correct']:>7}{_secs(row['median_log_seconds']):>8}"
        )
    return out


def _signal_table(rows: dict) -> list[str]:
    out = [
        "",
        "DETECTION BY SIGNAL",
        _rule(),
        "How much each signal caught, how much only it caught, and what "
        "detection would be",
        "without it. The `sole` column is where the detection rate actually "
        "lives.",
        "",
        f"{'signal':<{NAME_W}}{'caught':>8}{'rate':>8}{'sole':>7}{'without it':>13}",
    ]
    for signal, row in rows.items():
        label = f"{signal} {row['signal_name']}"
        out.append(
            f"{label:<{NAME_W}}{row['caught']:>8}{_pct(row['rate']):>8}"
            f"{row['sole']:>7}{_pct(row['detection_without']):>13}"
        )
    return out


def _coverage_matrix(operators: dict, signals: dict) -> list[str]:
    """Which evasion switched which signal off.

    The point of the whole table. Two operator rows can both read 100% caught
    and be doing completely different things to the detector, and this is the
    only place that difference is visible.
    """
    names = list(signals)
    header = "".join(f"{name:>6}" for name in names)
    out = [
        "",
        "SIGNALS FIRED PER OPERATOR",
        _rule(),
        "Variants carrying the operator on which each signal fired. A zero "
        "column under an",
        "operator is that operator doing its job, whether or not another "
        "signal covered for it.",
        "",
        f"{'operator':<{NAME_W}}{'n':>5}{header}",
    ]
    for name, row in operators.items():
        cells = "".join(f"{row['signals'][signal]:>6}" for signal in names)
        out.append(f"{name:<{NAME_W}}{row['n']:>5}{cells}")
    return out


def render(metrics: dict) -> str:
    detection = metrics["detection"]
    attribution = metrics["attribution"]
    fp = metrics["false_positives"]
    ttd = metrics["time_to_detect"]
    real = metrics["real_incident"]
    variants = metrics["variants"]

    out = [
        _rule("="),
        f"minny evaluation   seed {metrics['seed']}   {metrics['rule_revision']}",
        _rule("="),
        f"variants        {variants['total']} accepted, "
        f"{variants['declared_operators']} operator declarations, "
        f"{variants['without_operators']} carrying none",
        f"method          {metrics['method']['injection']}, "
        f"{metrics['method']['replays']} replays",
        f"detected when   {metrics['method']['detected_when']}",
    ]

    out += _table(
        "DETECTION BY OPERATOR",
        detection["by_operator"],
        intro="One row per evasion. A low rate is a gap, and it is the row the "
        "blue agent is pointed at.",
    )
    out += _signal_table(detection["by_signal"])
    out += _coverage_matrix(detection["by_operator"], detection["by_signal"])
    out += _table("DETECTION BY FAMILY", detection["by_family"])
    out += _table("DETECTION BY PERSONA", detection["by_persona"])

    out += [
        "",
        "OVERALL",
        _rule(),
        f"detection       {_pct(detection['overall'])} "
        f"({detection['detected']}/{detection['n']})",
        f"attribution     attacker {_pct(attribution['attacker_correct_rate'])} "
        f"({attribution['attacker_correct']}/{attribution['n_detected']}), "
        f"victim {_pct(attribution['victim_correct_rate'])} "
        f"({attribution['victim_correct']}/{attribution['n_detected']}), "
        f"both {_pct(attribution['both_correct_rate'])}",
        f"unnamed         attacker unnamed in {attribution['unnamed_attacker']} "
        f"detected incidents, victim unnamed in {attribution['unnamed_victim']}",
        f"misattributed   {attribution['misattributed_attacker']} attackers "
        f"and {attribution['misattributed_victim']} victims named as the wrong "
        f"account",
        "",
        "FALSE POSITIVES",
        _rule(),
        f"stream          {fp['benign_stream']}",
        f"alerts          {fp['alerts_total']} over {fp['days']} days "
        f"({fp['alerts_per_day']:.2f} per day)",
        f"incidents       {fp['incidents_total']} "
        f"({fp['incidents_per_day']:.2f} per day)",
        "",
        "TIME TO DETECT",
        _rule(),
        f"log time        median {_secs(ttd['median_log_seconds'])}, "
        f"p90 {_secs(ttd['p90_log_seconds'])}, "
        f"range {_secs(ttd['min_log_seconds'])} to "
        f"{_secs(ttd['max_log_seconds'])}, n={ttd['n']}",
        f"wall clock      {ttd['wallclock_ms_per_event']:.4f} ms per event "
        f"over {ttd['wallclock_events']:,} events "
        f"({ttd['wallclock_seconds']:.1f}s of detector time)",
        "",
        "REAL INCIDENT, 13-15 MARCH",
        _rule(),
        f"detected        {'yes' if real['detected'] else 'no'}"
        + (f"  {real['incident_id']}" if real["incident_id"] else ""),
        f"attribution     attacker {real['named_attacker']} "
        f"({'correct' if real['attacker_correct'] else 'wrong'}), "
        f"victim {real['named_victim']} "
        f"({'correct' if real['victim_correct'] else 'wrong'})",
        f"alerts          {real['alert_count']} citing "
        f"{real['labeled_lines_cited']} of {real['labeled_lines_total']} "
        f"labeled lines",
    ]

    out += ["", "EVADED DETECTION ENTIRELY", _rule()]
    if metrics["evasions"]:
        for row in metrics["evasions"]:
            out.append(
                f"{row['operator']:<{NAME_W}}{row['missed']:>5} of {row['n']:<5} "
                f"missed, {_pct(row['rate'])} caught"
            )
    else:
        out.append(
            "nothing. No operator produced a variant that reached the end of "
            "the stream unalerted."
        )

    out += [
        "",
        "EVADED A SIGNAL",
        _rule(),
        "Operator and signal pairs where the signal lost at least half its "
        "reach against",
        "variants of the same families without that operator, on at least "
        "five control",
        "firings. These are what the blue agent is pointed at, whether or not "
        "another",
        "signal covered for them. The full list is in metrics.json.",
        "",
        f"{'operator':<24}{'signal':<14}{'with':>12}{'control':>12}{'suppressed':>12}",
    ]
    # Two guards, both stated above the table. Half the reach is the effect
    # size worth a rule, and five control firings is the point below which a
    # zero is as likely to be the draw as the operator.
    material = [
        row
        for row in metrics["signal_suppression"]
        if row["suppression"] >= 0.5 and row["control_fired"] >= 5
    ]
    for row in material:
        fired = "{}/{}".format(row["fired"], row["n"])
        control = "{}/{}".format(row["control_fired"], row["control_n"])
        out.append(
            f"{row['operator']:<24}{row['signal']:<14}{fired:>12}{control:>12}"
            f"{_pct(row['suppression']):>12}"
        )
    if not material:
        out.append("nothing lost half its reach.")

    out += ["", "NOTES", _rule()]
    for note in metrics["notes"]:
        out += _wrap(note)
    return "\n".join(out)


def _wrap(text: str) -> list[str]:
    return textwrap.wrap(text, width=WIDTH - 2, initial_indent="  ",
                         subsequent_indent="  ") + [""]
