"""The rule DSL: what parses, what does not, and what it does when it runs.

The rules in detection-rules/rules.yaml are written by a language model and
loaded unattended at three in the morning. Two properties matter more than
any individual rule.

Nothing in the file reaches an interpreter. The tests below throw Python at
the parser and expect parse errors, not results, and there is no eval, exec
or import anywhere in minny/detect/rules.py for them to reach.

A bad rule is skipped, never fatal. A rule that does not parse, one that
nests too deeply, one with a duplicate id and a file that is not valid YAML
at all each leave the working rules working.

The grammar additions, `query` and `contains`, get their own section. They
exist so an overfitted rule can be written at all, and the point of writing
it is that it catches the March payloads exactly and dies on a renamed
parameter.
"""

from __future__ import annotations

import textwrap
from datetime import datetime, timedelta, timezone

import pytest

from minny.baselines.model import Baselines
from minny.detect.events import DetectEvent
from minny.detect.replay import Pipeline
from minny.detect.rules import (
    MAX_DEPTH,
    MAX_NODES,
    RuleSet,
    parse_expression,
)

LOG_TZ = timezone(timedelta(hours=-4))

BASELINE_DOC = {
    "event_count": 157818,
    "ip_owner": {"10.0.5.12": "sarah_j", "10.0.8.45": "david_m"},
    "users": {
        "david_m": {
            "ips": ["10.0.8.45"],
            "allowed_paths": ["/intranet/forum/new"],
            "denied_paths": [],
            "denied_counts": {},
            "templates_seen": ["/intranet/forum/new"],
            "months_observed": 7,
            "auth_fail": {"count": 0, "max_in_30s": 0},
        },
        "sarah_j": {
            "ips": ["10.0.5.12"],
            "allowed_paths": ["/api/auth/login"],
            "denied_paths": [],
            "denied_counts": {},
            "templates_seen": ["/api/auth/login"],
            "months_observed": 7,
            "auth_fail": {"count": 14, "max_in_30s": 1},
        },
    },
    "global": {
        "template_freq": {"/intranet/forum/new": 7933, "/api/auth/login": 7819},
        "param_keys": {"/intranet/forum/new": ["topic"], "/api/auth/login": []},
        "privileged_templates": [],
        "privileged_rule": {"prefixes": ["/api/admin/"], "rare_post_success_k": 100},
        "status_freq": {"200": 122229, "302": 30154, "401": 782},
        "rare_status_n": 10,
    },
}


@pytest.fixture()
def baselines():
    return Baselines.from_document(BASELINE_DOC)


def event(
    line: int = 1,
    second: int = 0,
    user: str = "david_m",
    ip: str = "10.0.8.45",
    path: str = "/intranet/forum/new",
    query: dict | None = None,
    status: int = 302,
    method: str = "POST",
    template: str | None = None,
) -> DetectEvent:
    base = path.split("?", 1)[0]
    return DetectEvent(
        line=line,
        ts=datetime(2026, 3, 15, 9, 20, tzinfo=LOG_TZ) + timedelta(seconds=second),
        ip=ip,
        user=user,
        method=method,
        path=path,
        base=base,
        query=query or {},
        status=status,
        size=112,
        template=template or base,
        obj_id=None,
        raw=f"{ip} - {user} [15/Mar/2026] \"{method} {path}\" {status} 112",
    )


def ruleset(*entries) -> RuleSet:
    return RuleSet.from_documents(list(entries))


def rule(when: str, rule_id: str = "R1", **extra) -> dict:
    document = {
        "id": rule_id,
        "name": extra.pop("name", "a rule"),
        "severity": extra.pop("severity", "high"),
        "when": when,
        "explain": extra.pop("explain", "{user} matched from {ip}."),
    }
    document.update(extra)
    return document


# ------------------------------------------------------------------ parsing


def test_the_contract_example_parses_to_the_numbers_the_proposals_report():
    """C's fixture says depth 2, 7 nodes. The parser has to agree with it."""
    parsed = parse_expression(
        "count(status=401, user=$u, window=24h) >= 5 AND ip_owner != $u"
    )
    assert parsed.as_dict() == {"ok": True, "depth": 2, "nodes": 7, "error": None}


def test_the_overfitted_rule_parses_to_the_numbers_the_proposals_report():
    parsed = parse_expression(
        'template == "/intranet/forum/new" AND query CONTAINS "csrf"'
    )
    assert parsed.as_dict() == {"ok": True, "depth": 2, "nodes": 5, "error": None}


@pytest.mark.parametrize(
    "expression",
    [
        '__import__("os").system("rm -rf /")',
        "open('/etc/passwd').read()",
        "user == $u; print(1)",
        'template == "x" AND eval("1+1")',
        "lambda: 1",
    ],
)
def test_code_never_parses(expression):
    """There is no interpreter behind this. These are parse errors, not results."""
    assert parse_expression(expression).ok is False


def test_depth_beyond_the_cap_is_rejected():
    deep = "NOT (NOT (NOT (NOT (status == 200))))"
    parsed = parse_expression(deep)
    assert parsed.ok is False
    assert str(MAX_DEPTH) in parsed.error
    assert parsed.depth > MAX_DEPTH


def test_node_count_beyond_the_cap_is_rejected():
    """Wide rather than deep, so it is the node cap that catches it."""
    wide = "count(" + ", ".join(["status=401"] * 30) + ") >= 1"
    parsed = parse_expression(wide)
    assert parsed.ok is False
    assert parsed.depth <= MAX_DEPTH
    assert parsed.nodes > MAX_NODES
    assert str(MAX_NODES) in parsed.error


def test_an_unknown_field_is_named_in_the_error():
    parsed = parse_expression('country == "CA"')
    assert parsed.ok is False
    assert "country" in parsed.error


def test_ordering_operators_are_numeric_fields_only():
    assert parse_expression("obj_id >= 1000").ok is True
    assert parse_expression("status < 500").ok is True
    broken = parse_expression('user >= "m"')
    assert broken.ok is False
    assert "user" in broken.error


def test_an_empty_when_is_an_error_rather_than_a_rule_that_matches_everything():
    assert parse_expression("").ok is False
    assert parse_expression(None).ok is False


# --------------------------------------------------- the grammar additions


def test_contains_is_defined_on_query_and_template_and_nowhere_else():
    assert parse_expression('query contains "csrf"').ok is True
    assert parse_expression('template contains "/api/admin/"').ok is True
    refused = parse_expression('user contains "david"')
    assert refused.ok is False
    assert "contains" in refused.error


def test_query_matches_a_parameter_key_or_a_parameter_value(baselines):
    rules = ruleset(rule('query contains "csrf"'))
    payload = event(query={"topic": "lunch_menu", "payload": "csrf_test"})
    assert len(rules.evaluate(payload, baselines)) == 1

    rules.reset()
    named = event(query={"csrf_token": "abc"})
    assert len(rules.evaluate(named, baselines)) == 1


def test_the_csrf_rule_catches_the_march_payloads_and_misses_a_renamed_one(baselines):
    """The reason the grammar was extended, stated as a test.

    A rule matching the literal string the attacker happened to use catches
    the real incident perfectly. Rename the parameter and it catches nothing.
    That is the difference between memorising a case and detecting a class of
    behaviour, and it is only demonstrable if the rule parses in the first
    place.
    """
    rules = ruleset(
        rule(
            'template == "/intranet/forum/new" AND query contains "csrf"',
            rule_id="R004",
            name="csrf payload in a forum parameter",
        )
    )
    real = [
        event(line=168330, query={"topic": "lunch_menu", "payload": "csrf_test"}),
        event(line=168331, second=1, query={"topic": "q1_updates",
                                            "action": "csrf_role_update"}),
    ]
    caught = [alert for item in real for alert in rules.evaluate(item, baselines)]
    assert [alert["evidence_lines"] for alert in caught] == [[168330], [168331]]

    rules.reset()
    renamed = event(
        line=900001, query={"topic": "q1_updates", "ref": "xsrf_role_update"}
    )
    assert rules.evaluate(renamed, baselines) == []


def test_query_equality_is_membership_not_the_whole_string(baselines):
    rules = ruleset(rule('query == "csrf_test"'))
    assert len(rules.evaluate(event(query={"payload": "csrf_test"}), baselines)) == 1
    rules.reset()
    assert rules.evaluate(event(query={"payload": "csrf_testing"}), baselines) == []


# --------------------------------------------------------------- evaluation


def test_a_rule_reads_the_same_fields_the_signals_read(baselines):
    rules = ruleset(rule('template contains "/api/admin/" AND ip_owner != $u'))
    borrowed = event(
        user="sarah_j",
        ip="10.0.8.45",
        path="/api/admin/role_update",
        template="/api/admin/role_update",
        status=200,
    )
    alerts = rules.evaluate(borrowed, baselines)
    assert len(alerts) == 1
    assert alerts[0]["ip_owner"] == "david_m"

    rules.reset()
    own = event(
        user="sarah_j",
        ip="10.0.5.12",
        path="/api/admin/role_update",
        template="/api/admin/role_update",
        status=200,
    )
    assert rules.evaluate(own, baselines) == []


def test_a_rule_alert_is_the_same_object_a_signal_produces(baselines):
    rules = ruleset(
        rule(
            'query contains "csrf"',
            rule_id="R004",
            name="csrf payload in a forum parameter",
            explain="{user} sent a forum parameter containing csrf from {ip}.",
        )
    )
    alert = rules.evaluate(event(query={"payload": "csrf_test"}), baselines)[0]
    assert set(alert) >= {
        "alert_id", "ts", "signal", "signal_name", "severity", "user", "ip",
        "ip_owner", "template", "obj_id", "value", "evidence_lines",
        "explanation", "incident_id",
    }
    assert alert["alert_id"].startswith("a_")
    assert alert["signal"] == "R004"
    assert alert["signal_name"] == "csrf payload in a forum parameter"
    assert alert["explanation"] == (
        "david_m sent a forum parameter containing csrf from 10.0.8.45."
    )
    assert alert["value"]["rule_id"] == "R004"
    assert alert["incident_id"] is None


def test_an_explanation_asking_for_a_field_it_did_not_compute_says_unknown(baselines):
    rules = ruleset(rule('query contains "csrf"', explain="{user} at {nonsense}."))
    alert = rules.evaluate(event(query={"payload": "csrf_test"}), baselines)[0]
    assert alert["explanation"] == "david_m at unknown."


def test_count_counts_the_window_including_the_event_it_fires_on(baselines):
    rules = ruleset(
        rule(
            "count(status=401, user=$u, window=24h) >= 5 AND ip_owner != $u",
            rule_id="R003",
            explain="{user} failed to log in {count} times from {ip}.",
        )
    )
    failures = [
        event(
            line=index,
            second=index,
            user="sarah_j",
            ip="10.0.8.45",
            path="/api/auth/login",
            status=401,
            query={},
        )
        for index in range(1, 7)
    ]
    fired = [alert for item in failures for alert in rules.evaluate(item, baselines)]
    # Five failures is the threshold, so the fifth and the sixth fire.
    assert len(fired) == 2
    assert fired[0]["explanation"] == (
        "sarah_j failed to log in 5 times from 10.0.8.45."
    )
    assert fired[0]["value"]["counts"] == [5]


def test_count_forgets_what_falls_out_of_its_window(baselines):
    rules = ruleset(rule("count(status=401, user=$u, window=30s) >= 3"))
    spread = [
        event(line=index, second=index * 20, user="sarah_j",
              path="/api/auth/login", status=401)
        for index in range(1, 5)
    ]
    assert [alert for item in spread for alert in rules.evaluate(item, baselines)] == []


def test_a_rule_alert_joins_the_incident_through_the_normal_correlator(baselines):
    """Rules emit through the same path, so the correlator treats them alike."""
    rules = ruleset(rule('query contains "csrf"', rule_id="R004"))
    pipeline = Pipeline(baselines, rules=rules)
    frames = pipeline.feed(event(line=168330, query={"payload": "csrf_test"}))
    alerts = [frame.data for frame in frames if frame.type == "alert"]
    assert any(alert["signal"] == "R004" for alert in alerts)
    incident = [frame.data for frame in frames if frame.type == "incident"][-1]
    assert "R004" in {
        alert["signal"] for alert in pipeline.alerts
    }
    assert incident["alert_count"] == len(pipeline.alerts)


# ----------------------------------------------------- loading and reloading


def write(path, text: str) -> None:
    path.write_text(textwrap.dedent(text).lstrip("\n"), encoding="utf-8")


def test_a_rule_that_does_not_parse_is_skipped_and_never_fatal(tmp_path):
    target = tmp_path / "rules.yaml"
    write(
        target,
        """
        - id: R1
          name: fine
          severity: high
          when: status == 500
        - id: R2
          name: broken
          severity: high
          when: user LIKE 'admin%'
        - id: R3
          name: also fine
          severity: medium
          when: obj_id == 1042
        """,
    )
    rules = RuleSet.load(target)
    assert [item.id for item in rules.rules if item.ok] == ["R1", "R3"]
    assert [failure["id"] for failure in rules.errors] == ["R2"]
    assert "LIKE" in rules.errors[0]["error"]

    described = rules.describe()
    broken = next(item for item in described["rules"] if item["id"] == "R2")
    assert broken["enabled"] is False
    assert broken["parse"]["ok"] is False
    assert described["counts"] == {"loaded": 3, "enabled": 2, "errors": 1}


def test_a_broken_rule_does_not_stop_the_working_ones_firing(tmp_path, baselines):
    target = tmp_path / "rules.yaml"
    write(
        target,
        """
        - id: R2
          name: broken
          severity: high
          when: user LIKE 'admin%'
        - id: R4
          name: works
          severity: high
          when: query contains "csrf"
          explain: "{user} matched."
        """,
    )
    rules = RuleSet.load(target)
    alerts = rules.evaluate(event(query={"payload": "csrf_test"}), baselines)
    assert [alert["signal"] for alert in alerts] == ["R4"]


@pytest.mark.parametrize(
    ("body", "expected_error"),
    [
        ("- name: no id\n  when: status == 500\n", "missing required key"),
        ("- id: R1\n  name: no when\n", "missing required key"),
        ("- id: R1\n  when: status == 500\n- id: R1\n  when: status == 400\n",
         "duplicate rule id"),
        ("- id: R1\n  when: status == 500\n  severity: catastrophic\n", "severity"),
        ("rules: not a list\n", "must be a list"),
    ],
)
def test_a_malformed_entry_is_described_rather_than_raised(tmp_path, body, expected_error):
    target = tmp_path / "rules.yaml"
    target.write_text(body, encoding="utf-8")
    rules = RuleSet.load(target)
    assert rules.errors
    assert expected_error in rules.errors[0]["error"]


def test_a_file_that_is_not_yaml_leaves_the_loaded_rules_live(tmp_path, baselines):
    """The blue agent writes here while a replay runs. A half-written file is
    a moment, not a reason to disarm the detector."""
    target = tmp_path / "rules.yaml"
    write(
        target,
        """
        - id: R4
          name: works
          severity: high
          when: query contains "csrf"
        """,
    )
    rules = RuleSet.load(target)
    assert len(rules.rules) == 1

    target.write_text("- id: R4\n  when: [unclosed\n", encoding="utf-8")
    rules.maybe_reload()
    assert [item.id for item in rules.rules] == ["R4"]
    assert rules.errors and rules.errors[0]["scope"] == "file"
    assert rules.evaluate(event(query={"payload": "csrf_test"}), baselines)


def test_a_missing_file_is_an_empty_ruleset_rather_than_an_error(tmp_path):
    rules = RuleSet.load(tmp_path / "nothing.yaml")
    assert rules.rules == []
    assert rules.errors == []


def test_rules_reload_when_the_file_changes(tmp_path, baselines):
    target = tmp_path / "rules.yaml"
    write(
        target,
        """
        - id: R1
          name: first
          severity: high
          when: status == 500
        """,
    )
    rules = RuleSet.load(target)
    assert [item.id for item in rules.rules] == ["R1"]
    assert rules.maybe_reload() is False

    write(
        target,
        """
        - id: R1
          name: first
          severity: high
          when: status == 500
        - id: R2
          name: appended by the blue agent
          severity: high
          when: query contains "csrf"
          explain: "{user} matched."
        """,
    )
    assert rules.maybe_reload() is True
    assert [item.id for item in rules.rules] == ["R1", "R2"]
    alerts = rules.evaluate(event(query={"payload": "csrf_test"}), baselines)
    assert [alert["signal"] for alert in alerts] == ["R2"]


def test_the_shipped_rules_file_parses(baselines):
    """Whatever is in the repository has to load, every time."""
    from minny import paths

    rules = RuleSet.load(paths.rules_path())
    assert rules.errors == []
    assert all(item.ok for item in rules.rules)


def test_the_shipped_rules_stay_silent_on_ordinary_traffic(baselines):
    from minny import paths

    rules = RuleSet.load(paths.rules_path())
    ordinary = [
        event(line=1, user="sarah_j", ip="10.0.5.12", path="/api/auth/login",
              status=200, method="POST"),
        event(line=2, second=1, user="david_m", path="/intranet/forum/new",
              query={"topic": "lunch_menu"}),
    ]
    assert [alert for item in ordinary for alert in rules.evaluate(item, baselines)] == []
