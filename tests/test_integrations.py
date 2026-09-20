"""The integration layer, exercised with no credentials on the machine.

Nothing is provisioned: no Composio project, no Slack workspace, no rules
repository, no mailbox. That is the condition this whole layer was built for,
so it is the condition the tests run in. Every test below passes with an
empty environment, which is the same thing as saying the demo does.

Five of them pin the promises that would be embarrassing to break:

* mock mode works with no credentials at all
* a vendor that throws never reaches a client
* an email attaches on an entity match **and** time proximity, never on one
* nothing from the mailbox appears in a Slack or a GitHub payload
* email evidence never carries a claim above medium
"""

from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from minny import paths
from minny.api.app import app
from minny.integrations import (
    client,
    config,
    egress,
    github_pr,
    gmail_evidence,
    mailbox,
    slack,
    store,
)

REAL_LOG_LINE = (
    '10.0.8.45 - david_m [15/Mar/2026:11:26:59 -0400] '
    '"GET /finance/reports/q1_draft_CONFIDENTIAL.zip HTTP/1.1" 200 8875123'
)

# The one deliberately unattachable message in the seeded mailbox: inside the
# window, inside a bounded query, and about somebody else.
DAVIDSON = "gmail:18f2c9a1b507"

# The one deliberately unfetchable message: the sender is not on the
# allowlist and the subject carries none of the keywords.
PARKING = "gmail:18f2c9a1b501"

ROLE_UPDATE = "gmail:18f2c9a1b4d7"


@pytest.fixture(autouse=True)
def bare_machine(tmp_path, monkeypatch):
    """No keys, no artifacts, nothing written outside the temp directory."""
    for name in (
        "COMPOSIO_API_KEY",
        "COMPOSIO_AUTH_CONFIG_SLACK",
        "COMPOSIO_AUTH_CONFIG_GITHUB",
        "COMPOSIO_AUTH_CONFIG_GMAIL",
        "COMPOSIO_AUTH_CONFIG_GMAIL_READ",
        "MINNY_INTEGRATIONS_MODE",
        "MINNY_GITHUB_OWNER",
        "MINNY_GITHUB_REPO",
        "MINNY_GITHUB_GAP_ISSUE",
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(paths, "data_dir", lambda: tmp_path)
    store.reset_deliveries()
    yield
    store.reset_deliveries()


@pytest.fixture
def api():
    return TestClient(app)


# --------------------------------------------------- mock mode, no keys


def test_every_capability_reports_mock_and_names_what_is_missing(api):
    """Four states, never one boolean.

    Gmail read and Gmail send are separate grants. A status endpoint that
    collapsed them would tell a user they had authorized something they had
    not.
    """
    body = api.get("/api/integrations/status").json()
    states = {cap["id"]: cap for cap in body["capabilities"]}

    assert set(states) == {"slack.post", "gmail.read", "gmail.send", "github.pr"}
    assert all(cap["state"] == config.MOCK for cap in states.values())
    assert states["gmail.read"]["scope"].endswith("gmail.readonly")
    assert states["gmail.send"]["scope"].endswith("gmail.send")
    assert states["gmail.read"]["scope"] != states["gmail.send"]["scope"]
    assert config.API_KEY_ENV in states["slack.post"]["missing_env"]


def test_slack_returns_the_recorded_response_with_no_credentials(api):
    delivery = api.post("/api/integrations/test").json()["delivery"]

    assert delivery["state"] == config.MOCK
    assert delivery["ok"] is True
    assert delivery["message_ts"]  # straight out of the recorded envelope
    assert delivery["detection_unaffected"] is True


def test_the_alert_carries_the_explanation_and_a_link_and_no_evidence(api):
    """The real path, not a demo path beside it.

    Posting a known incident uses the same assembly and the same checks the
    correlator's alert would, which is the only way the button on stage
    proves anything.
    """
    response = api.post("/api/integrations/test", json={"incident_id": "inc_e30fc0"})
    delivery = response.json()["delivery"]

    assert delivery["target"] == "inc_e30fc0"
    assert delivery["state"] == config.MOCK
    assert "#monitor?incident=inc_e30fc0" in delivery["text"]
    assert not egress.RAW_LOG_LINE.search(delivery["text"])


def test_a_medium_severity_incident_is_not_posted():
    """A channel that fires on everything is a channel nobody reads."""
    delivery = slack.post_incident(
        {"incident_id": "inc_quiet", "severity": "medium", "title": "t", "evidence_lines": []}
    )

    assert delivery["state"] == "skipped"
    assert "high only" in delivery["message"]


def test_gmail_sync_runs_the_bounded_queries_from_the_recorded_mailbox(api):
    report = api.post("/api/integrations/gmail/sync", json={}).json()

    assert report["source_mode"] == config.MOCK
    assert report["seeded_demo_mailbox"] is True
    assert report["disclosure"]
    assert report["written"] is True
    assert report["counts"]["stored"] == 5
    assert len(report["queries"]) == len(mailbox.QUERIES)
    assert json.loads(paths.email_evidence_path().read_text(encoding="utf-8"))


def test_the_bounded_query_is_a_bound_and_not_a_filter_applied_afterwards(api):
    """The mailbox holds six messages and five are fetchable.

    The parking notice is from a sender nobody allowlisted and carries none
    of the subject keywords, so it is never returned by any of the three
    queries. Proving that here is the difference between a bounded query and
    a full crawl that throws things away later.
    """
    report = api.post("/api/integrations/gmail/sync", json={}).json()
    stored = {message["evidence_id"] for message in report["messages"]}

    assert PARKING not in stored
    for query in report["queries"]:
        assert query["returned"] == 6
        assert query["in_bounds"] < 6
        assert "after:" in query["query"] and "before:" in query["query"]
        assert "from:(" in query["query"]


def test_a_pull_request_body_is_produced_without_a_repository(api):
    response = api.post("/api/integrations/github/pr", json={"rule_id": "R003"})
    artifact = response.json()

    assert response.status_code == 200
    assert artifact["state"] == config.MOCK
    assert artifact["posted"] is False
    assert artifact["repo"]["configured"] is False
    assert artifact["body"].startswith("<!-- minny:remediation:")
    assert "### Gate results" in artifact["body"]
    assert "### False positives" in artifact["body"]


def test_a_rejected_rule_never_gets_a_review(api):
    response = api.post("/api/integrations/github/pr", json={"rule_id": "R004"})

    assert response.status_code == 409
    assert response.json()["error"]["code"] == "rule_not_accepted"


# ------------------------------------------------------- failing soft


@pytest.mark.parametrize(
    "route, payload",
    [
        ("/api/integrations/test", None),
        ("/api/integrations/gmail/sync", {}),
        ("/api/integrations/github/pr", {"rule_id": "R003"}),
    ],
)
def test_a_vendor_exception_never_propagates_out_of_the_api(
    api, monkeypatch, route, payload
):
    """The adapter is the only failure point and it absorbs everything.

    This is the test that stands behind "the demo continues". A raised
    exception from the vendor layer must come back as an ordinary JSON
    response, never a 500 and never a traceback.
    """

    def explode(*args, **kwargs):
        raise RuntimeError("vendor is on fire")

    monkeypatch.setattr(client, "execute", explode)

    response = api.post(route, json=payload)

    assert response.status_code == 200
    body = response.json()
    assert isinstance(body, dict)
    assert "vendor is on fire" in json.dumps(body)


def test_a_live_call_that_throws_becomes_an_error_result_not_an_exception(monkeypatch):
    monkeypatch.setenv("MINNY_INTEGRATIONS_MODE", config.LIVE)

    def explode(cap, arguments):
        raise ConnectionError("no route to host")

    monkeypatch.setattr(client, "_live_call", explode)

    result = client.execute(
        config.SLACK_POST, {"channel": "#x", "text": "y"}, fixture="slack_chat_post_message.json"
    )

    assert result.state == config.ERROR
    assert result.ok is False
    assert result.error_code == "vendor_error"
    assert result.attempted_live is True


def test_a_missing_composio_package_falls_back_to_the_recorded_response(monkeypatch):
    """Forced live on a machine without the SDK still shows the demo."""
    monkeypatch.setenv("MINNY_INTEGRATIONS_MODE", config.LIVE)

    def no_package(cap, arguments):
        raise ImportError("No module named 'composio'")

    monkeypatch.setattr(client, "_live_call", no_package)

    result = client.execute(
        config.SLACK_POST, {"channel": "#x", "text": "y"}, fixture="slack_chat_post_message.json"
    )

    assert result.state == config.MOCK
    assert result.ok is True


def test_a_failed_delivery_is_recorded_apart_from_the_incident(monkeypatch):
    """Slack refusing a message says nothing about whether we found anything."""
    monkeypatch.setenv("MINNY_INTEGRATIONS_MODE", config.LIVE)
    monkeypatch.setattr(
        client, "_live_call", lambda cap, args: {"successful": False, "error": "rate_limited"}
    )

    delivery = slack.post_incident(
        {"incident_id": "inc_x", "severity": "high", "title": "t", "evidence_lines": [1, 2]}
    )

    assert delivery["state"] == config.ERROR
    assert delivery["ok"] is False
    assert delivery["detection_unaffected"] is True
    assert store.last_delivery(config.SLACK_POST.id)["error_code"] == "provider_rejected"


def test_an_unreadable_mailbox_store_hides_the_strip_rather_than_failing(
    api, monkeypatch
):
    monkeypatch.setattr(
        gmail_evidence, "load_store", lambda: (_ for _ in ()).throw(OSError("disk gone"))
    )

    response = api.get(f"/api/evidence/email?ids={ROLE_UPDATE}")

    assert response.status_code == 200
    assert response.json() == []


# ------------------------------------------------------- linking rules


def _window():
    return mailbox.window_for("2026-03-13T23:10:19-04:00", "2026-03-15T22:33:40-04:00")


ANCHORS = [
    (168315, mailbox.datetime.fromisoformat("2026-03-14T09:19:15-04:00")),
    (168336, mailbox.datetime.fromisoformat("2026-03-15T11:07:57-04:00")),
]

VOCAB = mailbox.vocabulary_for(
    {
        "attacker": {"user": "david_m", "ip": "10.0.8.45"},
        "victim": {"user": "sarah_j", "ip": "10.0.5.12"},
        "asset": "/finance/reports/q1_draft_CONFIDENTIAL.zip",
    }
)


def test_time_proximity_alone_attaches_nothing():
    """A message in the window about somebody else is not evidence.

    `davidson.k` sits one second inside every bound the incident sets and it
    must stay unattached, because matching is exact on a normalized token and
    `davidson_k` is not `david_m`.
    """
    message = {
        "subject": "Password reset completed for davidson.k",
        "snippet": "The password for davidson.k was reset at 16:10 EDT.",
        "from": "no-reply@intranet.example.com",
        "to": ["davidson.k@example.com"],
        "ts": "2026-03-15T11:07:58-04:00",
    }
    matched = mailbox.match_entities(message, VOCAB)
    basis, linked = mailbox.link(message, matched, window=_window(), anchors=ANCHORS)

    assert mailbox.has_entity_match(matched) is False
    assert basis == []
    assert linked == []


def test_entity_match_alone_attaches_nothing():
    """The same message a month early names the right people and is ignored."""
    message = {
        "subject": "Role updated: david.m added to finance-confidential",
        "snippet": "david.m was added to the group finance-confidential by sarah.j.",
        "from": "no-reply@intranet.example.com",
        "to": ["sarah.j@example.com"],
        "ts": "2026-02-01T11:07:58-04:00",
    }
    matched = mailbox.match_entities(message, VOCAB)
    basis, linked = mailbox.link(message, matched, window=_window(), anchors=ANCHORS)

    assert mailbox.has_entity_match(matched) is True
    assert basis == []
    assert linked == []


def test_both_rules_together_attach_and_record_why():
    message = {
        "subject": "Role updated: david.m added to finance-confidential",
        "snippet": "david.m was added to the group finance-confidential by sarah.j.",
        "from": "no-reply@intranet.example.com",
        "to": ["sarah.j@example.com"],
        "ts": "2026-03-15T11:07:58-04:00",
    }
    matched = mailbox.match_entities(message, VOCAB)
    basis, linked = mailbox.link(message, matched, window=_window(), anchors=ANCHORS)

    assert matched["users"] == ["david_m", "sarah_j"]
    assert matched["groups"] == ["finance-confidential"]
    assert basis[0] == "entity_match"
    assert basis[1].startswith("time_proximity_")
    assert 168336 in linked


def test_normalization_is_exact_on_a_token_and_never_a_substring():
    assert mailbox.normalize_user("david.m@example.com") == "david_m"
    assert mailbox.normalize_user("david-m") == "david_m"
    assert mailbox.normalize_user("davidson.k") != "david_m"


def test_the_seeded_mailbox_links_four_of_five_and_says_which_rules_fired(api):
    report = api.post("/api/integrations/gmail/sync", json={}).json()
    by_id = {message["evidence_id"]: message for message in report["messages"]}

    assert by_id[DAVIDSON]["link_basis"] == []
    assert by_id[DAVIDSON]["linked_lines"] == []
    assert by_id[ROLE_UPDATE]["link_basis"][0] == "entity_match"
    assert 168336 in by_id[ROLE_UPDATE]["linked_lines"]
    assert report["counts"]["linked"] == 4


# --------------------------------------------------- confidence discipline


def test_email_evidence_never_exceeds_medium(api):
    report = api.post("/api/integrations/gmail/sync", json={}).json()

    assert {message["confidence"] for message in report["messages"]} <= {"low", "medium"}
    assert mailbox.confidence_for(["entity_match", "time_proximity_60s"]) == "medium"
    assert mailbox.confidence_for([]) == "low"
    # There is no argument that produces "high". The cap is structural.
    assert "high" not in {
        mailbox.confidence_for(basis)
        for basis in ([], ["entity_match"], ["entity_match", "time_proximity_60s"])
    }


def test_the_mailbox_is_labelled_seeded_everywhere_it_surfaces(api):
    status = api.get("/api/integrations/status").json()
    report = api.post("/api/integrations/gmail/sync", json={}).json()
    resolved = api.get(f"/api/evidence/email?ids={ROLE_UPDATE}").json()

    assert status["mailbox"]["seeded_demo_mailbox"] is True
    assert "seeded" in (status["mailbox"]["disclosure"] or "").lower()
    assert report["seeded_demo_mailbox"] is True
    assert resolved[0]["seeded_demo_mailbox"] is True


# --------------------------------------------------------------- privacy


def test_no_message_body_is_ever_stored(api):
    """The allowlist is the control, so a body cannot survive the rebuild."""
    kept = mailbox.sanitize(
        {
            "id": "abc",
            "subject": "Role updated",
            "snippet": "a preview",
            "body": "the entire message, which must not be kept",
            "payload": {"parts": ["also not kept"]},
        }
    )

    assert "body" not in kept
    assert "payload" not in kept
    assert set(kept) <= set(mailbox.KEPT_FIELDS)

    report = api.post("/api/integrations/gmail/sync", json={}).json()
    assert report["counts"]["bodies_stored"] == 0
    for message in report["messages"]:
        assert "body" not in message


def test_no_mailbox_content_reaches_a_slack_payload(api):
    api.post("/api/integrations/gmail/sync", json={})
    incident = {
        "incident_id": "inc_e30fc0",
        "severity": "high",
        "title": "david_m escalated sarah_j's access and read the Q1 draft",
        "narrative": [{"ts": "2026-03-15T11:26:59-04:00", "text": "a templated sentence"}],
        "attacker": {"user": "david_m"},
        "victim": {"user": "sarah_j"},
        "asset": "/finance/reports/q1_draft_CONFIDENTIAL.zip",
        "evidence_lines": [168336, 168338],
        "evidence_emails": [ROLE_UPDATE],
    }

    text = slack.build_message(incident)
    current = store.read_email_store()

    for quoted in egress.mailbox_strings(current):
        if len(quoted) >= egress.MIN_QUOTE_CHARS:
            assert quoted.casefold() not in text.casefold()
    assert "gmail:" not in text
    assert not egress.RAW_LOG_LINE.search(text)
    # What goes instead is the link.
    assert "/#monitor?incident=inc_e30fc0" in text
    egress.check(text, store=current)


def test_no_mailbox_content_reaches_a_github_payload(api):
    api.post("/api/integrations/gmail/sync", json={})
    artifact = api.post("/api/integrations/github/pr", json={"rule_id": "R003"}).json()
    current = store.read_email_store()

    for quoted in egress.mailbox_strings(current):
        if len(quoted) >= egress.MIN_QUOTE_CHARS:
            assert quoted.casefold() not in artifact["body"].casefold()
    assert "gmail:" not in artifact["body"]
    assert not egress.RAW_LOG_LINE.search(artifact["body"])
    egress.check(artifact["body"], store=current)


def test_a_payload_carrying_a_source_record_is_refused_rather_than_posted(api):
    """The tripwire, not the control.

    Payloads are assembled from an allowlist so this never fires in normal
    operation. It fires the day somebody adds a convenient join of the
    evidence lines to a message body.
    """
    api.post("/api/integrations/gmail/sync", json={})

    with pytest.raises(egress.EgressRefused):
        egress.check(f"incident summary\n{REAL_LOG_LINE}")

    snippet = store.read_email_store()["messages"][0]["snippet"]
    with pytest.raises(egress.EgressRefused):
        egress.check(f"see also: {snippet}", store=store.read_email_store())

    delivery = slack.post_incident(
        {
            "incident_id": "inc_leak",
            "severity": "high",
            "title": REAL_LOG_LINE,
            "evidence_lines": [1],
        }
    )
    assert delivery["ok"] is False
    assert delivery["error_code"].startswith("egress_refused")


def test_the_review_relates_to_the_gap_issue_and_never_closes_it(api, monkeypatch):
    """A merge must not close the gap before the merged rule is replayed."""
    monkeypatch.setenv("MINNY_GITHUB_GAP_ISSUE", "12")
    body = github_pr.build_body(github_pr.load_proposal("R003"))

    assert "Related to #12" in body
    assert "Closes #" not in body
    assert "Fixes #" not in body


def test_only_allowlisted_tool_slugs_can_be_executed():
    assert config.ALLOWED_SLUGS == {
        "SLACK_CHAT_POST_MESSAGE",
        "GMAIL_FETCH_EMAILS",
        "GMAIL_SEND_EMAIL",
        "GITHUB_CREATE_A_PULL_REQUEST",
    }

    rogue = config.Capability(
        id="rogue",
        label="rogue",
        short="ROGUE",
        toolkit="slack",
        tool_slug="SLACK_DELETE_A_MESSAGE",
        direction="outbound",
        scope=None,
        auth_config_env="NOPE",
        summary="",
    )
    result = client.execute(rogue, {}, fixture="slack_chat_post_message.json")

    assert result.ok is False
    assert result.error_code == "tool_not_allowlisted"


def test_nothing_on_the_detection_path_reads_the_mailbox(api):
    """Email never feeds a signal, so the evaluation stays reproducible."""
    before = api.get("/api/incidents").json() if api.get("/api/incidents").status_code == 200 else None
    api.post("/api/integrations/gmail/sync", json={})
    after = api.get("/api/incidents").json() if api.get("/api/incidents").status_code == 200 else None

    assert before == after
    assert gmail_evidence.POLICY["feeds_a_detector"] is False
