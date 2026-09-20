"""The findings, pinned to the lines the queries actually returned.

These are the numbers said on stage. If the dataset is ever swapped or a
query is loosened, this file fails loudly instead of the case file quietly
citing evidence that no longer supports it.
"""

from __future__ import annotations

import pytest

from minny import paths
from minny.api.routes_case import MAX_LINES
from minny.casefile import build, queries

needs_dataset = pytest.mark.skipif(
    not paths.events_path().exists(),
    reason="data/events.parquet is shared out of band; set MINNY_DATA_DIR",
)

pytestmark = needs_dataset

BURST_ONE = [168311, 168312, 168313, 168314]
BURST_TWO = [168321, 168322, 168323, 168324, 168325, 168326]
NIGHT_SESSION = [168343, 168344, 168345, 168346]
PAYLOAD_ATTEMPTS = [168330, 168331, 168332]
CONFIDENTIAL_ZIP = "/finance/reports/q1_draft_CONFIDENTIAL.zip"


@pytest.fixture(scope="module")
def events():
    return queries.load_events()


@pytest.fixture(scope="module")
def results(events):
    return queries.run_all(events)


@pytest.fixture(scope="module")
def case_file(events):
    return build.build_case_file(events)


# --- the findings ----------------------------------------------------------


def test_f1_ip_binding_breaks_exactly_once(results):
    result = results["ip_user_mismatch"]
    assert result.lines == BURST_ONE + BURST_TWO + NIGHT_SESSION
    assert result.stats["violating_users"] == ["sarah_j"]
    assert result.stats["foreign_ips"] == ["10.0.8.45"]
    assert result.stats["foreign_ip_owners"] == ["david_m"]
    # Nine users on one IP for the whole file, ten for the baseline window.
    assert result.stats["users_with_one_ip_overall"] == 9
    assert result.stats["users_with_one_ip_in_baseline"] == 10


def test_f2_two_bursts_and_no_others(results):
    result = results["auth_fail_burst"]
    assert result.stats["burst_count"] == 2
    assert [burst["lines"] for burst in result.stats["bursts"]] == [
        BURST_ONE,
        BURST_TWO,
    ]
    assert result.stats["burst_users"] == ["sarah_j"]

    # The half of the finding that survives a skeptical judge: nothing else in
    # the file comes close to burst structure.
    assert result.stats["total_401"] == 899
    assert result.stats["isolated_401"] == 889
    assert result.stats["runs_of_two"] == 0
    assert result.stats["min_gap_s_outside_bursts"] > 60


def test_f3_only_three_requests_carry_an_unexpected_parameter(results):
    result = results["tampered_forum_post"]
    assert result.lines == PAYLOAD_ATTEMPTS
    assert sorted(result.stats["unexpected_keys"]) == ["action", "payload", "script"]
    assert result.stats["users"] == ["david_m"]
    assert result.stats["paths_with_any_parameter"] == [queries.FORUM_NEW]


def test_f4_two_templates_occur_exactly_once(results):
    result = results["globally_unique_templates"]
    assert result.lines == [168336, 168337]
    assert sorted(result.stats["unique_templates"]) == [
        "/api/admin/role_update",
        "/assets/avatar_{id}.png",
    ]
    # No gradient to argue about: everything else is in the thousands.
    assert result.stats["next_rarest_count"] > 1000


def test_f5_one_denial_history_ever_turns_into_a_success(results):
    result = results["first_success_after_denials"]
    assert result.lines == [168338]

    exfil = result.stats["flips"][0]
    assert exfil["user"] == "david_m"
    assert exfil["path"] == CONFIDENTIAL_ZIP
    assert exfil["prior_denials"] == 77
    assert exfil["total_denials"] == 80
    assert exfil["successes_on_path"] == 1

    # The threshold has to earn its place: unfiltered, the query also returns
    # an authorised reader's first access on day one of the dataset.
    below = result.stats["flips_below_threshold"]
    assert [flip["user"] for flip in below] == ["sarah_j"]
    assert below[0]["prior_denials"] == 1
    assert below[0]["successes_on_path"] > 1000


def test_f6_the_only_400_and_500_are_the_payload_attempts(results):
    result = results["anomalous_status"]
    assert result.lines == [168330, 168331]
    assert result.stats["rare_statuses"] == {"400": 1, "500": 1}
    assert [event["user"] for event in result.stats["events"]] == ["david_m"] * 2


def test_f7_attribution_is_one_chain_on_an_object_that_predates_it(results):
    result = results["post_attribution"]
    assert result.lines == [168332, 168333]
    assert result.stats["chain_count"] == 1

    chain = result.stats["chains"][0]
    assert chain["user"] == "david_m"
    assert chain["obj_id"] == 1042
    assert chain["gap_s"] == 3.0
    # The honest half: post 1042 is seven months older than the incident, so
    # the chain places him on the object and cannot make him its author.
    assert chain["object_first_line"] < 1000
    assert chain["object_first_ts"].startswith("2025-08-01")
    assert chain["object_event_count"] > 300


def test_the_privileged_call_follows_a_post_view_by_one_second(results):
    result = results["content_triggered_privileged_action"]
    assert result.lines == [168335, 168336]
    assert result.stats["privileged_calls"] == 1

    chain = result.stats["chains"][0]
    assert chain["user"] == "sarah_j"
    assert chain["ip"] == "10.0.5.12"
    assert chain["obj_id"] == 1042
    assert chain["gap_s"] == 1.0


def test_supporting_queries_frame_the_download(results):
    denials = results["denials_before_exfil"]
    assert denials.stats["success_line"] == 168338
    assert denials.stats["denials_before_success"] == 77
    # Access closed again afterwards, with no log line for either change.
    assert denials.stats["denials_after_success"] == 3
    assert denials.stats["first_denial_after_success_line"] == 178028

    assert results["vector_object_edits"].lines == [168339]
    assert results["cover_download"].lines == [168340]
    assert results["cover_download"].stats["path"] == "/finance/templates/expense.docx"


# --- the dismissed leads ---------------------------------------------------


def test_offhours_access_is_routine_and_mostly_legitimate(results):
    result = results["offhours_confidential_access"]
    assert result.stats["from_own_baseline_ip"] == 9
    assert result.stats["from_a_foreign_ip"] == 1
    # The single off-hours read belonging to the incident is already F1's.
    assert result.stats["foreign_lines"] == [168345]
    assert 162048 in result.lines
    assert "sarah_j" in result.stats["users"]


def test_the_other_failed_logins_have_no_structure(results):
    result = results["scattered_auth_failures"]
    assert result.stats["isolated_401"] == 889
    assert result.stats["users"] == 10
    assert result.stats["months"] == 8
    assert result.stats["paths"] == ["/api/auth/login"]


def test_denial_volume_is_the_baseline_not_the_signal(results):
    result = results["routine_denials"]
    assert result.stats["total_403"] == 5324
    assert result.stats["users"] == 10
    assert result.stats["per_user_min"] > 500
    assert result.stats["flips_above_threshold"] == 1


def test_no_credential_endpoint_exists_to_explain_the_login(results):
    result = results["credential_mechanism_gap"]
    assert result.stats["credential_templates"] == []
    assert result.stats["first_success_line"] == 168343
    assert result.stats["users_on_ip_between"] == ["david_m"]


# --- the assembled document ------------------------------------------------


def test_case_file_matches_the_contract_shape(case_file):
    assert set(case_file) >= {
        "case_id",
        "title",
        "window",
        "verdict",
        "actors",
        "findings",
        "timeline",
        "unknowns",
        "dismissed",
    }
    assert case_file["verdict"]["confidence"] in build.CONFIDENCE_VALUES
    assert case_file["actors"]["attacker"] == {"user": "david_m", "ip": "10.0.8.45"}
    assert case_file["actors"]["victim"] == {"user": "sarah_j", "ip": "10.0.5.12"}
    assert case_file["actors"]["asset"] == CONFIDENTIAL_ZIP
    assert case_file["actors"]["vector"]["obj_id"] == 1042
    # Timestamps carry an offset everywhere, never a naive datetime.
    assert case_file["window"]["start"].endswith("-04:00")


def test_every_finding_is_backed_by_a_re_runnable_query(case_file, events):
    assert [finding["id"] for finding in case_file["findings"]] == [
        f"F{n}" for n in range(1, 8)
    ]
    for finding in case_file["findings"]:
        assert finding["confidence"] in build.CONFIDENCE_VALUES
        assert finding["evidence_lines"], finding["id"]
        # The name in the document resolves to a query anyone can re-run, and
        # re-running it still reaches the lines the claim cites.
        result = queries.run(finding["query"], events)
        assert set(result.lines) <= set(finding["evidence_lines"]), finding["id"]


def test_post_attribution_is_labelled_a_heuristic(case_file):
    f7 = next(f for f in case_file["findings"] if f["id"] == "F7")
    assert f7["confidence"] == "medium"
    assert "HEURISTIC" in f7["method"]
    assert "never record" in f7["method"]


def test_timeline_is_ordered_and_every_entry_resolves(case_file, events):
    timeline = case_file["timeline"]
    assert len(timeline) >= 12
    lines = [entry["line"] for entry in timeline]
    assert lines == sorted(lines)

    by_line = events.set_index("line")
    for entry in timeline:
        row = by_line.loc[entry["line"]]
        assert entry["actor"] == row["user"]
        assert entry["ts"] == queries._iso(row["ts"])


def test_unknowns_and_dismissed_leads_ship_with_their_queries(case_file):
    assert [unknown["id"] for unknown in case_file["unknowns"]] == ["U1", "U2", "U3"]
    for unknown in case_file["unknowns"]:
        assert unknown["text"]
        assert unknown["query"] in queries.QUERIES or unknown["query"].split(".")[
            -1
        ] in queries.QUERIES

    assert len(case_file["dismissed"]) == 3
    for lead in case_file["dismissed"]:
        assert lead["evidence_lines"], lead["lead"]
        assert lead["query"].split(".")[-1] in queries.QUERIES


def test_a_finding_without_evidence_cannot_be_built(results):
    empty = queries.QueryResult(name="nothing", question="?", lines=[])
    with pytest.raises(AssertionError):
        build._finding("FX", "claim", "high", "method", empty)


# --- the endpoints ---------------------------------------------------------


@pytest.fixture(scope="module")
def client():
    from fastapi.testclient import TestClient

    from minny.api.app import app

    return TestClient(app)


def test_evidence_endpoint_returns_the_original_bytes(client, events):
    response = client.get("/api/events?lines=168330,168338")
    assert response.status_code == 200

    payload = response.json()
    assert [row["line"] for row in payload] == [168330, 168338]
    assert set(payload[0]) == {
        "line",
        "raw",
        "ts",
        "user",
        "ip",
        "method",
        "path",
        "status",
        "size",
    }
    # Evidence is the file's own bytes, never a line re-rendered from fields.
    assert payload[0]["raw"] == events.set_index("line").loc[168330, "raw"]
    assert payload[0]["ts"].endswith("-04:00")
    assert payload[1]["size"] == 8459200


def test_evidence_endpoint_caps_the_batch(client):
    too_many = ",".join(str(line) for line in range(1, MAX_LINES + 2))
    response = client.get(f"/api/events?lines={too_many}")
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "too_many_lines"


@pytest.mark.parametrize(
    ("query", "code"),
    [("", "missing_lines"), ("?lines=", "missing_lines"), ("?lines=abc", "invalid_lines")],
)
def test_evidence_endpoint_errors_carry_the_contract_shape(client, query, code):
    response = client.get(f"/api/events{query}")
    assert response.status_code == 400
    assert set(response.json()["error"]) == {"code", "message"}
    assert response.json()["error"]["code"] == code


def test_unknown_line_numbers_do_not_cost_the_rest_of_the_batch(client):
    response = client.get("/api/events?lines=999999,168338")
    assert response.status_code == 200
    assert [row["line"] for row in response.json()] == [168338]


def test_case_file_endpoint_serves_the_built_document(client):
    response = client.get("/api/case_file")
    if not paths.case_file_path().exists():
        assert response.status_code == 404
        assert response.json()["error"]["code"] == "case_file_missing"
        return

    payload = response.json()
    assert payload["case_id"] == build.CASE_ID
    assert len(payload["findings"]) == 7
