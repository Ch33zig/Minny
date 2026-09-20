"""The findings, pinned to the lines the queries actually returned.

These are the numbers said on stage. If the dataset is ever swapped or a
query is loosened, this file fails loudly instead of the case file quietly
citing evidence that no longer supports it.
"""

from __future__ import annotations

import json

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
    # 80 in total, but never 80 before the download. The query ships both
    # sides of the success so no sentence can imply the wrong order.
    assert denials.stats["total_denials"] == 80
    assert denials.lines == [168315, 178028]

    assert results["vector_object_edits"].lines == [168339]
    assert results["cover_download"].lines == [168340]
    assert results["cover_download"].stats["path"] == "/finance/templates/expense.docx"


# --- the dismissed leads ---------------------------------------------------


def test_offhours_access_is_rare_and_every_instance_is_accounted_for(results):
    result = results["offhours_confidential_access"]
    # Rare, not routine: 10 of 6,115 confidential reads fall in the window.
    assert result.stats["window"] == "20:00-06:00"
    assert result.stats["confidential_successes"] == 6115
    assert result.stats["off_hours_successes"] == 10
    assert result.stats["off_hours_share_pct"] < 1
    assert result.stats["from_own_baseline_ip"] == 9
    assert result.stats["from_a_foreign_ip"] == 1
    # The single off-hours read belonging to the incident is already F1's.
    assert result.stats["foreign_lines"] == [168345]
    assert 162048 in result.lines
    assert "sarah_j" in result.stats["users"]


def test_exactly_one_after_midnight_read_touches_the_stolen_file(results):
    result = results["offhours_confidential_access"]
    # The claim a judge checks first. Five after-midnight reads exist, and
    # exactly one of them is the Q1 zip.
    assert result.stats["after_midnight_by_path"][CONFIDENTIAL_ZIP] == 1
    on_asset = [
        entry
        for entry in result.stats["after_midnight_examples"]
        if entry["path"] == CONFIDENTIAL_ZIP
    ]
    assert [entry["line"] for entry in on_asset] == [162048]
    assert on_asset[0]["user"] == "sarah_j"
    assert on_asset[0]["ip"] == "10.0.5.12"
    assert on_asset[0]["ts"].startswith("2026-03-06T00:19")


def test_the_offhours_lead_states_its_window_and_never_calls_it_routine(case_file):
    lead = next(
        entry
        for entry in case_file["dismissed"]
        if entry["query"].endswith("offhours_confidential_access")
    )
    assert "20:00-06:00" in lead["why"]
    assert "is routine" not in lead["why"]
    # One after-midnight read of the asset, named with its line.
    assert f"exactly 1 of those touches {CONFIDENTIAL_ZIP}" in lead["why"]
    assert "line 162048" in lead["why"]


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
    # The contract's two required keys, now beside the optional card fields.
    attacker = case_file["actors"]["attacker"]
    victim = case_file["actors"]["victim"]
    assert (attacker["user"], attacker["ip"]) == ("david_m", "10.0.8.45")
    assert (victim["user"], victim["ip"]) == ("sarah_j", "10.0.5.12")
    assert case_file["actors"]["asset"] == CONFIDENTIAL_ZIP
    assert case_file["actors"]["vector"]["obj_id"] == 1042
    # Timestamps carry an offset everywhere, never a naive datetime.
    assert case_file["window"]["start"].endswith("-04:00")


def test_the_suspect_cards_quote_only_measured_figures(case_file, results):
    attacker = case_file["actors"]["attacker"]
    victim = case_file["actors"]["victim"]
    denials = results["denials_before_exfil"].stats
    mismatch = results["ip_user_mismatch"].stats

    assert attacker["confidence"] in build.CONFIDENCE_VALUES
    assert victim["confidence"] in build.CONFIDENCE_VALUES
    assert [stat["value"] for stat in attacker["stats"]] == [
        str(denials["denials_before_success"]),
        str(denials["denials_after_success"]),
        "1",
        "400, 500",
    ]
    assert [stat["value"] for stat in victim["stats"]] == ["1,528", "1", "2", "10"]
    assert mismatch["ips_per_user"]["sarah_j"] == 2
    assert mismatch["baseline_ips_per_user"]["sarah_j"] == 1
    # The card states the order too, because the total on its own misleads.
    assert "77 times before the download" in attacker["summary"]
    assert "never 80 before the download" in attacker["summary"]


def test_the_suspect_cards_resolve_to_lines_the_queries_returned(case_file, results):
    returned = {line for result in results.values() for line in result.lines}
    for role in ("attacker", "victim"):
        lines = case_file["actors"][role]["evidence_lines"]
        assert lines
        assert set(lines) <= returned, role


def test_the_source_rail_names_the_file_it_read(case_file):
    source = case_file.get("source")
    if source is None:
        pytest.skip("data/logs.txt is shared out of band")
    assert source["file"].endswith("logs.txt")
    assert source["lines"] == 180800
    assert len(source["sha256"]) == 64
    assert source["sha256"] == build.sha256_of(paths.logs_path())


def test_a_missing_log_drops_the_source_rail_and_nothing_else(monkeypatch, tmp_path):
    monkeypatch.setattr(build.paths, "logs_path", lambda: tmp_path / "absent.txt")
    assert build.build_source() is None


def test_the_verdict_carries_a_basis_a_judge_can_check(case_file):
    basis = case_file["verdict"]["basis"]
    # Counts over the whole file, and the single inference named as one.
    assert "180,800" in basis
    assert "not scores" in basis
    assert "F7" in basis


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
        assert entry["confidence"] in build.CONFIDENCE_VALUES

    # The three beats that rest on a reading rather than a record.
    inferred = {
        entry["line"] for entry in timeline if entry["confidence"] != "high"
    }
    assert inferred == {168333, 168339, 168340}


def test_u3_says_which_denials_fall_on_which_side_of_the_download(case_file):
    u3 = next(u for u in case_file["unknowns"] if u["id"] == "U3")
    assert "77 denials come before the download" in u3["text"]
    assert "3 further denials follow from line 178028" in u3["text"]
    assert "80 in all" in u3["text"]
    # The reopened denials are the reason this unknown exists at all.
    assert "the access closed again" in u3["text"]
    assert 178028 in u3["evidence_lines"]


def test_the_timeline_never_quotes_a_denial_count_it_did_not_measure(case_file):
    beats = {entry["line"]: entry for entry in case_file["timeline"]}
    assert "denied 77 times" in beats[168338]["action"]
    assert "The last of 77 denials before the download" in beats[168315]["note"]
    # The reopened denial closes the story the other three beats open.
    assert beats[178028]["actor"] == "david_m"
    assert "The first of the 3 denials after the download" in beats[178028]["note"]
    for entry in case_file["timeline"]:
        assert "{" not in entry["action"]
        assert "{" not in (entry["note"] or "")


def test_unknowns_and_dismissed_leads_ship_with_their_queries(case_file):
    assert [unknown["id"] for unknown in case_file["unknowns"]] == ["U1", "U2", "U3"]
    for unknown in case_file["unknowns"]:
        assert unknown["text"]
        assert unknown["query"] in queries.QUERIES or unknown["query"].split(".")[
            -1
        ] in queries.QUERIES

    assert [lead["id"] for lead in case_file["dismissed"]] == ["D1", "D2", "D3"]
    for lead in case_file["dismissed"]:
        assert lead["evidence_lines"], lead["lead"]
        assert lead["confidence"] in build.CONFIDENCE_VALUES
        assert lead["query"].split(".")[-1] in queries.QUERIES


def test_a_finding_without_evidence_cannot_be_built(results):
    empty = queries.QueryResult(name="nothing", question="?", lines=[])
    with pytest.raises(AssertionError):
        build._finding("FX", "claim", "high", "method", empty)


# --- the UI fixture --------------------------------------------------------


def test_the_fixture_is_a_copy_of_the_generated_case_file():
    """The drift this module exists to prevent, caught as a failing test."""
    fixture = build.FIXTURE_DIR / "case_file.json"
    generated = paths.case_file_path()
    if not fixture.exists() or not generated.exists():
        pytest.skip("run python -m minny.casefile.build --emit-fixture")

    mock = json.loads(fixture.read_text(encoding="utf-8"))
    live = json.loads(generated.read_text(encoding="utf-8"))
    # A rebuild moves the timestamp and nothing else. Every word the UI shows
    # has to be the same in both documents.
    for document in (mock, live):
        document.get("provenance", {}).pop("generated_at", None)
    assert mock == live, "re-run python -m minny.casefile.build --emit-fixture"


def test_every_line_the_fixture_cites_resolves_to_raw_bytes():
    fixture = build.FIXTURE_DIR / "case_file.json"
    events = build.FIXTURE_DIR / "events.json"
    if not fixture.exists() or not events.exists():
        pytest.skip("run python -m minny.casefile.build --emit-fixture")

    rows = json.loads(events.read_text(encoding="utf-8"))
    cited = build.cited_lines(json.loads(fixture.read_text(encoding="utf-8")))
    assert cited
    assert cited <= {row["line"] for row in rows}
    for row in rows:
        assert row["raw"]
        assert str(row["status"]) in row["raw"]


def test_emit_fixture_derives_both_documents(tmp_path, monkeypatch, case_file):
    if not paths.logs_path().exists():
        pytest.skip("data/logs.txt is shared out of band")
    monkeypatch.setattr(build, "FIXTURE_DIR", tmp_path)

    source = tmp_path / "generated.json"
    source.write_text(json.dumps(case_file, indent=2), encoding="utf-8")
    fixture_path, events_path, count = build.emit_fixture(source)

    # Byte for byte, so no hand edit can survive the next emit.
    assert fixture_path.read_text(encoding="utf-8") == source.read_text(
        encoding="utf-8"
    )
    rows = json.loads(events_path.read_text(encoding="utf-8"))
    assert len(rows) == count
    assert build.cited_lines(case_file) <= {row["line"] for row in rows}

    # And the bytes are the log's own, not a line rebuilt from the fields.
    raw = {row["line"]: row["raw"] for row in rows}
    with open(paths.logs_path(), "rb") as handle:
        for number, line in enumerate(handle, 1):
            if number in raw:
                assert raw[number] == line.decode("utf-8").rstrip()


def test_an_injected_line_is_carried_over_rather_than_invented(tmp_path, monkeypatch):
    monkeypatch.setattr(build, "FIXTURE_DIR", tmp_path)
    injected = {"line": 999999, "raw": "synthetic", "status": 200, "synthetic": True}
    rows = build.build_events_fixture({168338, 999999}, [injected])
    assert rows[-1] == injected

    # With nothing to carry over, the build refuses instead of guessing.
    with pytest.raises(AssertionError):
        build.build_events_fixture({999999}, [])


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


def test_mailbox_records_corroborate_and_never_promote(case_file):
    findings = [
        dict(finding, evidence_emails=list(finding["evidence_emails"]))
        for finding in case_file["findings"]
    ]
    message = {
        "evidence_id": "gmail:18f2c9a1b4d7",
        "linked_lines": [168336],
        "confidence": "medium",
    }
    attached = build.attach_email_evidence(findings, [message])

    f4 = next(finding for finding in attached if finding["id"] == "F4")
    assert f4["evidence_emails"] == ["gmail:18f2c9a1b4d7"]
    # Corroboration is not promotion: the confidence label is untouched.
    assert f4["confidence"] == next(
        finding["confidence"]
        for finding in case_file["findings"]
        if finding["id"] == "F4"
    )
    assert next(f for f in attached if f["id"] == "F1")["evidence_emails"] == []


def test_a_missing_mailbox_changes_nothing(monkeypatch, tmp_path):
    monkeypatch.setattr(
        build.paths, "email_evidence_path", lambda: tmp_path / "absent.json"
    )
    assert build.load_email_evidence() == []


def test_after_midnight_reads_are_all_authorised(results):
    result = results["offhours_confidential_access"]
    # Five, not four: the log's fixed -0400 offset puts line 150515 at
    # 00:08 on 19 Feb rather than 23:08 on the 18th. Every one of the five
    # is an authorised reader on their own baseline IP, which is the claim
    # the dismissed lead actually rests on.
    assert result.stats["after_midnight"] == 5
    owner = queries.baseline_ip_by_user()
    for entry in result.stats["after_midnight_examples"]:
        assert owner[entry["user"]] == entry["ip"]
