"""The three routes track C owns, exercised through the real application.

The judge panel is the one part of this system a stranger drives, on
conference wifi, during a three-minute demo. These pin the two things that
would embarrass it: a missing artifact served as an empty object, and an
incoherent request answered with a variant nobody asked for.
"""

from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from minny import paths
from minny.api.app import app
from minny.redteam.catalog import load_catalog

needs_dataset = pytest.mark.skipif(
    not paths.events_path().exists() or not paths.access_matrix_path().exists(),
    reason="set MINNY_DATA_DIR to the main checkout's data directory",
)

pytestmark = needs_dataset

TARGET = "/finance/reports/q1_draft_CONFIDENTIAL.zip"
VALID = {
    "attacker": "david_m",
    "victim": "sarah_j",
    "target": TARGET,
    "operators": ["slow_guess"],
    "persona": "careful_insider",
    "family": "F4",
}


@pytest.fixture(scope="module", autouse=True)
def warm_catalog():
    """Load the catalog before any test redirects the data directory.

    It is cached for the process, so warming it here keeps a monkeypatched
    path from sending the generator looking for a parquet file in a temporary
    directory.
    """
    load_catalog()


@pytest.fixture(scope="module")
def client():
    return TestClient(app)


def test_metrics_is_served_from_disk(client):
    response = client.get("/api/metrics")
    if response.status_code == 503:
        pytest.skip("metrics.json has not been generated in this data directory")
    body = response.json()
    assert body["command"].startswith("python eval.py --seed")
    assert "placeholder" not in body


def test_missing_metrics_is_a_503_naming_the_command(client, tmp_path, monkeypatch):
    """Never an empty object.

    A metrics panel rendering zeros because nobody ran the evaluation looks
    exactly like a detector that caught nothing, and that is the one mistake
    this project cannot afford to make on screen.
    """
    monkeypatch.setattr(paths, "metrics_path", lambda: tmp_path / "metrics.json")
    response = client.get("/api/metrics")

    assert response.status_code == 503
    error = response.json()["error"]
    assert error["code"] == "artifact_missing"
    assert "python eval.py --seed 42" in error["message"]


def test_blue_proposals_are_empty_until_the_agent_runs(client, tmp_path, monkeypatch):
    monkeypatch.setattr(paths, "data_dir", lambda: tmp_path)
    assert client.get("/api/blue/proposals").json() == {"proposals": []}


def test_blue_proposals_are_served_as_written(client, tmp_path, monkeypatch):
    written = [{"id": "R001", "gate": {"accepted": False}}]
    (tmp_path / "blue_proposals.json").write_text(json.dumps(written), "utf-8")
    monkeypatch.setattr(paths, "data_dir", lambda: tmp_path)

    assert client.get("/api/blue/proposals").json() == written


def test_generate_returns_a_variant_label(client):
    response = client.post("/api/redteam/generate", json=VALID)
    assert response.status_code == 200

    label = response.json()
    assert label["attacker"] == VALID["attacker"]
    assert label["victim"] == VALID["victim"]
    assert label["target"] == VALID["target"]
    assert "slow_guess" in label["operators"]
    assert label["family"] == "F4"
    assert label["critic"]["accepted"] is True
    assert label["injected_lines"]
    # Injection belongs to the replay engine, and whether one is running is
    # not this endpoint's business. What is its business is saying which
    # happened: a variant that reached the queue reports it, and one that did
    # not says why rather than implying a replay nobody started is showing it.
    assert isinstance(label["injected"], bool)
    if label["injected"]:
        assert label["reason"] is None
    else:
        assert label["reason"]


def test_generated_variants_never_reuse_an_event_id(client):
    first = client.post("/api/redteam/generate", json=VALID).json()
    second = client.post("/api/redteam/generate", json=VALID).json()

    assert first["variant_id"] != second["variant_id"]
    assert not set(first["injected_lines"]) & set(second["injected_lines"])
    assert min(first["injected_lines"]) > 180_800


@pytest.mark.parametrize(
    "override, code",
    [
        ({"victim": "david_m"}, "same_account"),
        ({"victim": "chris_b"}, "victim_not_authorized"),
        ({"attacker": "nicole_h"}, "attacker_not_denied"),
        ({"target": "/finance/reports/nothing_here.zip"}, "unknown_target"),
        ({"operators": ["slow_walk"]}, "unknown_operator"),
        ({"family": "F1", "operators": ["no_cover_download"]}, "operator_not_applicable"),
        ({"family": "F9"}, "unknown_family"),
        ({"persona": "bored_contractor"}, "unknown_persona"),
    ],
)
def test_an_incoherent_request_is_a_clear_400(client, override, code):
    """Rejected, not silently substituted.

    The planner falls back to a seeded choice for anything it cannot use,
    which is right for a batch of 200 and wrong for a request: a judge who
    picks a victim with no access would otherwise be handed a label naming
    somebody else with nothing to say the request was ignored.
    """
    response = client.post("/api/redteam/generate", json={**VALID, **override})

    assert response.status_code == 400
    error = response.json()["error"]
    assert error["code"] == code
    assert error["message"]
