"""Independent inert metadata controls; no historical writer is executed."""
from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest
from oversized_fixture import fixture, observe, refresh, write

from talkcut.privacy_checks import _review_text_origin_inventory
from talkcut.project import TalkCutError

REPLAY = ["known_graph", "synthetic_failure_fixtures", 0, "current_reproduction", "scope"]
REASONS = [["known_graph", "synthetic_failure_fixtures", 0, "rows", i, "reason"] for i in range(3)]


def observation(parts):
    return parts["body"]["known_graph"]["synthetic_failure_fixtures"][0]


def locator(parts, selector=REPLAY):
    return {"schema_version": "review-text-origin/v1", "kind": "machine_inventory_field",
            "parent": parts["parent"], "authority": parts["authority"], "selector": selector}


def intake(parts, locators, registered=None):
    return _review_text_origin_inventory(locators, parts["directory"], parts["root"],
                                        set(parts["registered"].values()) if registered is None else registered,
                                        [parts["authority"]])


def rebound_run(parts, raw):
    item = observation(parts)
    item["run"] = write(item["run"]["path"], raw)
    for row in item["rows"]:
        row["historical_run"] = item["run"]
    refresh(parts)


@pytest.mark.parametrize("count", [20_000, 20_001])
def test_original_exact_artifact_record_bound(tmp_path, count):
    parts = fixture(tmp_path)
    raw = json.loads(Path(observation(parts)["run"]["path"]).read_bytes())
    folder = tmp_path / "inert-record-members"
    folder.mkdir()
    # Every additional member is a real empty file with truthful distinct path/hash.
    for i in range(count - len(raw["artifacts"])):
        raw["artifacts"].append(write(folder / str(i), b""))
    rebound_run(parts, raw)
    if count == 20_000:
        result = observe(parts, REASONS[0])[0]
        assert result["associated_row"] == observation(parts)["rows"][0]
        assert len(json.loads(Path(observation(parts)["run"]["path"]).read_bytes())["artifacts"]) == count
    else:
        with pytest.raises(TalkCutError, match="artifact denominator"):
            observe(parts, REASONS[0])


@pytest.mark.parametrize("fault", ["duplicate", "same_path_other_hash", "pair_order", "missing_speaker", "extra_role"])
def test_complete_wrong_hash_collection_relationships(tmp_path, fault):
    parts = fixture(tmp_path)
    assert observe(parts, REASONS[1])
    raw = json.loads(Path(observation(parts)["run"]["path"]).read_bytes())
    if fault in {"duplicate", "same_path_other_hash"}:
        extra = copy.deepcopy(raw["artifacts"][0])
        if fault == "same_path_other_hash":
            extra["sha256"] = "e" * 64
        raw["artifacts"].append(extra)
    elif fault == "pair_order":
        raw["cases"]["wrong_hashes"]["pairs"].reverse()
    else:
        ref = raw["artifacts"][0]
        body = json.loads(Path(ref["path"]).read_bytes())
        if fault == "missing_speaker":
            body["sources"].pop("speaker")
        else:
            body["sources"]["third"] = body["sources"]["speaker"]
        raw["artifacts"][0] = write(ref["path"], body)
    rebound_run(parts, raw)
    with pytest.raises(TalkCutError):
        observe(parts, REASONS[1])


@pytest.mark.parametrize("field", ["classification", "status", "preserved_original", "historical_run"])
def test_complete_reason_row_is_not_only_literal_equality(tmp_path, field):
    parts = fixture(tmp_path)
    row = observation(parts)["rows"][2]
    if field in {"classification", "status"}:
        row[field] = "PASS"
    else:
        row[field] = parts["source"]
    refresh(parts)
    with pytest.raises(TalkCutError, match="complete input projections"):
        observe(parts, REASONS[2])


@pytest.mark.parametrize("field", ["generator", "harness", "code_tree_hash", "source_sha256", "generator_argv_prefix", "output_hashes", "technical_validation"])
def test_replay_bound_sibling_relations(tmp_path, field):
    parts = fixture(tmp_path)
    reproduction = observation(parts)["current_reproduction"]
    if field in {"generator", "harness"}:
        reproduction[field] = parts["helper"]
    elif field in {"code_tree_hash", "source_sha256"}:
        reproduction[field] = "e" * 64
    elif field == "generator_argv_prefix":
        reproduction[field] = ["another-never-executed-command"]
    else:
        reproduction[field] = {"changed": True}
    refresh(parts)
    with pytest.raises(TalkCutError):
        observe(parts, REPLAY)


@pytest.mark.parametrize("selector", [None, [], {}, [True], [1.5], ["known_graph", None], ["known_graph", []], ["known_graph", {}]])
def test_selector_exact_json_types(tmp_path, selector):
    parts = fixture(tmp_path)
    with pytest.raises(TalkCutError):
        intake(parts, [locator(parts, selector)])


@pytest.mark.parametrize("target", ["source", "parent"])
def test_registered_private_bytes_do_not_acquire_origin_authority(tmp_path, target):
    parts = fixture(tmp_path)
    registered = {*parts["registered"].values(), parts[target]["sha256"]}
    with pytest.raises(TalkCutError):
        intake(parts, [locator(parts)], registered)


def test_duplicate_locators_refuse_and_two_distinct_rows_remain(tmp_path):
    parts = fixture(tmp_path)
    first, second = locator(parts, REASONS[0]), locator(parts, REASONS[1])
    result = intake(parts, [first, second])
    assert len(result) == 2
    assert [r["extractions"][0]["edge"] for r in result] == REASONS[:2]
    with pytest.raises(TalkCutError):
        intake(parts, [first, copy.deepcopy(first)])


def test_identical_copied_parent_has_no_original_output_authority(tmp_path):
    parts = fixture(tmp_path)
    copied = write(parts["directory"] / "copied-parent.json", Path(parts["parent"]["path"]).read_bytes())
    row = locator(parts)
    row["parent"] = copied
    with pytest.raises(TalkCutError):
        intake(parts, [row])


@pytest.mark.parametrize("target", ["metadata", "source", "parent"])
def test_late_read_mutation_fails_complete_consumer_conservation(tmp_path, monkeypatch, target):
    parts = fixture(tmp_path)
    item = observation(parts)
    late = Path(item["current_reproduction"]["executions"]["path"])
    if target == "metadata":
        earlier = Path(parts["body"]["known_graph"]["auxiliary_metadata_history"][0]["preserved_ref"]["path"])
    else:
        earlier = Path(parts[target]["path"])
    real_read = Path.read_bytes
    fired = []

    def injected(path):
        result = real_read(path)
        if path == late and not fired:
            fired.append(True)
            earlier.write_bytes(real_read(earlier) + b"\n")
        return result

    monkeypatch.setattr(Path, "read_bytes", injected)
    with pytest.raises(TalkCutError):
        observe(parts, REPLAY)
    assert fired == [True]


@pytest.mark.parametrize(("needle", "replacement"), [
    ("read_text().split", "read_text(encoding='utf-8').split"),
    ("synthetic_negative_runs=[runref]", "synthetic_negative_runs=[runref, runref]"),
    ("oversized-stdout-inventory.json", "different-output.json"),
])
def test_complete_bootstrap_kwargs_output_writer(tmp_path, needle, replacement):
    parts = fixture(tmp_path)
    script = Path(parts["script"]["path"])
    original = script.read_text()
    assert needle in original
    script.write_text(original.replace(needle, replacement, 1))
    refresh(parts)
    with pytest.raises(TalkCutError):
        observe(parts)


@pytest.mark.parametrize("field", ["external_inputs", "external_tool_links"])
def test_replay_whole_row_cannot_claim_noncollection_external_fields(tmp_path, field):
    parts = fixture(tmp_path)
    assert observe(parts, REPLAY)
    observation(parts)["current_reproduction"][field] = "unverified authored prose in a list-valued original output"
    refresh(parts)
    with pytest.raises(TalkCutError):
        observe(parts, REPLAY)
