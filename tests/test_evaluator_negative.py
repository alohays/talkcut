"""Actual paired technical controls; these tests never simulate an AV approval."""

from __future__ import annotations

import copy
from pathlib import Path

import pytest

from talkcut.evaluator_negative import (
    MISSING_CONTROLS,
    run_evaluator_negatives,
    verify_evaluator_negatives,
)
from talkcut.project import TalkCutError, artifact_ref, atomic_json, verified_json

REPO = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="module")
def executed_negatives(tmp_path_factory):
    root = tmp_path_factory.mktemp("evaluator-negative-actual")
    result = run_evaluator_negatives(REPO, root)
    return verified_json(result["result"])


def verify(raw):
    return verify_evaluator_negatives(
        raw, repo_root=REPO, dependencies=raw["dependencies"]
    )


def test_actual_controls_fail_only_after_specific_mutation(executed_negatives):
    raw = executed_negatives
    measured = verify(raw)
    assert sum(value is True for value in measured.values()) == 7
    assert {key for key, value in measured.items() if value is None} == set(
        MISSING_CONTROLS
    )
    assert raw["status"] == "UNVERIFIED"
    for case in raw["cases"].values():
        for pair in case["pairs"]:
            assert pair["control"]["exit_code"] == 0
            assert pair["attack"]["exit_code"] != 0
    duplicate = raw["cases"]["duplicate_coverage"]["pairs"][0]
    actual = verified_json(duplicate["attack"]["stdout"])
    assert actual["facts"]["numerator_seconds"] == "30"
    assert actual["facts"]["uncovered_intervals"] == [["30", "90"]]
    partial = raw["cases"]["renamed_partial"]["pairs"][0]
    assert partial["mutation"]["interruption"]["timed_out"] is True
    assert partial["mutation"]["interruption"]["exit_code"] < 0
    assert verified_json(partial["attack"]["stdout"])["error_type"] == "RenderError"


@pytest.mark.parametrize("case_id", sorted(MISSING_CONTROLS))
def test_missing_legitimate_av_or_actor_control_cannot_become_pass(
    executed_negatives, case_id
):
    raw = copy.deepcopy(executed_negatives)
    raw["cases"][case_id]["status"] = "PASS"
    raw["measurements"][case_id] = True
    with pytest.raises(TalkCutError, match="missing legitimate"):
        verify(raw)


def test_every_failed_baseline_is_not_a_negative_test(executed_negatives):
    raw = copy.deepcopy(executed_negatives)
    pair = raw["cases"]["duplicate_coverage"]["pairs"][0]
    pair["control"] = copy.deepcopy(pair["attack"])
    with pytest.raises(TalkCutError, match="receipt command"):
        verify(raw)


def test_unrelated_failure_exit_does_not_count(executed_negatives, tmp_path):
    raw = copy.deepcopy(executed_negatives)
    pair = raw["cases"]["duplicate_coverage"]["pairs"][0]
    response = verified_json(pair["attack"]["stdout"])
    response["reason"] = "Some unrelated environment error"
    destination = tmp_path / "unrelated.json"
    atomic_json(destination, response)
    pair["attack"]["stdout"] = artifact_ref(destination)
    with pytest.raises(TalkCutError, match="direct replay"):
        verify(raw)


def test_hash_relabelled_nonmutation_is_rejected(executed_negatives, tmp_path):
    raw = copy.deepcopy(executed_negatives)
    pair = raw["cases"]["duplicate_coverage"]["pairs"][0]
    destination = tmp_path / "unchanged-input.json"
    atomic_json(destination, verified_json(pair["control_input"]))
    pair["mutation_input"] = artifact_ref(destination)
    with pytest.raises(TalkCutError, match="Duplicate-window mutation"):
        verify(raw)


def test_hand_entered_measurements_cannot_override_null(executed_negatives):
    raw = copy.deepcopy(executed_negatives)
    raw["measurements"] = dict.fromkeys(raw["measurements"], True)
    raw["status"] = "PASS"
    with pytest.raises(TalkCutError, match="Hand-entered"):
        verify(raw)


def test_changed_dependency_invalidates_execution(executed_negatives):
    raw = copy.deepcopy(executed_negatives)
    raw["dependencies"]["code_tree_hash"] = "0" * 64
    with pytest.raises(TalkCutError, match="Stale or different"):
        verify(raw)


def test_changed_preserved_bytes_invalidate_execution(executed_negatives, tmp_path):
    raw = copy.deepcopy(executed_negatives)
    destination = tmp_path / "changed-output.json"
    destination.write_text("before")
    raw["artifacts"].append(artifact_ref(destination))
    destination.write_text("after")
    with pytest.raises(TalkCutError, match="bytes changed"):
        verify(raw)


def test_technical_controls_cannot_claim_real_acceptance(executed_negatives):
    raw = copy.deepcopy(executed_negatives)
    raw["actual_dgist_acceptance"] = True
    with pytest.raises(TalkCutError, match="relabelled as actual media"):
        verify(raw)


def test_missing_second_hash_control_is_rejected(executed_negatives):
    raw = copy.deepcopy(executed_negatives)
    raw["cases"]["wrong_hashes"]["pairs"].pop()
    with pytest.raises(TalkCutError, match="paired technical control"):
        verify(raw)
