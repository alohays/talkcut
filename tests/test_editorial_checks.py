"""Actual media regressions; these tests supply no real AI/editorial PASS."""

import copy
from pathlib import Path

import pytest

from talkcut.editorial_checks import (
    _case_outcome,
    _selection_matches,
    generate_nonverbal_fixture,
    verify_editorial_fixtures,
)
from talkcut.project import TalkCutError, artifact_ref, atomic_json, read_json
from talkcut.timeline import as_fraction

REPO = Path(__file__).parents[1]


@pytest.fixture(scope="module")
def generated(tmp_path_factory):
    result = generate_nonverbal_fixture(tmp_path_factory.mktemp("editorial"), REPO)
    return result, read_json(result["input"]["path"])


def test_actual_nonverbal_source_decode_is_not_editorial_approval(generated):
    result, raw = generated
    assert result["status"] == "UNVERIFIED"
    assert all(value is None for value in result["measurements"].values())
    report = read_json(raw["fixtures"][0]["analysis"]["path"])
    assert report["coverage"]["acoustic_full_stream"] is True
    assert report["coverage"]["audiovisual_context_complete"] is False
    assert report["status"] == "ANALYSIS_UNAVAILABLE"
    assert len(report["candidates"]) >= 3
    assert all(row["policy_action"] == "keep" for row in report["candidates"])


def test_fixture_rejects_hash_preserving_empty_ledger(generated, tmp_path):
    _, raw = generated
    raw = copy.deepcopy(raw)
    report = read_json(raw["fixtures"][0]["analysis"]["path"])
    report["segments"], report["candidates"] = [], []
    atomic_json(tmp_path / "analysis.json", report)
    raw["fixtures"][0]["analysis"] = artifact_ref(tmp_path / "analysis.json")
    with pytest.raises(TalkCutError, match="full analysis ledger"):
        verify_editorial_fixtures(raw, REPO, tmp_path / "recheck")


def test_fabricated_analyzed_label_is_recomputed(generated, tmp_path):
    _, raw = generated
    raw = copy.deepcopy(raw)
    report = read_json(raw["fixtures"][0]["analysis"]["path"])
    report["status"] = "ANALYZED"
    atomic_json(tmp_path / "analysis.json", report)
    raw["fixtures"][0]["analysis"] = artifact_ref(tmp_path / "analysis.json")
    with pytest.raises(TalkCutError, match="full analysis ledger"):
        verify_editorial_fixtures(raw, REPO, tmp_path / "recheck")


def test_shortened_actual_fixture_domain_is_rejected(generated, tmp_path):
    _, raw = generated
    raw = copy.deepcopy(raw)
    raw["fixtures"][0]["domain"] = ["0", "5"]
    with pytest.raises(TalkCutError, match="truncates the actual source"):
        verify_editorial_fixtures(raw, REPO, tmp_path / "recheck")


def test_copied_acoustic_silence_intervals_are_reexecuted(generated, tmp_path):
    _, raw = generated
    raw = copy.deepcopy(raw)
    report = read_json(raw["fixtures"][0]["analysis"]["path"])
    acoustic = read_json(report["acoustic_ref"]["path"])
    acoustic["intervals"] = []
    atomic_json(tmp_path / "acoustic.json", acoustic)
    report["acoustic_ref"] = artifact_ref(tmp_path / "acoustic.json")
    atomic_json(tmp_path / "analysis.json", report)
    raw["fixtures"][0]["analysis"] = artifact_ref(tmp_path / "analysis.json")
    with pytest.raises(TalkCutError, match="acoustic intervals differs"):
        verify_editorial_fixtures(raw, REPO, tmp_path / "recheck")


def test_old_source_labels_cannot_be_reused(generated, tmp_path):
    _, raw = generated
    raw = copy.deepcopy(raw)
    expected = read_json(raw["fixtures"][0]["expectations"]["path"])
    expected["source_sha256"] = "a" * 64
    atomic_json(tmp_path / "expected.json", expected)
    raw["fixtures"][0]["expectations"] = artifact_ref(tmp_path / "expected.json")
    with pytest.raises(TalkCutError, match="actual source identity"):
        verify_editorial_fixtures(raw, REPO, tmp_path / "recheck")


def test_testonly_policy_labels_cannot_become_av_expectations(generated, tmp_path):
    _, raw = generated
    raw = copy.deepcopy(raw)
    report = read_json(raw["fixtures"][0]["analysis"]["path"])
    report["test_only"] = True
    report["source_kind"] = "fixture"
    atomic_json(tmp_path / "analysis.json", report)
    raw["fixtures"][0]["analysis"] = artifact_ref(tmp_path / "analysis.json")
    with pytest.raises(TalkCutError, match="Policy-only mocked"):
        verify_editorial_fixtures(raw, REPO, tmp_path / "recheck")


def test_raw_pass_review_cannot_replace_unavailable_context(generated, tmp_path):
    _, raw = generated
    raw = copy.deepcopy(raw)
    atomic_json(tmp_path / "review.json", {"status": "PASS"})
    raw["fixtures"][0]["expectations_review"] = artifact_ref(tmp_path / "review.json")
    with pytest.raises(TalkCutError, match="Expectation PASS cannot replace"):
        verify_editorial_fixtures(raw, REPO, tmp_path / "recheck")


def test_missing_separate_disfluency_review_stays_unknown():
    case = {"id": "repeated", "start": "10", "end": "12", "kind": "disfluency"}
    report = {"candidates": [{**case, "policy_action": "requires_review"}]}
    assert (
        _case_outcome(case, report, {}, {}, (as_fraction(0), as_fraction(20))) is None
    )


def test_degenerate_selection_controls_have_a_nonempty_positive_control():
    cases = [
        {"start": "0", "end": "4", "expected_action": "cut"},
        {"start": "5", "end": "8", "expected_action": "keep"},
    ]
    selected = [(as_fraction(0), as_fraction(4))]
    assert _selection_matches(cases, selected, complete_ledger=True)
    assert not _selection_matches(cases, [], complete_ledger=True)
    assert not _selection_matches(
        cases, [(as_fraction(0), as_fraction(10))], complete_ledger=True
    )
    assert not _selection_matches(cases, selected, complete_ledger=False)
