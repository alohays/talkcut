"""Adversarial evaluator tests. These artifacts never certify real media."""

import json
import shutil
from fractions import Fraction
from pathlib import Path

import pytest

from talkcut.acceptance import (
    Evaluator,
    EvidenceError,
    coverage,
    empty_index,
    evaluate,
    exit_code,
    union,
)
from talkcut.contracts import (
    CHECK_REQUIREMENTS,
    DOCUMENT_HASHES,
    code_identity,
    expected_contract,
    file_hash,
    freeze_contract,
    load_schema,
    validate_project,
    verify_contract,
)

ROOT = Path(__file__).resolve().parents[1]


def artifact(directory, name, value):
    path = directory / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value) if not isinstance(value, str) else value)
    return {"path": str(path), "sha256": file_hash(path)}


@pytest.fixture
def evaluator(tmp_path):
    return Evaluator(tmp_path, "final", tmp_path / "contract.json", ROOT)


def test_empty_real_project_never_passes(tmp_path):
    frozen = freeze_contract(ROOT, tmp_path / "contract.json")
    report = evaluate(tmp_path, "missing-render", frozen["path"], ROOT)
    assert len(report["criteria"]) == 13
    assert all(item["status"] == "UNVERIFIED" for item in report["criteria"])
    assert report["owner_acceptance"] == "pending"
    assert report["goal_achieved"] is False
    assert report["release_ready"] is False
    assert report["media_state"] == "BLOCKED"
    assert exit_code(report) == 1


def test_duplicate_windows_do_not_inflate_coverage():
    repeated = [(Fraction(0), Fraction(30))] * 114
    result = coverage([(Fraction(0), Fraction(3423))], repeated)
    assert result["numerator_seconds"] == "30"
    assert result["uncovered_intervals"] == [["30", "3423"]]
    assert result["fraction"] < 0.01


def test_outside_windows_are_clipped_and_zero_denominator_is_not_100_percent():
    result = coverage([(Fraction(10), Fraction(20))], [(Fraction(0), Fraction(12))])
    assert result["numerator_seconds"] == "2"
    assert result["uncovered_intervals"] == [["12", "20"]]
    zero = coverage([], [(Fraction(0), Fraction(12))])
    assert zero["fraction"] is None
    assert zero["not_applicable"] is True
    with pytest.raises(ValueError):
        union([(Fraction(0), Fraction(0))])


def test_contract_threshold_required_and_severity_changes_are_rejected():
    for mutation in ("threshold", "required", "severity", "coverage"):
        contract = expected_contract()
        if mutation == "threshold":
            contract["checks"]["sync"]["max_lip_residual_with_uncertainty_ms"][
                "max"
            ] = 800
        elif mutation == "required":
            contract["criteria"][0]["required"] = False
        elif mutation == "severity":
            contract["unresolved_P0_P1"] = 1
        else:
            contract["coverage"]["output_audio"] = 0.99
        assert verify_contract(contract, ROOT)


def test_document_and_frozen_contract_cannot_be_silently_replaced(tmp_path):
    for name in DOCUMENT_HASHES:
        target = tmp_path / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / name, target)
    output = tmp_path / "frozen.json"
    freeze_contract(tmp_path, output)
    output.write_text('{"required": false}')
    with pytest.raises(ValueError, match="different frozen"):
        freeze_contract(tmp_path, output)
    (tmp_path / next(iter(DOCUMENT_HASHES))).write_text("weakened requirements")
    with pytest.raises(ValueError, match="document missing or changed"):
        freeze_contract(tmp_path, tmp_path / "other.json")


def test_current_code_identity_includes_untracked_runtime_and_lock(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "a.py").write_text("VALUE = 1")
    (tmp_path / "uv.lock").write_text("locked")
    first = code_identity(tmp_path)
    (tmp_path / "src" / "a.py").write_text("VALUE = 2")
    assert code_identity(tmp_path)["code_tree_hash"] != first["code_tree_hash"]
    first = code_identity(tmp_path)
    (tmp_path / "uv.lock").write_text("changed")
    assert code_identity(tmp_path)["code_tree_hash"] != first["code_tree_hash"]


def test_wrong_source_or_output_hash_is_stale(evaluator, tmp_path):
    ref = artifact(tmp_path, "output.mp4", "original bytes")
    Path(ref["path"]).write_text("different bytes")
    with pytest.raises(EvidenceError, match="Stale or changed") as error:
        evaluator.artifact(ref, json_value=False)
    assert error.value.status == "FAIL"


def test_synthetic_source_registration_cannot_replace_dgist(evaluator, tmp_path):
    evaluator.index["registration"] = artifact(
        tmp_path,
        "registration.json",
        {
            "schema_version": "source-registration/v1",
            "dataset": "dgist-w02",
            "source_kind": "synthetic",
        },
    )
    with pytest.raises(EvidenceError, match="Synthetic/sample"):
        evaluator.load_sources()


def test_hidden_actual_deletion_is_reconstructed(evaluator, tmp_path):
    evaluator.source_domain = (Fraction(0), Fraction(100))
    timeline = {
        "domain": {"start": "0", "end": "100"},
        "duration": "90",
        "retained": [
            {
                "source_start": "0",
                "source_end": "10",
                "output_start": "0",
                "output_end": "10",
            },
            {
                "source_start": "20",
                "source_end": "100",
                "output_start": "10",
                "output_end": "90",
            },
        ],
        "deletions": [],
    }
    evaluator.index["timeline"] = artifact(tmp_path, "timeline.json", timeline)
    with pytest.raises(EvidenceError, match="Actual source deletions"):
        evaluator.load_timeline_render()
    assert evaluator.deletions == [(Fraction(10), Fraction(20))]


def test_sample_export_cannot_change_source_denominator(evaluator, tmp_path):
    evaluator.source_domain = (Fraction(0), Fraction(3423))
    evaluator.index["timeline"] = artifact(
        tmp_path, "sample.json", {"domain": {"start": "0", "end": "60"}}
    )
    with pytest.raises(EvidenceError, match="drops or invents"):
        evaluator.load_timeline_render()


def test_fake_pass_and_owner_approval_are_not_measurements(evaluator, tmp_path):
    evaluator.index["checks"] = {
        "sync": artifact(
            tmp_path, "fake.json", {"status": "PASS", "human_approved": True}
        )
    }
    with pytest.raises(EvidenceError, match="Measurement check identity") as error:
        evaluator.measured_check("sync")
    assert error.value.status == "UNVERIFIED"


def test_copied_measurements_without_execution_receipt_are_unverified(
    evaluator, tmp_path
):
    evidence = {
        "schema_version": "measurement-check/v1",
        "check_id": "recovery",
        "dependencies": evaluator.deps,
        "measurements": CHECK_REQUIREMENTS["recovery"],
    }
    evaluator.index["checks"] = {
        "recovery": artifact(tmp_path, "fake-measurements.json", evidence)
    }
    with pytest.raises(EvidenceError, match="hashed artifact"):
        evaluator.measured_check("recovery")


def test_transcript_only_provider_response_cannot_cover_video_audio(
    evaluator, tmp_path
):
    # Unit adversary: valid-looking receipt chain followed by an explicit
    # transcript-only response. It must be rejected before media is credited.
    prompt = artifact(
        tmp_path,
        "review-prompt.txt",
        "Review the audiovisual input against the fixed rubric.",
    )
    response = artifact(
        tmp_path,
        "response.json",
        {
            "verdict": "PASS",
            "reason": "The transcript appears coherent throughout the requested source segment.",
            "findings": [],
            "needs_source_comparison": False,
            "observed_modalities": ["transcript"],
        },
    )
    receipt = artifact(
        tmp_path,
        "receipt.json",
        {
            "schema_version": "execution-receipt/v1",
            "run_id": "review-2",
            "started_at": "2026-01-01T00:00:00Z",
            "finished_at": "2026-01-01T00:00:01Z",
            "completed": True,
            "exit_code": 0,
            "executor": "unit-adversary",
            "tool_version": "fixture",
            "command": ["fixture"],
            "log": artifact(tmp_path, "log.txt", "fixture transcript response"),
            "dependencies": evaluator.deps,
            "provider_request_id": "fixture-request",
            "model_revision": "fixture",
            "prompt": prompt,
            "prompt_sha256": prompt["sha256"],
            "request": artifact(tmp_path, "request.json", {}),
            "response": response,
        },
    )
    evaluator.capabilities["fixture-cap"] = {"model_revision": "fixture"}
    ref = artifact(
        tmp_path,
        "review.json",
        {
            "schema_version": "multimodal-review/v1",
            "reviewer_role": "adversarial_reviewer",
            "dependencies": evaluator.deps,
            "receipt": receipt,
            "proposer_run_id": "proposal-1",
            "prompt_sha256": prompt["sha256"],
            "proposer_prompt_sha256": "different",
            "capability": {"sha256": "fixture-cap"},
        },
    )
    with pytest.raises(EvidenceError, match="Transcript-only") as error:
        evaluator.load_review(ref)
    assert error.value.status == "UNVERIFIED"
    assert not evaluator.valid_reviews


def test_partial_renamed_master_lacks_completed_manifest(evaluator, tmp_path):
    evaluator.source_domain = (Fraction(0), Fraction(10))
    evaluator.index["timeline"] = artifact(
        tmp_path,
        "timeline.json",
        {
            "domain": {"start": "0", "end": "10"},
            "retained": [
                {
                    "source_start": "0",
                    "source_end": "10",
                    "output_start": "0",
                    "output_end": "10",
                }
            ],
            "deletions": [],
            "duration": "10",
        },
    )
    evaluator.index["render"] = artifact(
        tmp_path,
        "render.json",
        {
            "render_id": "final",
            "status": "cancelled",
            "complete": False,
            "output": artifact(tmp_path, "renamed.mp4", "partial encoded bytes"),
        },
    )
    with pytest.raises(EvidenceError, match="Incomplete/cancelled"):
        evaluator.load_timeline_render()


def test_unreviewed_seam_and_deleted_context_stay_unverified(evaluator):
    evaluator.source_domain = (Fraction(0), Fraction(100))
    evaluator.output_domain = (Fraction(0), Fraction(90))
    evaluator.deletions = [(Fraction(10), Fraction(20))]
    evaluator.seams = [Fraction(10)]
    evaluator.valid_reviews = [
        {"scope": "output", "intervals": [(Fraction(0), Fraction(90))], "response": {}},
        {
            "scope": "analysis",
            "intervals": [(Fraction(0), Fraction(100))],
            "response": {},
        },
        {
            "scope": "deletion",
            "intervals": [(Fraction(10), Fraction(20))],
            "response": {},
        },
    ]
    with pytest.raises(EvidenceError, match="complete source and sentence context"):
        evaluator.review_coverage()
    assert evaluator.coverage["deleted_source"]["fraction"] == 1
    assert evaluator.coverage["deletion_count"]["numerator"] == 0
    assert evaluator.coverage["seams"]["uncovered_times"] == ["10"]


def test_invalid_index_schema_errors_are_not_success(tmp_path):
    frozen = freeze_contract(ROOT, tmp_path / "contract.json")
    artifact(
        tmp_path,
        "acceptance.local.json",
        {
            "schema_version": "acceptance-index/v1",
            "criteria": [{"id": "AC01", "status": "PASS"}],
        },
    )
    with pytest.raises(ValueError, match="Invalid acceptance index"):
        evaluate(tmp_path, "final", frozen["path"], ROOT)
    assert exit_code({"status": "PASS", "goal_achieved": True, "criteria": []}) == 1
    assert exit_code({"status": "UNVERIFIED", "goal_achieved": False}) == 1


def test_packaged_published_schema_is_identical_and_project_validates():
    for name in ("project-v1.schema.json", "acceptance-manifest.schema.json"):
        assert load_schema(name) == json.loads((ROOT / "schemas" / name).read_text())
    source = {
        "path": "/example.mp4",
        "sha256": "a" * 64,
        "bytes": 100,
        "role": "screen",
        "durable": True,
    }
    project = {
        "schema_version": "talkcut-project/v1",
        "revision": 0,
        "sources": {"screen": source, "speaker": {**source, "role": "speaker"}},
        "events": [],
        "owner_acceptance": "pending",
    }
    validate_project(project)
    for mutation in ("revision", "schema_version", "owner_acceptance"):
        invalid = {
            **project,
            mutation: {
                "revision": -1,
                "schema_version": "talkcut-project/v99",
                "owner_acceptance": "human_approved",
            }[mutation],
        }
        with pytest.raises(ValueError):
            validate_project(invalid)
    assert empty_index()["owner_acceptance"] == "pending"
