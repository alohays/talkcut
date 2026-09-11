"""Independent negative probes; authored fixtures never certify actual media.

These tests assert rejection. Successful construction of a receipt-shaped JSON
document is deliberately not represented as a real provider execution.
"""

import json
import shutil
import subprocess
from copy import deepcopy
from fractions import Fraction
from pathlib import Path

import pytest

from talkcut.acceptance import Evaluator, EvidenceError, empty_index
from talkcut.contracts import CHECK_REQUIREMENTS, file_hash, freeze_contract
from talkcut.project import TalkCutError, artifact_ref
from talkcut.review import _capability, _clip, validate_review_request

ROOT = Path(__file__).resolve().parents[1]


def artifact(directory, name, value):
    path = directory / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value if isinstance(value, str) else json.dumps(value))
    return {"path": str(path), "sha256": file_hash(path)}


def receipt(directory, name, deps, *, request=None, response=None):
    value = {
        "schema_version": "execution-receipt/v1",
        "run_id": name,
        "started_at": "2026-01-01T00:00:00Z",
        "finished_at": "2026-01-01T00:00:01Z",
        "completed": True,
        "exit_code": 0,
        "executor": "independent-negative-fixture",
        "tool_version": "authored-fixture/v1",
        "command": ["fixture-only"],
        "log": artifact(
            directory, name + ".log", "Authored negative fixture, not a provider run."
        ),
        "dependencies": deps,
    }
    if request is not None:
        prompt = artifact(
            directory, name + ".prompt", "Authored independent negative-test prompt."
        )
        value.update(
            provider_request_id="authored-" + name,
            model_revision="authored-negative-fixture",
            prompt=prompt,
            prompt_sha256=prompt["sha256"],
            request=artifact(directory, name + ".request.json", request),
            response=artifact(directory, name + ".response.json", response),
        )
    return artifact(directory, name + ".receipt.json", value)


def test_measurements_cannot_borrow_an_unrelated_successful_receipt(tmp_path):
    evaluator = Evaluator(tmp_path, "final", tmp_path / "contract.json", ROOT)
    run = receipt(tmp_path, "unrelated-calculation", evaluator.deps)
    evidence = {
        "schema_version": "measurement-check/v1",
        "check_id": "recovery",
        "dependencies": evaluator.deps,
        "receipt": run,
        "measurements": CHECK_REQUIREMENTS["recovery"],
        "evidence_refs": [
            artifact(
                tmp_path, "unrelated-result.json", {"calculation": "1 + 1", "result": 2}
            )
        ],
    }
    evaluator.index["checks"] = {
        "recovery": artifact(tmp_path, "measurement.json", evidence)
    }
    with pytest.raises(EvidenceError):
        evaluator.measured_check("recovery")


def test_matching_result_labels_cannot_certify_unrelated_recovery_evidence(tmp_path):
    evaluator = Evaluator(tmp_path, "final", tmp_path / "contract.json", ROOT)
    unrelated = artifact(
        tmp_path, "unrelated-result.json", {"calculation": "1 + 1", "result": 2}
    )
    result = {
        "schema_version": "measurement-result/v1",
        "check_id": "recovery",
        "dependencies": evaluator.deps,
        "measurements": CHECK_REQUIREMENTS["recovery"],
        "evidence_refs": [unrelated],
    }
    run_ref = receipt(tmp_path, "unrelated-calculation", evaluator.deps)
    run = json.loads(Path(run_ref["path"]).read_text())
    run.update(
        {
            "operation": "check:recovery",
            "result": artifact(tmp_path, "matching-result.json", result),
            "stdout": artifact(tmp_path, "matching-stdout.json", result),
        }
    )
    evidence = {
        "schema_version": "measurement-check/v1",
        "check_id": "recovery",
        "dependencies": evaluator.deps,
        "receipt": artifact(tmp_path, "relabeled-receipt.json", run),
        "measurements": CHECK_REQUIREMENTS["recovery"],
        "evidence_refs": [unrelated],
    }
    evaluator.index["checks"] = {
        "recovery": artifact(tmp_path, "measurement.json", evidence)
    }
    with pytest.raises(EvidenceError):
        evaluator.measured_check("recovery")


def test_release_snapshot_must_be_bound_to_actual_remote_verification(
    tmp_path, monkeypatch
):
    evaluator = Evaluator(tmp_path, "final", tmp_path / "contract.json", ROOT)
    remote = {
        "repository": "https://github.com/alohays/talkcut",
        "pr": {
            "state": "MERGED",
            "reviewed": True,
            "merge_commit": "not-a-git-commit",
            "url": "https://github.com/alohays/talkcut/pull/1",
        },
        "required_checks": [{"conclusion": "SUCCESS"}],
        "protection_bypassed": False,
        "tag_commit": "not-a-git-commit",
        "code_tree_hash": evaluator.identity["code_tree_hash"],
        "release": {
            "target_commit": "not-a-git-commit",
            "prerelease": True,
            "tag": "v0.0.0-alpha-fixture",
            "url": "https://github.com/alohays/talkcut/releases/tag/v0.0.0-alpha-fixture",
        },
    }
    run_ref = receipt(tmp_path, "unrelated-local-command", evaluator.deps)
    run = json.loads(Path(run_ref["path"]).read_text())
    run["executor"] = "github-verification"
    evaluator.index["release"] = artifact(
        tmp_path,
        "release.json",
        {
            "dependencies": evaluator.deps,
            "receipt": artifact(tmp_path, "remote-label-receipt.json", run),
            "remote_snapshot": artifact(tmp_path, "remote-snapshot.json", remote),
        },
    )
    # This probe isolates remote provenance from the independently tested privacy
    # gate. It performs no network, publication, or actual release acceptance.
    monkeypatch.setattr(evaluator, "measured_check", lambda _: {})
    with pytest.raises(EvidenceError):
        evaluator.release_check()


def test_severity_downgrade_requires_verified_independent_evidence(tmp_path):
    frozen = freeze_contract(ROOT, tmp_path / "contract.json")
    index = empty_index()
    index["findings"] = [
        {
            "id": "unresolved-sync-defect",
            "original_severity": "P1",
            "severity": "P2",
            "resolved": False,
            "severity_change_reason": "A separate auditor supposedly approved this downgrade.",
            "independent_review_ref": {
                "path": "DOES-NOT-EXIST.json",
                "sha256": "0" * 64,
            },
        }
    ]
    artifact(tmp_path, "acceptance.local.json", index)
    report = Evaluator(tmp_path, "final", Path(frozen["path"]), ROOT).evaluate()
    finding_check = next(
        check
        for criterion in report["criteria"]
        if criterion["id"] == "AC09"
        for check in criterion["checks"]
        if check["check_id"] == "open_P0_P1"
    )
    assert finding_check["status"] != "PASS"
    assert report["open_findings"]


def test_capability_rejects_text_files_claimed_as_observed_audio_video(tmp_path):
    challenge = {"audio_events": ["authored beep"], "video_events": ["authored flash"]}
    execution = receipt(
        tmp_path,
        "capability",
        {},
        request={
            "input_modalities": ["transcript"],
            "text": "Authored beep and flash labels.",
        },
        response=challenge,
    )
    run = json.loads(Path(execution["path"]).read_text())
    plain_text = artifact(
        tmp_path, "not-media.txt", "This file has no audio, video, or image stream."
    )
    observation = {
        "audio_continuous": True,
        "video_frame_timestamps": ["0", "1/25"],
        "frame_artifacts": [plain_text, plain_text],
        "audio_artifact": plain_text,
        "request_sha256": run["request"]["sha256"],
    }
    capability = {
        "schema_version": "review-capability/v1",
        "model_revision": "authored-negative-fixture",
        "receipt": execution,
        "challenge": artifact(tmp_path, "challenge.json", challenge),
        "observations": artifact(tmp_path, "observations.json", challenge),
        "input_observation": artifact(tmp_path, "sampling.json", observation),
    }
    with pytest.raises(TalkCutError):
        _capability(capability)


def test_independent_audit_cannot_relabel_an_unrelated_request_snapshot(tmp_path):
    evaluator = Evaluator(tmp_path, "final", tmp_path / "contract.json", ROOT)
    evaluator.analysis = {"proposer_run_id": "proposal"}
    output = artifact(
        tmp_path,
        "fixture-final.mp4",
        "No media acceptance is claimed by this isolated audit test.",
    )
    evaluator.render = {"output": output}
    handoff = {
        "dependencies": evaluator.deps,
        "owner_acceptance": "pending",
        "final_output_path": output["path"],
        "rerun_commands": ["fixture-only"],
        "restore_commands": ["fixture-only"],
        "actual_measurements": {},
        "cost_usage": {},
        "unfulfilled_ac": ["all actual media conditions remain unverified"],
        "checkpoint": artifact(tmp_path, "checkpoint.json", {"fixture_only": True}),
    }
    evaluator.index["handoff"] = artifact(tmp_path, "handoff.json", handoff)
    for name in ("registration", "timeline", "render", "analysis"):
        evaluator.index[name] = artifact(
            tmp_path, name + ".json", {"fixture_only": True}
        )
    snapshot = {
        "schema_version": "acceptance-snapshot/v1",
        "immutable": True,
        "dependencies": evaluator.deps,
        "implementation_run_ids": ["implementation"],
        "artifacts": list(evaluator.index.values()),
    }
    evaluator.index["snapshot"] = artifact(tmp_path, "snapshot.json", snapshot)
    run = receipt(
        tmp_path,
        "independent-audit",
        evaluator.deps,
        request={
            "snapshot_hash": "0" * 64,
            "input_artifacts": [],
            "scope": "unrelated-project",
        },
        response={
            "verdict": "PASS",
            "evaluator_reviewed": True,
            "fixed_fixture_expectations_reviewed": True,
            "media_and_logs_rechecked": True,
            "open_P0_P1": 0,
            "reason": "Authored response for an unrelated fixture snapshot, not this audit target.",
        },
    )
    evaluator.index["audit"] = artifact(
        tmp_path,
        "audit.json",
        {
            "dependencies": evaluator.deps,
            "receipt": run,
            "snapshot_hash": evaluator.index["snapshot"]["sha256"],
            "reviewer_role": "independent_auditor",
            "reviewer_run_id": "independent-audit",
        },
    )
    with pytest.raises(EvidenceError):
        evaluator.audit_handoff()


def test_current_failed_provider_review_remains_an_open_blocker(tmp_path):
    frozen = freeze_contract(ROOT, tmp_path / "contract.json")
    evaluator = Evaluator(tmp_path, "final", Path(frozen["path"]), ROOT)
    evaluator.load_contract()
    # Isolate aggregation after the capability gate; no actual capability or
    # actual media acceptance is asserted by this unit fixture.
    evaluator.capabilities["fixture-capability"] = {
        "model_revision": "authored-negative-fixture"
    }
    run = receipt(
        tmp_path,
        "current-review",
        evaluator.deps,
        request={},
        response={
            "verdict": "FAIL",
            "reason": "The current fixture review reports an unresolved synchronization defect.",
            "findings": [{"id": "current-sync", "severity": "P1", "resolved": False}],
        },
    )
    execution = json.loads(Path(run["path"]).read_text())
    record = artifact(
        tmp_path,
        "current-review.json",
        {
            "schema_version": "multimodal-review/v1",
            "reviewer_role": "adversarial_reviewer",
            "dependencies": evaluator.deps,
            "receipt": run,
            "proposer_run_id": "proposal",
            "prompt_sha256": execution["prompt_sha256"],
            "proposer_prompt_sha256": "separate-instructions",
            "capability": {"sha256": "fixture-capability"},
        },
    )
    index = empty_index()
    index["reviews"] = [record]
    artifact(tmp_path, "acceptance.local.json", index)
    report = evaluator.evaluate()
    assert report["invalid_evidence"]
    assert report["open_findings"], (
        "Current provider P1 was silently demoted to ignored invalid evidence"
    )


@pytest.fixture
def traced_review(tmp_path):
    """Actual synthetic extraction, authored provider response; no DGIST claim."""
    if not shutil.which("ffmpeg") or not shutil.which("ffprobe"):
        pytest.skip("FFmpeg and FFprobe required")
    parent = tmp_path / "synthetic-parent.mp4"
    subprocess.run(
        [
            "ffmpeg",
            "-v",
            "error",
            "-f",
            "lavfi",
            "-i",
            "testsrc2=size=96x64:rate=25:duration=2",
            "-f",
            "lavfi",
            "-i",
            "sine=frequency=440:sample_rate=48000:duration=2",
            "-c:v",
            "libx264",
            "-c:a",
            "aac",
            str(parent),
        ],
        check=True,
        capture_output=True,
    )
    evaluator = Evaluator(tmp_path, "final", tmp_path / "contract.json", ROOT)
    evaluator.deps.update(
        {
            "source_hashes": {"screen": file_hash(parent)},
            "contract_hash": "authored-contract",
            "timeline_hash": "authored-timeline",
            "output_hash": file_hash(parent),
        }
    )
    clip = _clip(
        artifact_ref(parent),
        (Fraction(0), Fraction(1)),
        tmp_path / "clip",
        evaluator.deps,
    )
    request = {
        "schema_version": "review-request/v1",
        "scope": "output",
        "dependencies": evaluator.deps,
        "inputs": [clip],
        "input_clip_hashes": [clip["clip"]["sha256"]],
        "intervals": [["0", "1"]],
    }
    response = {
        "verdict": "PASS",
        "observed_modalities": ["audio", "video"],
        "continuous_video_observed": True,
        "reason": "Authored synthetic unit response; this does not certify real audiovisual observation.",
        "findings": [],
        "needs_source_comparison": False,
        "observed_intervals": [["0", "1"]],
        "observed_frame_count": 25,
    }
    execution_ref = receipt(
        tmp_path,
        "structural-review",
        evaluator.deps,
        request=request,
        response=response,
    )
    execution = json.loads(Path(execution_ref["path"]).read_text())
    record = {
        "schema_version": "multimodal-review/v1",
        "scope": "output",
        "dependencies": evaluator.deps,
        "inputs": [clip],
        "reviewer_role": "adversarial_reviewer",
        "receipt": execution_ref,
        "proposer_run_id": "proposal",
        "prompt_sha256": execution["prompt_sha256"],
        "proposer_prompt_sha256": "separate-instructions",
        "capability": {"sha256": "fixture-capability"},
    }
    evaluator.capabilities["fixture-capability"] = {
        "model_revision": "authored-negative-fixture",
        "temporal_resolution_ms": 40,
    }
    evaluator.source_domain = evaluator.output_domain = (Fraction(0), Fraction(2))
    return evaluator, record, execution, request, response


def test_actual_synthetic_extraction_satisfies_structural_binding(traced_review):
    evaluator, record, execution, request, _ = traced_review
    assert validate_review_request(record, execution) == request
    ref = artifact(evaluator.project, "review-control.json", record)
    assert evaluator.load_review(ref)["intervals"] == [(Fraction(0), Fraction(1))]


def test_multiple_actual_clips_preserve_request_coverage(traced_review):
    evaluator, record, execution, request, response = traced_review
    second_clip = _clip(
        record["inputs"][0]["parent_media"],
        (Fraction(1), Fraction(2)),
        evaluator.project / "second-clip",
        evaluator.deps,
    )
    request["inputs"] = record["inputs"] = [record["inputs"][0], second_clip]
    request["input_clip_hashes"] = [
        item["clip"]["sha256"] for item in request["inputs"]
    ]
    request["intervals"] = response["observed_intervals"] = [["0", "1"], ["1", "2"]]
    response["observed_frame_count"] = 50
    execution["request"] = artifact(evaluator.project, "multi-request.json", request)
    execution["response"] = artifact(evaluator.project, "multi-response.json", response)
    record["receipt"] = artifact(evaluator.project, "multi-receipt.json", execution)
    assert validate_review_request(record, execution) == request
    ref = artifact(evaluator.project, "multi-review.json", record)
    assert evaluator.load_review(ref)["intervals"] == [
        (Fraction(0), Fraction(1)),
        (Fraction(1), Fraction(2)),
    ]


@pytest.mark.parametrize(
    ("mutation", "expected_reason"),
    [
        ("scope", "scope differs"),
        ("request_interval", "not present in actual clips"),
        ("request_dependency", "dependencies differ"),
        ("extraction_interval", "interval differs from actual extraction"),
        ("clip_bytes", "missing or changed"),
        ("parent_bytes", "missing or changed"),
    ],
)
def test_review_scope_time_dependencies_and_media_are_bound(
    traced_review, mutation, expected_reason
):
    evaluator, record, execution, request, response = traced_review
    record, execution, request, response = deepcopy(
        (record, execution, request, response)
    )
    if mutation == "scope":
        request["scope"] = "seam"
    elif mutation == "request_interval":
        request["intervals"] = [["1", "2"]]
    elif mutation == "request_dependency":
        request["dependencies"]["timeline_hash"] = "different-timeline"
        # deepcopy preserves shared dict identity; restore record/receipt explicitly.
        record["dependencies"] = dict(evaluator.deps)
        execution["dependencies"] = dict(evaluator.deps)
    elif mutation == "extraction_interval":
        record["inputs"][0]["interval"] = ["1", "2"]
        request["inputs"] = deepcopy(record["inputs"])
        request["intervals"] = response["observed_intervals"] = [["1", "2"]]
    else:
        key = "clip" if mutation == "clip_bytes" else "parent_media"
        Path(record["inputs"][0][key]["path"]).write_text(
            "Replaced synthetic fixture bytes."
        )
    execution["request"] = artifact(evaluator.project, "mutated-request.json", request)
    execution["response"] = artifact(
        evaluator.project, "mutated-response.json", response
    )
    record["receipt"] = artifact(evaluator.project, "mutated-receipt.json", execution)
    with pytest.raises(TalkCutError, match=expected_reason):
        validate_review_request(record, execution)
    with pytest.raises((EvidenceError, TalkCutError)):
        evaluator.load_review(
            artifact(evaluator.project, "mutated-review.json", record)
        )
