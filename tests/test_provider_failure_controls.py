"""Synthetic production-boundary controls; no actual-positive/model credit.

The full optional producer deliberately stays unexecuted without a real current
provider positive. These fixtures exercise deterministic faults, parser/content
rejection, conservation, and recovery at the factored production boundary.
"""

import ast
import copy
import inspect
import json
from pathlib import Path

import pytest

from talkcut import provider_failure_checks as controls
from talkcut import review
from talkcut.project import TalkCutError, artifact_ref, atomic_json


@pytest.fixture
def content(tmp_path):
    request = {"intervals": [["1/2", "3/2"], ["2", "4"]]}
    response = {
        "verdict": "PASS", "observed_modalities": ["audio", "video"],
        "continuous_video_observed": True,
        "reason": "Explicit synthetic response for production content-boundary tests only.",
        "findings": [], "needs_source_comparison": False,
        "observed_intervals": copy.deepcopy(request["intervals"]),
        "sampling_limitations": "This synthetic content does not establish actual audiovisual observation.",
        "dense_motion_and_lip_verified": False,
    }
    raw = tmp_path / "original.json"
    atomic_json(raw, response)
    return {"completed": True, "exit_code": 0, "response": artifact_ref(raw)}, request, {"precision_supported": False}


@pytest.mark.parametrize("kind", review.PROVIDER_CONTROL_FAULTS)
def test_named_fault_rejects_intended_gate_and_original_boundary_recovers(tmp_path, content, kind):
    execution, request, capability = content
    before = Path(execution["response"]["path"]).read_bytes()
    positive = review.review_observation_outcome(execution["response"], request, capability)
    assert positive["content_valid"] is True
    assert positive["coverage"] == request["intervals"]
    review.validate_provider_completion(execution)
    directory = tmp_path / kind
    directory.mkdir()
    result = review.provider_control_outcome(kind, execution, request, capability, directory)
    assert result["test_only"] is True and result["counterfactual"] is True
    assert result["actual_provider_outcome"] is False
    assert result["intended_rejection"] is True
    assert result["gate_content_valid"] is False
    assert result["original_response"] == execution["response"]
    injected = Path(result["injected_artifact"]["path"])
    assert artifact_ref(injected) == result["injected_artifact"]
    if kind in {"provider_timeout", "budget_exhaustion"}:
        assert result["boundary"] == "normalized_provider_completion"
        assert json.loads(injected.read_bytes())["injected_fields"] == {
            "completed": False, "exit_code": 124 if kind == "provider_timeout" else 75}
        assert execution["completed"] is True and execution["exit_code"] == 0
    else:
        assert result["boundary"] == "review_response_content"
        if kind == "empty_review":
            assert injected.read_bytes() == b""
        elif kind == "truncated_review":
            assert injected.read_bytes() == before.rstrip()[:-1]
        else:
            original = json.loads(before)
            altered = json.loads(injected.read_bytes())
            key = "observed_modalities" if kind == "modality_missing" else "observed_intervals"
            assert {k: v for k, v in original.items() if k != key} == {
                k: v for k, v in altered.items() if k != key}
            assert altered[key] == (["video"] if kind == "modality_missing" else [["5", "6"]])
    assert Path(execution["response"]["path"]).read_bytes() == before
    assert review.review_observation_outcome(execution["response"], request, capability) == positive
    review.validate_provider_completion(execution)


@pytest.mark.parametrize("completed,exit_code", [(True, 0), (True, False), (True, 1), (False, 0), (1, 0), (None, 0)])
def test_completion_uses_exact_boolean_and_integer_types(completed, exit_code):
    if completed is True and type(exit_code) is int and exit_code == 0:
        review.validate_provider_completion({"completed": completed, "exit_code": exit_code})
    else:
        with pytest.raises(TalkCutError, match="did not finish"):
            review.validate_provider_completion({"completed": completed, "exit_code": exit_code})


@pytest.mark.parametrize("kind", ["", "timeout", "all", True, [], {}, 124])
def test_unknown_fault_cannot_create_import_or_execute_commands(tmp_path, kind):
    with pytest.raises(TalkCutError, match="Unknown provider control fault"):
        review.import_review("missing", "missing", "missing", tmp_path / "out", control_fault=kind)
    assert not (tmp_path / "out").exists()


@pytest.mark.parametrize("kind", review.PROVIDER_CONTROL_FAULTS)
def test_early_invalid_positive_is_labelled_without_intended_gate_credit(tmp_path, kind):
    files = []
    for name, value in (("record", {}), ("request", {}), ("capability", {})):
        path = tmp_path / (name + ".json")
        atomic_json(path, value)
        files.append(path)
    result = review.import_review(*files, tmp_path / "out", control_fault=kind)
    assert result["status"] == "UNVERIFIED" and result["coverage"] == []
    assert result["owner_acceptance"] == "pending"
    assert result["control"]["test_only"] is True
    assert result["control"]["counterfactual"] is True
    assert result["control"]["intended_rejection"] is False
    assert result["control"]["boundary_reached"] is False
    with pytest.raises(TalkCutError, match=controls.STALE_CONTROL_REASON):
        review.verify_imported_review(result["artifact_ref"])


def test_control_is_refused_before_revalidation_even_if_claimed_pass(tmp_path):
    path = tmp_path / "injected.json"
    atomic_json(path, {"schema_version": "review-import/v1", "status": "PASS", "coverage": [[0, 10]],
                       "control": {}, "artifact_refs": {}})
    with pytest.raises(TalkCutError, match=controls.STALE_CONTROL_REASON):
        review.verify_imported_review(artifact_ref(path))
    assert not (tmp_path / "revalidations").exists()


def test_current_hashed_empty_json_reaches_parser_not_digest_failure(tmp_path, content):
    execution, request, capability = content
    path = tmp_path / "empty.raw"
    path.write_bytes(b"")
    outcome = review.review_observation_outcome(artifact_ref(path), request, capability)
    assert outcome["error_code"] == "INVALID_ARTIFACT"
    assert outcome["status"] == "UNVERIFIED" and outcome["coverage"] == []
    stale = {**execution["response"], "sha256": "0" * 64}
    assert review.review_observation_outcome(stale, request, capability)["error_code"] == "STALE_REVIEW"


def test_reference_closure_keeps_cycles_aliases_originals_and_raw_counterfactual(tmp_path):
    raw = tmp_path / "counterfactual.raw"
    raw.write_bytes(b"{")
    inner = tmp_path / "inner.json"
    atomic_json(inner, {"raw": artifact_ref(raw)})
    root = tmp_path / "root.json"
    atomic_json(root, {"left": artifact_ref(inner), "right": artifact_ref(inner)})
    refs = controls._closure(artifact_ref(root))
    assert {ref["path"] for ref in refs} == {str(path) for path in (raw, inner, root)}
    raw.write_bytes(b"changed")
    with pytest.raises(TalkCutError, match="bytes changed"):
        controls._closure(artifact_ref(root))


@pytest.mark.parametrize("flag", ["mock", "synthetic", "test_only"])
def test_synthetic_success_cannot_supply_actual_positive_without_any_verifier_mock(tmp_path, flag):
    refs = {}
    for name in ("record", "request", "capability"):
        path = tmp_path / (name + ".json")
        atomic_json(path, {flag: True})
        refs[name] = artifact_ref(path)
    positive = tmp_path / "positive.json"
    atomic_json(positive, {"schema_version": "review-import/v1", "status": "PASS", "owner_acceptance": "pending", "artifact_refs": refs})
    with pytest.raises(TalkCutError, match="Synthetic/mock positive"):
        controls._positive(artifact_ref(positive), {}, tmp_path / "control",
                           repo_root=tmp_path, contract_ref={})
    assert not (tmp_path / "control").exists()


@pytest.mark.parametrize("value", [{}, {"schema_version": "provider-failure-run/v1", "measurements": dict.fromkeys(review.PROVIDER_CONTROL_FAULTS, True)},
                                   {"schema_version": "failure-run/v1", "controls_executed": True}])
def test_labels_or_copied_measurements_do_not_replace_actual_positive(tmp_path, value):
    path = tmp_path / "fake-run.json"
    atomic_json(path, value)
    with pytest.raises(TalkCutError, match="Typed counterfactual"):
        controls.verify_provider_failure_controls(artifact_ref(path), dependencies={},
                                                  repo_root=tmp_path, output_dir=tmp_path / "replays")
    assert not (tmp_path / "replays").exists()


def test_complete_subject_denominator_and_stale_subjects(tmp_path):
    refs = {}
    for name in ("screen", "speaker", "output", "timeline", "contract"):
        path = tmp_path / name
        path.write_bytes(name.encode())
        refs[name] = artifact_ref(path)
    subjects = {"sources": {role: refs[role] for role in ("screen", "speaker")},
                **{name: refs[name] for name in ("output", "timeline", "contract")}}
    deps = {"source_hashes": {role: refs[role]["sha256"] for role in ("screen", "speaker")},
            **{name + "_hash": refs[name]["sha256"] for name in ("output", "timeline", "contract")},
            "code_tree_hash": "synthetic-boundary-only"}
    controls._subjects(subjects, deps)
    missing = copy.deepcopy(subjects)
    del missing["sources"]["speaker"]
    with pytest.raises(TalkCutError, match="denominator"):
        controls._subjects(missing, deps)
    stale = {**deps, "output_hash": "0" * 64}
    with pytest.raises(TalkCutError, match="output is stale"):
        controls._subjects(subjects, stale)


def test_failed_producer_keeps_all_six_unknown_and_preserves_error(tmp_path):
    result = controls.run_provider_failure_controls({}, subjects={}, dependencies={},
                     repo_root=tmp_path, output_dir=tmp_path / "controls")
    assert result["controls_executed"] is False
    assert result["measurements"] == dict.fromkeys(review.PROVIDER_CONTROL_FAULTS)
    assert result["status"] == "UNVERIFIED" and result["error"]
    assert Path(result["artifact_ref"]["path"]).is_file()


def test_output_cannot_be_inside_original_success_directory(tmp_path):
    positive = tmp_path / "positive.json"
    atomic_json(positive, {})
    with pytest.raises(TalkCutError, match="outside the original positive"):
        controls.run_provider_failure_controls(artifact_ref(positive), subjects={}, dependencies={},
                         repo_root=tmp_path, output_dir=tmp_path / "nested")
    assert not (tmp_path / "nested").exists()


def test_actor_gate_preserves_independent_positive_and_rejects_reuse():
    record = {"reviewer_role": "adversarial_reviewer", "owner_acceptance": "pending",
              "proposer_run_id": "proposal", "proposer_prompt_sha256": "proposal-prompt"}
    receipt = {"run_id": "review", "prompt_sha256": "review-prompt"}
    review.validate_review_actor(record, receipt)
    for altered in ({**receipt, "run_id": "proposal"}, {**receipt, "prompt_sha256": "proposal-prompt"}):
        with pytest.raises(TalkCutError):
            review.validate_review_actor(record, altered)
    with pytest.raises(TalkCutError, match="owner approval"):
        review.validate_review_actor({**record, "owner_acceptance": "accepted"}, receipt)


def test_raw_composite_dispatch_precedes_plain_completion_gate():
    # Structural preservation only: this does not invent a composite positive.
    source = ast.parse(inspect.getsource(review._receipt)).body[0]
    composite_if = next(i for i, node in enumerate(source.body) if isinstance(node, ast.If))
    completion = next(i for i, node in enumerate(source.body) if isinstance(node, ast.Expr)
                      and isinstance(node.value, ast.Call) and isinstance(node.value.func, ast.Name)
                      and node.value.func.id == "validate_provider_completion")
    assert composite_if < completion


def test_actual_cli_absent_positive_exits_two_with_all_six_unknown(tmp_path):
    import os
    import subprocess
    import sys

    raw = tmp_path / "input.json"
    atomic_json(raw, {"schema_version": "provider-failure-input/v1", "positive": {},
                      "subjects": {}, "dependencies": {}})
    env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1",
           "PYTHONPATH": str(Path(controls.__file__).resolve().parent.parent)}
    actual = subprocess.run([sys.executable, "-m", "talkcut.provider_failure_checks",
                            "--input", str(raw), "--repo", str(tmp_path),
                            "--output", str(tmp_path / "attempt")],
                            capture_output=True, env=env, timeout=10, check=False)
    (tmp_path / "stdout.json").write_bytes(actual.stdout)
    (tmp_path / "stderr.log").write_bytes(actual.stderr)
    assert actual.returncode == 2
    result = json.loads(actual.stdout)
    assert result["controls_executed"] is False
    assert result["measurements"] == dict.fromkeys(review.PROVIDER_CONTROL_FAULTS)
    assert result["test_only"] is True and result["status"] == "UNVERIFIED"
    assert json.loads(Path(result["artifact_ref"]["path"]).read_text())["error"]


@pytest.mark.parametrize("change", ["ref", "control", "status", "coverage", "owner"])
def test_retained_fault_cannot_rebind_or_promote(tmp_path, content, change):
    execution, request, capability = content
    directory = tmp_path / "fault-bytes"
    directory.mkdir()
    counterfactual = review.provider_control_outcome("empty_review", execution, request, capability, directory)
    original = {}
    for name in ("record", "request", "capability"):
        path = tmp_path / (name + ".json")
        atomic_json(path, {"synthetic_boundary": name})
        original[name] = artifact_ref(path)
    envelope = {"schema_version": "review-import/v1", "owner_acceptance": "pending",
                "artifact_refs": copy.deepcopy(original), "status": "UNVERIFIED", "coverage": [],
                "control": counterfactual}
    path = tmp_path / "import.json"
    atomic_json(path, envelope)
    controls._retained_import(artifact_ref(path), original, fault=True)
    if change == "ref":
        envelope["artifact_refs"]["record"] = original["request"]
    elif change == "control":
        envelope["control"]["actual_provider_outcome"] = True
    elif change == "status":
        envelope["status"] = "PASS"
    elif change == "coverage":
        envelope["coverage"] = [["0", "1"]]
    else:
        envelope["owner_acceptance"] = "accepted"
    atomic_json(path, envelope)
    with pytest.raises(TalkCutError):
        controls._retained_import(artifact_ref(path), original, fault=True)


def test_optional_input_preserves_original_eighteen_case_denominator():
    from talkcut.contracts import CHECK_REQUIREMENTS
    from talkcut.failure_checks import verify_failure_checks

    assert len(CHECK_REQUIREMENTS["failure_injection"]) == 18
    assert set(review.PROVIDER_CONTROL_FAULTS).issubset(CHECK_REQUIREMENTS["failure_injection"])
    source = inspect.getsource(verify_failure_checks)
    assert 'raw.get("provider_controls") is not None' in source
    assert 'dependencies=dependencies' in source
