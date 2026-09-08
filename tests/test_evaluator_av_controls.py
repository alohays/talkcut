"""Closed adapter boundaries; authored unit inputs never establish actual AV.

Only tests explicitly replacing the positive-validation function isolate the
production fault gate. No such replacement exists in a subprocess producer.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from talkcut import evaluator_av_controls as av
from talkcut.acceptance import EvidenceError
from talkcut.contracts import CHECK_REQUIREMENTS, code_identity
from talkcut.evaluator_negative import MISSING_CONTROLS, _probe
from talkcut.project import TalkCutError, artifact_ref, atomic_json, sha256

REPO = Path(__file__).resolve().parents[1]


def save(root, name, value):
    path = root / name
    atomic_json(path, value)
    return artifact_ref(path)


@pytest.fixture
def declared(tmp_path):
    deps = {
        "code_tree_hash": code_identity(REPO)["code_tree_hash"],
        "contract_hash": "c" * 64,
        "source_hashes": {"screen": "s" * 64},
        "timeline_hash": "t" * 64,
        "output_hash": "o" * 64,
    }
    subjects = {
        "sources": {
            "screen": save(tmp_path, "subject-source.json", {"unit_test_only": True})
        },
        "output": save(tmp_path, "subject-output.json", {"unit_test_only": True}),
        "contract": save(tmp_path, "subject-contract.json", {"unit_test_only": True}),
        "timeline": save(tmp_path, "subject-timeline.json", {"unit_test_only": True}),
    }
    deps.update(
        source_hashes={"screen": subjects["sources"]["screen"]["sha256"]},
        **{
            key + "_hash": subjects[key]["sha256"]
            for key in ("output", "contract", "timeline")
        },
    )
    raw = save(
        tmp_path,
        "authored-unverified.json",
        {"verdict": "PASS", "human_approved": True},
    )
    envelopes = {}
    for key in av.SCOPES:
        field = "editorial_fixture" if key == "always_keep" else "review_import"
        envelopes[key] = save(
            tmp_path,
            key + ".json",
            {
                "schema_version": "evaluator-av-positive/v2",
                "case_id": key,
                "dependencies": deps,
                "subjects": subjects,
                field: raw,
            },
        )
    registry = {
        "schema_version": "evaluator-av-positive-controls/v2",
        "dependencies": deps,
        "controls": envelopes,
    }
    return deps, envelopes, registry


def test_no_positive_leaves_all_three_missing_and_ten_denominator(declared):
    deps, _, _ = declared
    assert av.bound_controls(None, REPO, deps) == {}
    assert set(MISSING_CONTROLS) == set(av.SCOPES)
    assert len(CHECK_REQUIREMENTS["evaluator_negative"]) == 10


def test_closed_registry_is_only_a_binding_not_positive_approval(tmp_path, declared):
    deps, envelopes, registry = declared
    assert (
        av.bound_controls(save(tmp_path, "registry.json", registry), REPO, deps)
        == envelopes
    )
    for key, ref in envelopes.items():
        code, result = _probe(
            REPO, key, av.inputs(key, ref, deps, attack=True), output_dir=tmp_path
        )
        assert code != 0 and result["status"] == "FAIL"
        assert "Legitimate positive unavailable:" in result["reason"]
        assert result.get("facts", {}).get("positive_verified") is not True
        assert result["coverage"] == []
    assert not list(tmp_path.rglob("counterfactual.json"))


@pytest.mark.parametrize("key", ["schema_version", "dependencies", "controls", "argv"])
def test_registry_missing_or_extra_fields_reject(tmp_path, declared, key):
    deps, _, value = declared
    if key == "argv":
        value[key] = ["touch", str(tmp_path / "unexecuted")]
    else:
        value.pop(key)
    with pytest.raises(TalkCutError):
        av.bound_controls(save(tmp_path, "registry.json", value), REPO, deps)
    assert not (tmp_path / "unexecuted").exists()


@pytest.mark.parametrize("bad", [None, [], "transcript_only", {"other": {}}])
def test_registry_control_type_and_unknown_case_reject(tmp_path, declared, bad):
    deps, _, value = declared
    value["controls"] = bad
    with pytest.raises(TalkCutError):
        av.bound_controls(save(tmp_path, "registry.json", value), REPO, deps)


@pytest.mark.parametrize(
    "key",
    [
        "code_tree_hash",
        "contract_hash",
        "timeline_hash",
        "output_hash",
        "source_hashes",
    ],
)
def test_registry_dependencies_cannot_differ(tmp_path, declared, key):
    deps, _, value = declared
    value = copy.deepcopy(value)
    value["dependencies"][key] = "changed"
    with pytest.raises(TalkCutError, match="dependencies"):
        av.bound_controls(save(tmp_path, "registry.json", value), REPO, deps)


@pytest.mark.parametrize(
    "mutation", ["case", "schema", "extra", "missing", "dependency", "hash"]
)
def test_exact_envelope_binding_rejects_unrelated_fields(tmp_path, declared, mutation):
    deps, envelopes, registry = declared
    value = av.read(envelopes["transcript_only"])
    if mutation == "case":
        value["case_id"] = "fabricated_pass"
    elif mutation == "schema":
        value["schema_version"] = "PASS"
    elif mutation == "extra":
        value["argv"] = ["false"]
    elif mutation == "missing":
        value.pop("review_import")
    elif mutation == "dependency":
        value["dependencies"]["output_hash"] = "stale"
    else:
        value["review_import"]["sha256"] = "0" * 64
    registry["controls"]["transcript_only"] = save(tmp_path, "changed.json", value)
    with pytest.raises(TalkCutError):
        av.bound_controls(save(tmp_path, "registry.json", registry), REPO, deps)


@pytest.mark.parametrize(
    "mutation", ["none", "list", "relative", "hash", "alias", "extra", "duplicate"]
)
def test_positive_ref_types_alias_and_duplicate_json(tmp_path, mutation):
    ref = save(tmp_path, "value.json", {"x": 1})
    if mutation == "none":
        ref = None
    elif mutation == "list":
        ref = []
    elif mutation == "relative":
        ref["path"] = "value.json"
    elif mutation == "hash":
        ref["sha256"] = "0" * 64
    elif mutation == "alias":
        alias = tmp_path / "alias.json"
        alias.symlink_to(Path(ref["path"]).name)
        ref["path"] = str(alias)
    elif mutation == "extra":
        ref["bytes"] = 10
    else:
        Path(ref["path"]).write_text('{"x":1,"x":2}')
        ref = artifact_ref(ref["path"])
    with pytest.raises(TalkCutError):
        av.read(ref)


@pytest.mark.parametrize(
    "mutation",
    [
        "fault-list",
        "fault-null",
        "arbitrary-fault",
        "extra-argv",
        "missing-fault",
        "deps-null",
        "stale-code",
        "wrong-case",
        "positive-list",
    ],
)
def test_probe_input_cannot_inject_faults_or_commands(tmp_path, declared, mutation):
    deps, envelopes, _ = declared
    value = av.inputs(
        "transcript_only", envelopes["transcript_only"], deps, attack=True
    )
    value = copy.deepcopy(value)
    if mutation == "fault-list":
        value["fault"] = []
    elif mutation == "fault-null":
        value["fault"] = None
    elif mutation == "arbitrary-fault":
        value["fault"] = "fabricate_response"
    elif mutation == "extra-argv":
        value["argv"] = ["touch", str(tmp_path / "unexecuted")]
    elif mutation == "missing-fault":
        value.pop("fault")
    elif mutation == "deps-null":
        value["dependencies"] = None
    elif mutation == "stale-code":
        value["dependencies"]["code_tree_hash"] = "0" * 64
    elif mutation == "wrong-case":
        value["case_id"] = "always_keep"
    else:
        value["positive_control"] = []
    code, response = _probe(REPO, "transcript_only", value, output_dir=tmp_path)
    assert code != 0 and response.get("facts", {}).get("positive_verified") is not True
    assert not list(tmp_path.rglob("counterfactual.json"))
    assert not (tmp_path / "unexecuted").exists()


def unit_proof():
    return {
        "response": {
            "verdict": "PASS",
            "observed_modalities": ["audio", "video"],
            "continuous_video_observed": True,
            "reason": "Explicit synthetic content-gate unit fixture; never actual evidence.",
            "findings": [],
            "needs_source_comparison": False,
            "observed_intervals": [["0", "1"]],
        },
        "request": {"intervals": [["0", "1"]]},
        "normalized_capability": {},
        "record": {
            "reviewer_role": "adversarial_reviewer",
            "owner_acceptance": "pending",
            "proposer_run_id": "unit-proposer",
            "proposer_prompt_sha256": "unit-proposer-prompt",
        },
        "receipt": {"run_id": "unit-reviewer", "prompt_sha256": "unit-review-prompt"},
        "cases": [[{"start": "0", "end": "1", "expected_action": "cut"}]],
        "facts": {"unit_test_only": True, "no_actual_positive_claim": True},
    }


@pytest.mark.parametrize("case", sorted(av.SCOPES))
def test_labelled_counterfactual_exercises_real_gate_after_isolated_positive_boundary(
    tmp_path, declared, monkeypatch, case
):
    deps, refs, _ = declared
    proof = unit_proof()
    original = copy.deepcopy(proof)
    # Explicit unit isolation, impossible through a preserved runtime input.
    monkeypatch.setattr(av, "_preserve_positive", lambda *args: refs[case])
    monkeypatch.setattr(
        av, "_normalized_positive", lambda *args: {"unit_test_only": True}
    )
    monkeypatch.setattr(av, "_review_positive", lambda *args: proof)
    monkeypatch.setattr(av, "_editorial_positive", lambda *args: proof)
    code, positive = _probe(
        REPO, case, av.inputs(case, refs[case], deps, attack=False), output_dir=tmp_path
    )
    assert code == 0 and positive["facts"]["unit_test_only"] is True
    code, negative = _probe(
        REPO, case, av.inputs(case, refs[case], deps, attack=True), output_dir=tmp_path
    )
    assert code != 0 and negative["reason"] == av.REASONS[case]
    assert negative["error_type"] == "CounterfactualRejection"
    assert negative["facts"]["positive_verified"] is True
    assert negative["facts"]["counterfactual"] is True
    assert negative["coverage"] == [] and proof == original
    saved = json.loads(next(tmp_path.rglob("counterfactual.json")).read_text())
    assert saved["test_only"] is True and saved["audiovisual_review"] == "UNVERIFIED"
    if case == "transcript_only":
        expected = copy.deepcopy(proof["response"])
        expected.update(observed_modalities=["text"], continuous_video_observed=False)
    elif case == "fabricated_pass":
        expected = copy.deepcopy(proof["record"])
        expected.pop("reviewer_role")
    else:
        expected = {"selected": [], "complete_ledger": True}
    assert saved["value"] == expected


@pytest.mark.parametrize("case", sorted(av.SCOPES))
@pytest.mark.parametrize("error_kind", ["same-reason", "capability"])
def test_positive_failure_cannot_count_even_with_intended_reason(
    tmp_path, declared, monkeypatch, case, error_kind
):
    deps, refs, _ = declared

    def failed(*args):
        if error_kind == "capability":
            raise EvidenceError("Stale capability code", "UNVERIFIED")
        raise TalkCutError("UNIT_POSITIVE_FAILURE", av.REASONS[case])

    monkeypatch.setattr(av, "_review_positive", failed)
    monkeypatch.setattr(av, "_editorial_positive", failed)
    code, result = _probe(
        REPO, case, av.inputs(case, refs[case], deps, attack=True), output_dir=tmp_path
    )
    assert code != 0 and result["reason"].startswith("Legitimate positive unavailable:")
    assert result["error_type"] != "CounterfactualRejection" and "facts" not in result
    assert not list(tmp_path.rglob("counterfactual.json"))


@pytest.mark.parametrize("case", sorted(av.SCOPES))
def test_unexpected_gate_success_is_not_negative_pass(
    tmp_path, declared, monkeypatch, case
):
    deps, refs, _ = declared
    monkeypatch.setattr(av, "_preserve_positive", lambda *args: refs[case])
    monkeypatch.setattr(av, "_review_positive", lambda *args: unit_proof())
    monkeypatch.setattr(av, "_editorial_positive", lambda *args: unit_proof())
    monkeypatch.setattr(
        "talkcut.review.validate_observation_content", lambda *args: None
    )
    monkeypatch.setattr("talkcut.review.validate_review_actor", lambda *args: None)
    monkeypatch.setattr(
        "talkcut.editorial_checks._selection_matches", lambda *args, **kwargs: True
    )
    code, result = _probe(
        REPO, case, av.inputs(case, refs[case], deps, attack=True), output_dir=tmp_path
    )
    assert (
        code != 0
        and result["reason"] == "Fixed audiovisual counterfactual unexpectedly passed"
    )
    assert result["error_type"] != "CounterfactualRejection"


def test_authored_import_revalidation_writes_only_private_output(tmp_path, declared):
    deps, _, _ = declared
    original = tmp_path / "original-provider"
    original.mkdir()
    refs = {
        key: save(original, key + ".json", {})
        for key in ("record", "request", "capability")
    }
    imported = save(
        original,
        "import.json",
        {
            "schema_version": "review-import/v1",
            "artifact_refs": refs,
            "status": "PASS",
            "owner_acceptance": "pending",
        },
    )
    before = {p.name: sha256(p) for p in original.iterdir()}
    output = tmp_path / "private-output"
    output.mkdir()
    with pytest.raises(TalkCutError, match="Original provider review failed"):
        av._review_positive(
            {"review_import": imported, "dependencies": deps}, REPO, output
        )
    assert before == {p.name: sha256(p) for p in original.iterdir()}
    assert list(output.rglob("*.original.json"))
    assert not (original / "revalidations").exists()


@pytest.fixture
def isolated_intake(tmp_path, declared, monkeypatch):
    """Unit isolate imported intake; all current adapter gates remain callable."""
    deps, _, _ = declared
    proof = unit_proof()
    capability = save(tmp_path, "unit-capability.json", {})
    receipt = save(tmp_path, "unit-receipt.json", {})
    proof["record"].update(dependencies=copy.deepcopy(deps), receipt=receipt)
    proof["request"].update(
        dependencies=copy.deepcopy(deps),
        scope="output",
        inputs=[{"parent_sha256": deps["output_hash"]}],
    )
    proof["receipt"]["dependencies"] = copy.deepcopy(deps)
    proof["capability"] = {}
    imported = {
        "schema_version": "review-import/v1",
        "status": "PASS",
        "owner_acceptance": "pending",
        "artifact_refs": {"capability": capability},
    }
    monkeypatch.setattr("talkcut.review.verify_imported_review", lambda ref: proof)
    return deps, proof, imported, capability


@pytest.mark.parametrize(
    "component", ["import", "record", "request", "receipt", "capability", "response"]
)
@pytest.mark.parametrize(
    "flag", ["synthetic", "mock", "test_only", "self_attested_only"]
)
def test_every_positive_object_denies_synthetic_markers(
    tmp_path, isolated_intake, component, flag
):
    deps, proof, imported, _ = isolated_intake
    (imported if component == "import" else proof[component])[flag] = True
    ref = save(tmp_path, "unit-import.json", imported)
    directory = tmp_path / "revalidation"
    directory.mkdir()
    with pytest.raises(TalkCutError, match="Synthetic or mocked"):
        av._review_positive(
            {"review_import": ref, "dependencies": deps}, REPO, directory
        )


@pytest.mark.parametrize("component", ["record", "request", "receipt"])
@pytest.mark.parametrize("field", ["contract_hash", "timeline_hash", "source_hashes"])
def test_positive_intake_dependencies_cannot_diverge(
    tmp_path, isolated_intake, component, field
):
    deps, proof, imported, _ = isolated_intake
    proof[component]["dependencies"][field] = "stale"
    ref = save(tmp_path, "unit-import.json", imported)
    directory = tmp_path / "revalidation"
    directory.mkdir()
    with pytest.raises(TalkCutError, match="dependencies differ"):
        av._review_positive(
            {"review_import": ref, "dependencies": deps}, REPO, directory
        )


def test_intake_cannot_skip_actual_current_capability_gate(tmp_path, isolated_intake):
    deps, _, imported, _ = isolated_intake
    ref = save(tmp_path, "unit-import.json", imported)
    directory = tmp_path / "revalidation"
    directory.mkdir()
    # Actual loader rejects the empty capability after isolated import intake.
    with pytest.raises(EvidenceError, match="Reviewer capability schema missing"):
        av._review_positive(
            {"review_import": ref, "dependencies": deps}, REPO, directory
        )


@pytest.mark.parametrize(
    "scope,parent",
    [
        ("output", "stale-output"),
        ("analysis", "stale-source"),
        ("owner_acceptance", "o" * 64),
    ],
)
def test_positive_scope_and_source_binding_after_current_gate(
    tmp_path, isolated_intake, monkeypatch, scope, parent
):
    deps, proof, imported, capability = isolated_intake
    proof["request"].update(scope=scope, inputs=[{"parent_sha256": parent}])
    calls = []

    def capability_gate(evaluator, ref):
        assert evaluator.deps == deps and ref == capability
        calls.append("capability")
        evaluator.capabilities[ref["sha256"]] = proof["normalized_capability"]

    def receipt_gate(evaluator, ref, **kwargs):
        assert evaluator.deps == deps and kwargs == {"provider": True}
        calls.append("receipt")

    monkeypatch.setattr("talkcut.acceptance.Evaluator.load_capability", capability_gate)
    monkeypatch.setattr("talkcut.acceptance.Evaluator.receipt", receipt_gate)
    ref = save(tmp_path, "unit-import.json", imported)
    directory = tmp_path / "revalidation"
    directory.mkdir()
    with pytest.raises(TalkCutError, match="unsupported scope|current source/output"):
        av._review_positive(
            {"review_import": ref, "dependencies": deps}, REPO, directory
        )
    assert calls == ["capability", "receipt"]


def test_actual_full_nonverbal_media_does_not_supply_missing_editorial_positive(
    tmp_path, declared
):
    from talkcut.editorial_checks import generate_nonverbal_fixture

    deps, _, _ = declared
    result = generate_nonverbal_fixture(tmp_path / "actual-media", REPO)
    assert result["status"] == "UNVERIFIED"
    assert all(value is None for value in result["measurements"].values())
    original = av.read(result["input"])
    original_sha = result["input"]["sha256"]
    # Explicit test input copy adds the declared contract context. It does not
    # alter the producer's original media, analysis, source rows or null result.
    copied = copy.deepcopy(original)
    copied["dependencies"]["contract_hash"] = deps["contract_hash"]
    raw_ref = save(tmp_path, "actual-media-input-with-declared-contract.json", copied)
    envelope = save(
        tmp_path,
        "actual-editorial-positive-envelope.json",
        {
            "schema_version": "evaluator-av-positive/v2",
            "case_id": "always_keep",
            "dependencies": deps,
            "subjects": av.read(declared[1]["always_keep"])["subjects"],
            "editorial_fixture": raw_ref,
        },
    )
    code, response = _probe(
        REPO,
        "always_keep",
        av.inputs("always_keep", envelope, deps, attack=True),
        output_dir=tmp_path,
    )
    assert code != 0 and response["error_type"] != "CounterfactualRejection"
    assert "Complete actual editorial positive" in response["reason"]
    assert response.get("facts", {}).get("positive_verified") is not True
    assert sha256(result["input"]["path"]) == original_sha
    assert not list(tmp_path.rglob("counterfactual.json"))


def test_actual_cli_cannot_promote_authored_positives_or_skip_seven_controls(
    tmp_path, declared
):
    import os
    import subprocess
    import sys

    deps, _, registry = declared
    reference = save(tmp_path, "registry.json", registry)
    destination = tmp_path / "actual-negative-cli"
    command = [
        sys.executable,
        "-m",
        "talkcut.evaluator_negative",
        "run",
        "--repo",
        str(REPO),
        "--output",
        str(destination),
        "--positive-controls",
        reference["path"],
    ]
    completed = subprocess.run(
        command,
        cwd=REPO,
        env={**os.environ, "PYTHONPATH": str(REPO / "src")},
        capture_output=True,
        text=True,
        timeout=180,
        check=False,
    )
    (tmp_path / "cli.stdout.log").write_text(completed.stdout)
    (tmp_path / "cli.stderr.log").write_text(completed.stderr)
    assert completed.returncode != 0
    attempts = list(destination.rglob("attempt.json"))
    assert len(attempts) == 1
    raw = json.loads(attempts[0].read_text())
    assert raw["dependencies"] == deps
    assert set(raw["cases"]) == set(CHECK_REQUIREMENTS["evaluator_negative"])
    assert raw["test_only"] is True and raw["actual_dgist_acceptance"] is False
    assert not (attempts[0].parent / "result.json").exists()
    assert (attempts[0].parent / "verification-failure.json").is_file()
    for case_id, case in raw["cases"].items():
        for pair in case["pairs"]:
            if case_id not in av.SCOPES:
                assert (
                    pair["control"]["exit_code"] == 0
                    and pair["attack"]["exit_code"] != 0
                )
                continue
            for side in ("control", "attack"):
                assert pair[side]["exit_code"] != 0
                response = json.loads(Path(pair[side]["stdout"]["path"]).read_text())
                assert response["reason"].startswith("Legitimate positive unavailable:")
                assert response.get("facts", {}).get("positive_verified") is not True
                assert response["error_type"] != "CounterfactualRejection"
    assert not list(destination.rglob("counterfactual.json"))


@pytest.mark.parametrize("missing", ["sources", "output", "contract", "timeline"])
def test_complete_current_subject_denominator_is_required(tmp_path, declared, missing):
    deps, refs, registry = declared
    value = av.read(refs["transcript_only"])
    value["subjects"].pop(missing)
    registry["controls"]["transcript_only"] = save(
        tmp_path, "changed-subject.json", value
    )
    with pytest.raises(TalkCutError, match="subjects"):
        av.bound_controls(
            save(tmp_path, "registry-subjects.json", registry), REPO, deps
        )


@pytest.mark.parametrize("case", sorted(av.SCOPES))
@pytest.mark.parametrize(
    "boundary",
    [
        "good",
        "changed-source",
        "failed-recovery",
        "changed-recovery-facts",
        "changed-observations",
    ],
)
def test_measured_fault_recovery_order_under_explicit_unit_positive_isolation(
    tmp_path, declared, monkeypatch, case, boundary
):
    deps, refs, _ = declared
    calls = []
    proof = unit_proof()

    def positive(*args):
        calls.append("positive")
        if len(calls) == 2:
            if boundary == "failed-recovery":
                raise TalkCutError("UNIT_RECOVERY_UNVERIFIED", av.REASONS[case])
            if boundary == "changed-recovery-facts":
                return {**proof, "facts": {"different": True}}
        return copy.deepcopy(proof)

    monkeypatch.setattr(av, "_review_positive", positive)
    monkeypatch.setattr(av, "_editorial_positive", positive)
    monkeypatch.setattr(av, "_preserve_positive", lambda *args: refs[case])
    normalized_calls = []

    def normalized(*args):
        normalized_calls.append(1)
        return {
            "unit_test_only": True,
            "different": len(normalized_calls)
            if boundary == "changed-observations"
            else 0,
        }

    monkeypatch.setattr(av, "_normalized_positive", normalized)
    if boundary == "changed-source":
        source = av.read(refs[case])["subjects"]["sources"]["screen"]

        def changed(*args, **kwargs):
            Path(source["path"]).write_text("ACTUAL UNIT SOURCE MUTATION")
            raise TalkCutError("UNIT_GATE_REJECTION", av.REASONS[case])

        monkeypatch.setattr("talkcut.review.validate_observation_content", changed)
        monkeypatch.setattr("talkcut.review.validate_review_actor", changed)
        monkeypatch.setattr("talkcut.editorial_checks._selection_matches", changed)
    code, result = _probe(
        REPO, case, av.inputs(case, refs[case], deps, attack=True), output_dir=tmp_path
    )
    assert code != 0
    if boundary == "good":
        assert calls == ["positive", "positive"]
        assert result["error_type"] == "CounterfactualRejection"
        assert result["facts"]["recovery_verified"] is True
        artifacts = result["facts"]["execution_artifacts"]
        assert set(artifacts) == {
            "before",
            "positive",
            "counterfactual",
            "after_fault",
            "recovery",
            "after_recovery",
            "stale_before",
            "stale_after",
        }
        assert (
            av.read(artifacts["before"])
            == av.read(artifacts["after_fault"])
            == av.read(artifacts["after_recovery"])
        )
        assert av.read(artifacts["stale_before"])["refused"] is True
        assert av.read(artifacts["stale_after"])["refused"] is True
    else:
        assert result["error_type"] != "CounterfactualRejection"
        assert result.get("facts", {}).get("recovery_verified") is not True
        assert len(calls) == (1 if boundary == "changed-source" else 2)


def test_shared_reference_inventory_includes_subjects_and_rejects_changed_bytes(
    tmp_path, declared
):
    from talkcut.provider_failure_checks import _closure, _snapshot

    deps, refs, _ = declared
    envelope = av.read(refs["transcript_only"])
    values = _closure(refs["transcript_only"])
    paths = {value["path"] for value in values}
    subjects = envelope["subjects"]
    assert {
        ref["path"]
        for ref in [
            subjects["output"],
            subjects["timeline"],
            subjects["contract"],
            *subjects["sources"].values(),
        ]
    } <= paths
    before = _snapshot(values, REPO)
    assert before["code_tree_hash"] == deps["code_tree_hash"] and len(
        before["files"]
    ) == len(values)
    Path(subjects["output"]["path"]).write_text("changed")
    with pytest.raises(TalkCutError, match="bytes changed"):
        _snapshot(values, REPO)


def test_fake_positive_facts_without_bound_recovery_artifacts_reject(
    tmp_path, declared
):
    _, refs, _ = declared
    response = {
        "facts": {
            "positive_verified": True,
            "counterfactual": True,
            "recovery_verified": True,
            "original_provider_bytes_unchanged": True,
            "execution_artifacts": {},
        }
    }
    with pytest.raises(TalkCutError, match="artifact denominator"):
        av.stable_response(response, refs["transcript_only"], REPO)


@pytest.mark.parametrize("case", sorted(av.SCOPES))
def test_actual_probe_cli_rejects_duplicate_json_input(tmp_path, declared, case):
    import os
    import subprocess
    import sys

    deps, refs, _ = declared
    value = av.inputs(case, refs[case], deps, attack=True)
    encoded = json.dumps(value)
    path = tmp_path / "duplicate-probe.json"
    path.write_text(encoded[:-1] + ',"fault":' + json.dumps(value["fault"]) + "}")
    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "talkcut.evaluator_negative",
            "probe",
            "--repo",
            str(REPO),
            "--case",
            case,
            "--input",
            str(path),
        ],
        cwd=REPO,
        env={**os.environ, "PYTHONPATH": str(REPO / "src")},
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert completed.returncode != 0 and "duplicate keys" in completed.stderr
    assert not list(tmp_path.rglob("counterfactual.json"))


def test_retained_positive_normalization_only_allows_actual_copy_paths_and_time(
    tmp_path, declared
):
    """Exercise retained-file binding only; these authored imports have no real provider proof."""
    _, refs, _ = declared
    original_rows = {
        key: save(
            tmp_path,
            "unit-original-" + key + ".json",
            {"unit_test_only": True, "kind": key},
        )
        for key in ("record", "request", "capability")
    }
    original = save(
        tmp_path,
        "unit-original-import.json",
        {
            "schema_version": "review-import/v1",
            "status": "PASS",
            "owner_acceptance": "pending",
            "artifact_refs": original_rows,
        },
    )
    envelope = av.read(refs["transcript_only"])
    envelope["review_import"] = original
    positive = save(tmp_path, "unit-normalization-envelope.json", envelope)
    records = []
    for number in (0, 1):
        copied_rows = {
            key: save(tmp_path, f"unit-copy-{number}-{key}.json", av.read(ref))
            for key, ref in original_rows.items()
        }
        imported = save(
            tmp_path,
            f"unit-retained-{number}.json",
            {
                "schema_version": "review-import/v1",
                "status": "PASS",
                "coverage": [["0", "1"]],
                "owner_acceptance": "pending",
                "artifact_refs": copied_rows,
                "imported_at": f"2026-09-08T00:00:0{number}+00:00",
            },
        )
        proof = unit_proof()
        proof["capability"] = {}
        proof["import"] = {"artifact_ref": imported}
        records.append(
            av._preserve_positive(
                proof, envelope, positive, tmp_path / f"unit-proof-{number}.json"
            )
        )
    assert records[0]["sha256"] != records[1]["sha256"]
    assert av._normalized_positive(records[0], envelope) == av._normalized_positive(
        records[1], envelope
    )
    altered = av.read(records[1])
    altered["observed"]["response"]["verdict"] = "FAIL"
    changed = save(tmp_path, "unit-changed-observation.json", altered)
    assert av._normalized_positive(records[0], envelope) != av._normalized_positive(
        changed, envelope
    )
    altered["review_imports"] = []
    with pytest.raises(TalkCutError, match="denominator"):
        av._normalized_positive(
            save(tmp_path, "unit-missing-import.json", altered), envelope
        )
    Path(original_rows["record"]["path"]).write_text("changed provider input")
    with pytest.raises(TalkCutError, match="changed"):
        av._normalized_positive(records[0], envelope)


@pytest.mark.parametrize("case", sorted(CHECK_REQUIREMENTS["evaluator_negative"]))
def test_current_comparison_preserves_av_text_and_legacy_ffmpeg_scope(case):
    """Execute only the actual final comparison after retained-file validation.

    This tests comparison semantics; it supplies no provider-positive evidence.
    """
    import ast
    import inspect

    from talkcut import evaluator_negative as negative

    syntax = ast.parse(inspect.getsource(negative.verify_evaluator_negatives))
    selected = None
    for loop in ast.walk(syntax):
        if not isinstance(loop, ast.For):
            continue
        for end, statement in enumerate(loop.body):
            if not (
                isinstance(statement, ast.Expr)
                and isinstance(statement.value, ast.Call)
                and isinstance(statement.value.func, ast.Name)
                and statement.value.func.id == "_require"
                and len(statement.value.args) == 2
                and isinstance(statement.value.args[1], ast.Constant)
                and statement.value.args[1].value
                == "Preserved probe output differs from direct replay"
            ):
                continue
            for start, previous in enumerate(loop.body[:end]):
                if isinstance(previous, ast.Assign) and any(
                    isinstance(target, ast.Name) and target.id == "stable_observed"
                    for target in previous.targets
                ):
                    selected = ast.Module(
                        body=copy.deepcopy(loop.body[start : end + 1]), type_ignores=[]
                    )
                    break
    assert selected is not None
    scope = {
        **vars(negative),
        "case_id": case,
        "process": {"exit_code": 1},
        "actual_code": 1,
        "observed_for_comparison": {"observation": "Observed label @ 0x111"},
        "actual_for_comparison": {"observation": "Observed label @ 0x222"},
    }
    code = compile(selected, "actual-scoped-comparison", "exec")
    if case in av.SCOPES:
        with pytest.raises(TalkCutError, match="Preserved probe output differs"):
            exec(code, scope)  # noqa: S102 - inspected current production AST, no supplied code
    else:
        exec(code, scope)  # noqa: S102 - inspected current production AST, no supplied code
