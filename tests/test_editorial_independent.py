"""Independent structural controls using explicit synthetic provider fixtures.

These tests provide no actual provider or audiovisual approval. The imported
fixture gates original provider validation; production editorial logic remains
under test. Rejection tests remove those gates where provider authority matters.
"""

import copy
from fractions import Fraction
from pathlib import Path

import pytest
import test_editorial_binding as author_fixtures

from talkcut import editorial_binding as binding
from talkcut.acceptance import Evaluator, EvidenceError
from talkcut.project import (
    TalkCutError,
    artifact_ref,
    atomic_json,
    load_project,
    read_json,
    save_revision,
    store_artifact,
    verified_json,
)

inspected = author_fixtures.inspected
scenario = author_fixtures.scenario
no_safe_audit = author_fixtures.no_safe_audit
synthetic_supervised_binding = author_fixtures.synthetic_supervised_binding

DEPENDENCIES = (
    "source_hashes", "code_tree_hash", "contract_hash", "plan_hash",
    "timeline_hash", "output_hash",
)


@pytest.mark.parametrize("key", DEPENDENCIES)
def test_stale_review_dependency_is_rejected_with_current_file_hash(scenario, key):
    def change(proof):
        proof["request"]["dependencies"][key] = (
            {"screen": "f" * 64, "speaker": "f" * 64}
            if key == "source_hashes" else "f" * 64
        )
    review = scenario["review"](change=change)
    with pytest.raises(TalkCutError, match="stale"):
        scenario["verify"]([review])


@pytest.mark.parametrize("key", DEPENDENCIES)
def test_snapshot_dependencies_cannot_be_rehashed_into_authority(scenario, key):
    original = scenario["prepared"]()
    snapshot = verified_json(original)
    snapshot["dependencies"][key] = None
    replacement = store_artifact(scenario["directory"], "independent-snapshot", snapshot)
    with pytest.raises(TalkCutError, match="snapshot is stale"):
        binding.verify_editorial_inputs(
            scenario["directory"], replacement, [scenario["review"]()], None, Path.cwd()
        )


@pytest.mark.parametrize("damage", ["missing", "extra", "duplicate", "effective", "requested"])
def test_hash_consistent_compiled_cut_rewrite_never_binds(scenario, damage):
    directory = scenario["directory"]
    project = load_project(directory)
    timeline = verified_json(project["active_timeline"])
    if damage == "missing":
        timeline["cuts"].clear()
    elif damage == "extra":
        timeline["cuts"].append({**timeline["cuts"][0], "id": "unproposed"})
    elif damage == "duplicate":
        timeline["cuts"].append(copy.deepcopy(timeline["cuts"][0]))
    elif damage == "effective":
        timeline["cuts"][0]["start"] = {"num": 1, "den": 1}
    else:
        timeline["cuts"][0]["requested_end"] = {"num": 4, "den": 1}
    project["active_timeline"] = store_artifact(directory, "independent-timeline", timeline)
    render = verified_json(project["active_render"])
    render["settings"]["timeline"] = project["active_timeline"]
    project["active_render"] = store_artifact(directory, "independent-render", render)
    save_revision(directory, project, project["revision"], "independent_rewrite", {})
    with pytest.raises(TalkCutError, match="timeline differs"):
        scenario["prepared"]()


@pytest.mark.parametrize("damage", ["source", "contract", "plan", "timeline", "output", "analysis"])
def test_current_artifact_changes_invalidate_prepared_snapshot(scenario, damage, tmp_path):
    directory = scenario["directory"]
    snapshot = scenario["prepared"]()
    review = scenario["review"]()
    project = load_project(directory)
    if damage == "source":
        changed = tmp_path / "independent-different-source.mp4"
        changed.write_bytes(Path(project["sources"]["screen"]["path"]).read_bytes() + b"different")
        project["sources"]["screen"] = artifact_ref(changed)
    elif damage == "contract":
        atomic_json(directory / "frozen-contract.local.json", {"forged": "PASS"})
    elif damage == "output":
        render = verified_json(project["active_render"])
        output = tmp_path / "independent-output.bin"
        output.write_bytes(b"a different output")
        render["output"] = artifact_ref(output)
        project["active_render"] = store_artifact(directory, "independent-output-render", render)
    else:
        key = "analysis" if damage == "analysis" else "active_" + damage
        value = verified_json(project[key])
        value["independent_changed"] = True
        project[key] = store_artifact(directory, "independent-" + damage, value)
    save_revision(directory, project, project["revision"], "independent_changed", {})
    with pytest.raises((TalkCutError, KeyError, ValueError)):
        binding.verify_editorial_inputs(directory, snapshot, [review], None, Path.cwd())


@pytest.mark.parametrize("damage", ["duplicate", "missing", "wrong_boundary", "accept", "short_reason"])
def test_no_safe_audit_exact_original_candidate_denominator(scenario, monkeypatch, damage):
    scenario["install"](accepted=False)
    rows = [{"candidate_id": "synthetic-candidate-1", "requested_interval": ["2", "3"],
             "decision": "keep", "reason": "This synthetic observation is sufficiently substantive."}]
    if damage == "duplicate":
        rows.append(copy.deepcopy(rows[0]))
    elif damage == "missing":
        rows = []
    elif damage == "wrong_boundary":
        rows[0]["requested_interval"] = ["2", "4"]
    elif damage == "accept":
        rows[0]["decision"] = "accept"
    else:
        rows[0]["reason"] = "PASS"
    audit, _ = no_safe_audit(scenario, monkeypatch, candidate_decisions=rows)
    with pytest.raises(TalkCutError):
        scenario["verify"]([scenario["review"](scope="analysis")], audit)


def test_single_proposer_prompt_spoof_cannot_hide_same_prompt_review(scenario):
    def spoof(proof):
        # Actual analysis prompt and actual review prompt are both 'a' * 64.
        # Only the review's claimed proposer prompt is replaced with another hash.
        proof["receipt"]["prompt_sha256"] = "a" * 64
        proof["record"]["prompt_sha256"] = "a" * 64
        proof["record"]["proposer_prompt_sha256"] = "f" * 64
    ref = scenario["review"](change=spoof)
    with pytest.raises(TalkCutError, match="prompt|proposal|instructions"):
        scenario["verify"]([ref])


@pytest.mark.parametrize("damage", ["executor", "cwd", "test_only", "schema", "dependencies"])
def test_rehashed_local_receipt_must_describe_actual_executor(scenario, tmp_path, monkeypatch, damage):
    outcome = synthetic_supervised_binding(scenario, tmp_path, monkeypatch)
    record = verified_json(outcome["editorial"])
    result = verified_json(record["verification"])
    receipt = verified_json(record["receipt"])
    process = verified_json(receipt["log"])
    if damage == "executor":
        receipt["executor"] = "/does/not/exist/editorial-authority"
        receipt["command"][0] = receipt["executor"]
        process["command"][0] = receipt["executor"]
    elif damage == "cwd":
        process["cwd"] = "/does/not/exist/project"
    elif damage == "test_only":
        receipt["test_only"] = True
    elif damage == "schema":
        process["schema_version"] = "provider-execution/v1"
    else:
        receipt["dependencies"]["plan_hash"] = "f" * 64
    directory = scenario["directory"]
    receipt["log"] = store_artifact(directory, "independent-process", process)
    record["receipt"] = store_artifact(directory, "independent-receipt", receipt)
    rebound = store_artifact(directory, "independent-binding", record)
    atomic_json(tmp_path / "independent-receipt-claim.local.json", {
        "original_binding": outcome["editorial"], "rebound_binding": rebound,
        "damage": damage, "original_result": result,
    })
    with pytest.raises(TalkCutError):
        binding.verify_editorial_binding(rebound, directory, Path.cwd())


@pytest.mark.parametrize("damage", ["cuts", "output", "disposition", "missing_reviews", "analysis"])
def test_acceptance_independently_rejects_conflicting_editorial_binding(scenario, monkeypatch, damage):
    verification = scenario["verify"]([scenario["review"]()])
    directory = scenario["directory"]
    evaluator = Evaluator(directory, "synthetic", directory / "frozen-contract.local.json", Path.cwd())
    evaluator.index = {
        "analysis": verification["analysis"], "timeline": verification["timeline"],
        "editorial": store_artifact(directory, "independent-evaluator-binding", {"receipt": {"test_only": True}}),
        "edit_disposition": "EDITED",
    }
    evaluator.deps = verification["dependencies"]
    evaluator.render = {"output": verification["output"]}
    evaluator.deletions = [(Fraction(2), Fraction(3))]
    evaluator.valid_reviews = [{"ref": ref} for ref in verification["review_records"]]
    monkeypatch.setattr(binding, "verify_editorial_binding", lambda *args: verification)
    monkeypatch.setattr(evaluator, "receipt", lambda *args: {"synthetic_unit_gate": True})
    if damage == "cuts":
        evaluator.deletions = []
    elif damage == "output":
        evaluator.render["output"] = {"path": "other", "sha256": "f" * 64}
    elif damage == "disposition":
        evaluator.index["edit_disposition"] = "NO_SAFE_CUTS_VERIFIED"
    elif damage == "missing_reviews":
        evaluator.valid_reviews = []
    else:
        evaluator.index["analysis"] = store_artifact(directory, "independent-other-analysis", {"status": "PASS"})
    with pytest.raises(EvidenceError):
        evaluator.analysis_check()


def test_local_success_receipt_cannot_promote_synthetic_providers(scenario, tmp_path, monkeypatch):
    outcome = synthetic_supervised_binding(scenario, tmp_path, monkeypatch)
    directory = scenario["directory"]
    before = read_json(directory / "acceptance.local.json")
    monkeypatch.undo()
    with pytest.raises((TalkCutError, KeyError, ValueError)):
        binding.verify_editorial_binding(outcome["editorial"], directory, Path.cwd())
    assert read_json(directory / "acceptance.local.json") == before
