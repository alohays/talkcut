"""Synthetic integration controls, never real AV/capability or editorial approval.

Actual FFmpeg source inspection, immutable plan decisions, timeline compilation,
artifact hashes, CLI subprocess failure capture and index updates are exercised.
Only explicitly named original-provider gates are patched in positive units.
Their test_only receipts cannot pass the unpatched provider path.
"""

import copy
import os
import subprocess
import sys
from fractions import Fraction
from pathlib import Path

import pytest

from talkcut import analysis as analysis_module
from talkcut import editorial_binding as binding
from talkcut import editorial_execution as execution_module
from talkcut import review as review_module
from talkcut.acceptance import Evaluator, EvidenceError
from talkcut.contracts import code_identity, freeze_contract
from talkcut.media import inspect_source
from talkcut.plan import build_plan, compile_plan, decide, persist_plan
from talkcut.project import (
    TalkCutError,
    artifact_ref,
    atomic_json,
    content_hash,
    init_project,
    load_project,
    read_json,
    save_revision,
    store_artifact,
    verified_json,
)

REASON = "Authored isolated synthetic observation; this is not provider evidence."


@pytest.fixture(scope="module")
def inspected(tmp_path_factory):
    directory = tmp_path_factory.mktemp("editorial-synthetic-source")
    source = directory / "synthetic.mp4"
    subprocess.run(
        [
            "ffmpeg",
            "-v",
            "error",
            "-nostdin",
            "-n",
            "-f",
            "lavfi",
            "-i",
            "testsrc2=s=160x96:r=10:duration=6",
            "-f",
            "lavfi",
            "-i",
            "anullsrc=r=48000:cl=mono:d=6",
            "-c:v",
            "libx264",
            "-preset",
            "ultrafast",
            "-c:a",
            "aac",
            str(source),
        ],
        check=True,
        capture_output=True,
        timeout=30,
    )
    return source, inspect_source(source, directory / "inspection")


@pytest.fixture
def scenario(tmp_path, inspected, monkeypatch):
    source, inspection = inspected
    directory = tmp_path / "project"
    init_project(directory, source, source)
    project = load_project(directory)
    inspection_ref = store_artifact(directory, "unit-inspection", inspection)
    project["inspections"] = {role: inspection_ref for role in ("screen", "speaker")}
    save_revision(directory, project, project["revision"], "unit_inspection", {})
    freeze_contract(Path.cwd(), directory / "frozen-contract.local.json")
    build_plan(directory, diagnostic=True)
    candidates = [
        {
            "id": "synthetic-candidate-1",
            "start": "2",
            "end": "3",
            "kind": "silence",
            "policy_action": "auto_apply",
            "reason": REASON,
            "proposer_run_id": "synthetic-proposal",
            "test_only": False,
            "evidence_refs": [inspection_ref],
        }
    ]
    proposal_request = store_artifact(directory, "unit-provider", {"test_only": True})
    proposal_receipt = store_artifact(
        directory,
        "unit-provider",
        {
            "run_id": "synthetic-proposal",
            "test_only": True,
            "request": proposal_request,
            "response": proposal_request,
        },
    )
    report = {
        "schema_version": "source-analysis/v1",
        "source_kind": "real",
        "test_only": False,
        "status": "ANALYZED",
        "domain": ["0", "6"],
        "proposer_run_id": "synthetic-proposal",
        "prompt_sha256": "a" * 64,
        "segments": [{"start": "0", "end": "6", "action": "keep", "reason": REASON}],
        "candidates": candidates,
        "protected_intervals": [],
        "context": {"receipt": proposal_receipt},
        "owner_acceptance": "pending",
    }
    report["source_hashes"] = {k: v["sha256"] for k, v in project["sources"].items()}
    calls, proofs = [], {}

    def original_provider_gate(ref, plan):
        calls.append(("original_analysis_replayed", ref))
        result = verified_json(ref)
        if result.get("unit_original_rejected"):
            raise TalkCutError(
                "UNIT_PROVIDER_REJECTED", "Original source provider proof rejected"
            )
        return result

    def review_provider_gate(ref):
        return copy.deepcopy(proofs[ref["sha256"]])

    monkeypatch.setattr(binding, "verify_analysis_report", original_provider_gate)
    monkeypatch.setattr(
        analysis_module, "verify_analysis_report", original_provider_gate
    )
    monkeypatch.setattr(binding, "verify_imported_review", review_provider_gate)
    monkeypatch.setattr(review_module, "verify_imported_review", review_provider_gate)
    monkeypatch.setattr(binding, "_receipt", lambda ref: verified_json(ref))
    monkeypatch.setattr(review_module, "_receipt", lambda ref: verified_json(ref))

    def install(report_value=None, *, accepted=True):
        nonlocal report
        if report_value is not None:
            report = copy.deepcopy(report_value)
        project = load_project(directory)
        ref = store_artifact(directory, "unit-original-analysis", report)
        project["analysis"] = ref
        plan = verified_json(project["active_plan"])
        plan.update(
            analysis_ref=ref,
            protected_intervals=report["protected_intervals"],
            test_only=False,
            contract_hash=artifact_ref(directory / "frozen-contract.local.json")[
                "sha256"
            ],
        )
        plan["timing"]["status"] = "PASS"
        plan["candidates"] = [
            {**row, "decision": "proposed"} for row in report["candidates"]
        ]
        persist_plan(directory, project, plan, "unit_proposal_setup")
        if accepted:
            for row in report["candidates"]:
                before = load_project(directory)
                historical = None
                if row["policy_action"] != "auto_apply":
                    historical = review(
                        row["id"], plan_override=verified_json(before["active_plan"])
                    )
                decide(directory, row["id"], "accept", before["revision"], historical)
        project = load_project(directory)
        plan = verified_json(project["active_plan"])
        assert compile_plan(project, plan) == verified_json(project["active_timeline"])
        # Explicit authored render envelope, not a real master approval. Tests of
        # real rendering and final technical gates live in existing workflow tests.
        render = {
            "status": "RENDERED",
            "profile": "master",
            "test_only": False,
            "output": artifact_ref(source),
            "settings": {
                "plan": project["active_plan"],
                "timeline": project["active_timeline"],
            },
        }
        project["active_render"] = store_artifact(directory, "unit-render", render)
        save_revision(
            directory, project, project["revision"], "unit_render_envelope", {}
        )
        return report

    def review(
        candidate_id="synthetic-candidate-1",
        *,
        scope="deletion",
        change=None,
        plan_override=None,
    ):
        project = load_project(directory)
        plan = plan_override or verified_json(project["active_plan"])
        deps = {
            "source_hashes": plan["source_hashes"],
            "contract_hash": plan["contract_hash"],
            "code_tree_hash": code_identity(Path.cwd())["code_tree_hash"],
            "plan_hash": content_hash(plan),
            "timeline_hash": project["active_timeline"]["sha256"],
            "output_hash": artifact_ref(source)["sha256"],
        }
        candidate = next(
            (row for row in plan["candidates"] if row["id"] == candidate_id), None
        )
        request = {
            "scope": scope,
            "dependencies": deps,
            "intervals": [["0", "6"]],
            "inputs": [{"parent_sha256": plan["source_hashes"]["screen"]}],
            "details": {},
        }
        if scope == "deletion":
            request["details"] = {
                "candidate_id": candidate_id,
                "requested_interval": [candidate["start"], candidate["end"]],
                "source_domain": ["0", "6"],
            }
        response = {
            "observed_intervals": [["0", "6"]],
            "candidate_id": candidate_id,
            "candidate_decision": "approve_deletion",
            "complete_sentence_context": True,
        }
        record = {
            "reviewer_role": "adversarial_reviewer",
            "proposer_run_id": "synthetic-proposal",
            "proposer_prompt_sha256": "a" * 64,
            "prompt_sha256": "b" * 64,
        }
        execution = {
            "run_id": "synthetic-review-" + str(len(proofs)),
            "prompt_sha256": "b" * 64,
            "test_only": True,
        }
        proof = {
            "record": record,
            "request": request,
            "response": response,
            "receipt": execution,
            "import": {"artifact_ref": {"synthetic_unit_gate": True}},
        }
        if change:
            change(proof)
        execution.update(
            request=store_artifact(directory, "unit-review-request", request),
            response=store_artifact(directory, "unit-review-response", response),
        )
        receipt_ref = store_artifact(directory, "unit-provider", execution)
        record["receipt"] = receipt_ref
        ref = store_artifact(
            directory,
            "unit-import",
            {
                "test_only": True,
                "artifact_refs": {
                    "record": store_artifact(directory, "unit-review-record", record),
                    "capability": store_artifact(
                        directory, "unit-capability", {"test_only": True}
                    ),
                },
            },
        )
        proofs[ref["sha256"]] = proof
        return ref

    def prepared():
        return binding.prepare_editorial(directory, Path.cwd())["snapshot"]

    def verify(refs=None, audit=None):
        return binding.verify_editorial_inputs(
            directory, prepared(), refs or [], audit, Path.cwd()
        )

    install()
    return {
        "directory": directory,
        "report": report,
        "calls": calls,
        "proofs": proofs,
        "install": install,
        "review": review,
        "prepared": prepared,
        "verify": verify,
    }


def test_actual_plan_decision_replaces_legacy_analysis_mutation(scenario):
    p = load_project(scenario["directory"])
    original = Path(p["analysis"]["path"]).read_bytes()
    original_plan = Path(p["active_plan"]["path"]).read_bytes()
    candidate = verified_json(p["active_plan"])["candidates"][0]
    assert candidate["decision"] == "accepted"
    assert candidate["decision_evidence"]["actor"] == "delegated_policy"
    assert "decision" not in verified_json(p["analysis"])["candidates"][0]
    result = scenario["verify"]([scenario["review"]()])
    assert result["edit_disposition"] == "EDITED"
    assert result["actual_deletions"] == [["2", "3"]]
    assert result["owner_acceptance"] == "pending"
    assert len(scenario["calls"]) >= 3
    assert Path(p["analysis"]["path"]).read_bytes() == original
    assert Path(p["active_plan"]["path"]).read_bytes() == original_plan


def test_automatic_cut_still_requires_current_separate_av(scenario):
    with pytest.raises(TalkCutError, match="Every actual cut"):
        scenario["verify"]()


def test_original_analysis_is_replayed_even_when_no_cuts(scenario):
    report = {**scenario["report"], "unit_original_rejected": True}
    scenario["install"](report, accepted=False)
    with pytest.raises(TalkCutError, match="Original source provider"):
        scenario["verify"]()


@pytest.mark.parametrize(
    "part",
    [
        "source_hashes",
        "contract_hash",
        "code_tree_hash",
        "plan_hash",
        "timeline_hash",
        "output_hash",
    ],
)
def test_review_current_dependencies_are_all_required(scenario, part):
    ref = scenario["review"](change=lambda p: p["request"]["dependencies"].pop(part))
    with pytest.raises(TalkCutError, match="stale"):
        scenario["verify"]([ref])


@pytest.mark.parametrize(
    "change",
    [
        lambda p: p["request"]["details"].update(candidate_id="wrong"),
        lambda p: p["request"]["details"].update(requested_interval=["2", "4"]),
        lambda p: p["request"].update(intervals=[["2", "3"]]),
        lambda p: p["request"]["details"].update(source_domain=["0", "7"]),
        lambda p: p["request"]["inputs"][0].update(parent_sha256="x" * 64),
        lambda p: p["response"].update(candidate_id="wrong"),
        lambda p: p["response"].update(candidate_decision="keep"),
        lambda p: p["response"].update(complete_sentence_context="true"),
        lambda p: p["response"].update(observed_intervals=[["0", "2"]]),
        lambda p: p["receipt"].update(run_id="synthetic-proposal"),
    ],
)
def test_existing_candidate_authority_is_used_for_final_auto_review(scenario, change):
    ref = scenario["review"](change=change)
    with pytest.raises(TalkCutError):
        scenario["verify"]([ref])


def test_historical_nonautomatic_review_cannot_replace_final_review(scenario):
    report = copy.deepcopy(scenario["report"])
    report["candidates"][0].update(policy_action="requires_review", kind="disfluency")
    scenario["install"](report)
    p = load_project(scenario["directory"])
    candidate = verified_json(p["active_plan"])["candidates"][0]
    assert candidate["decision_evidence"]["actor"] == "delegated_ai_reviewer"
    with pytest.raises(TalkCutError, match="stale"):
        scenario["verify"]([candidate["decision_evidence"]["review"]])
    result = scenario["verify"]([scenario["review"]()])
    assert result["applied_candidate_ids"] == [candidate["id"]]


def test_all_overlapping_cut_ids_need_individual_review(scenario):
    report = copy.deepcopy(scenario["report"])
    report["candidates"].append(
        {**report["candidates"][0], "id": "second", "start": "5/2", "end": "4"}
    )
    scenario["install"](report)
    one = scenario["review"]()
    with pytest.raises(TalkCutError, match="Every actual cut"):
        scenario["verify"]([one])
    verified = scenario["verify"]([one, scenario["review"]("second")])
    assert verified["actual_deletions"] == [["2", "4"]]
    assert len(verified["applied_candidate_ids"]) == 2


def test_duplicate_review_is_rejected(scenario):
    ref = scenario["review"]()
    with pytest.raises(TalkCutError, match="Duplicate"):
        scenario["verify"]([ref, ref])


@pytest.mark.parametrize(
    "change",
    [
        lambda p: p["candidates"][0].update(reason="changed"),
        lambda p: p["candidates"][0].update(start="1"),
        lambda p: p["candidates"].append({**p["candidates"][0], "id": "invented"}),
        lambda p: p["candidates"].clear(),
        lambda p: p["candidates"][0].update(decision="apply"),
        lambda p: p["candidates"][0]["decision_evidence"].update(
            actor="workflow_executor"
        ),
    ],
)
def test_original_candidates_and_actual_actor_cannot_be_rewritten(scenario, change):
    directory = scenario["directory"]
    project = load_project(directory)
    plan = verified_json(project["active_plan"])
    change(plan)
    # Preserve original bytes and recompute real timeline so candidate validation
    # cannot hide behind a stale file hash or a stale compiled timeline.
    persist_plan(directory, project, plan, "unit_negative_plan")
    project = load_project(directory)
    render = {
        "status": "RENDERED",
        "profile": "master",
        "test_only": False,
        "output": project["sources"]["screen"],
        "settings": {
            "plan": project["active_plan"],
            "timeline": project["active_timeline"],
        },
    }
    project["active_render"] = store_artifact(directory, "unit-render", render)
    save_revision(directory, project, project["revision"], "unit_negative_render", {})
    with pytest.raises(TalkCutError):
        scenario["prepared"]()


def test_keep_all_is_not_a_no_safe_cuts_exception(scenario):
    scenario["install"](accepted=False)
    with pytest.raises(TalkCutError, match="No-safe-cuts"):
        scenario["verify"]()


def no_safe_audit(scenario, monkeypatch, **changes):
    response = {
        "analysis_available": True,
        "all_candidates_reviewed": True,
        "no_safe_cuts_reason": REASON,
        "candidate_decisions": [
            {
                "candidate_id": row["id"],
                "requested_interval": [row["start"], row["end"]],
                "decision": "keep",
                "reason": REASON,
            }
            for row in scenario["report"]["candidates"]
        ],
    }
    response.update(changes)
    calls = []
    request_ref = store_artifact(
        scenario["directory"], "unit-audit-request", {"test_only": True}
    )
    response_ref = store_artifact(
        scenario["directory"], "unit-audit-response", response
    )
    execution = {
        "run_id": "synthetic-independent-audit",
        "test_only": True,
        "request": request_ref,
        "response": response_ref,
    }
    receipt_ref = store_artifact(scenario["directory"], "unit-provider", execution)

    def gate(ref, **kwargs):
        calls.append(kwargs)
        return {
            "response": response,
            "receipt": execution,
            "envelope": {"receipt": receipt_ref},
        }

    monkeypatch.setattr(binding, "verify_artifact_audit", gate)
    return store_artifact(
        scenario["directory"], "unit-audit", {"test_only": True, "response": response}
    ), calls


def test_no_safe_cuts_requires_full_av_and_separate_all_candidate_audit(
    scenario, monkeypatch
):
    scenario["install"](accepted=False)
    source_review = scenario["review"](scope="analysis")
    audit, calls = no_safe_audit(scenario, monkeypatch)
    result = scenario["verify"]([source_review], audit)
    assert result["edit_disposition"] == "NO_SAFE_CUTS_VERIFIED"
    assert result["actual_deletions"] == []
    assert calls[0]["scope"] == "no_safe_cuts"
    assert "synthetic-proposal" in calls[0]["excluded_run_ids"]
    assert "synthetic-review-0" in calls[0]["excluded_run_ids"]
    assert len(calls[0]["input_refs"]) == 5


@pytest.mark.parametrize(
    "changes",
    [
        {"candidate_decisions": []},
        {"all_candidates_reviewed": 1},
        {"analysis_available": False},
        {"no_safe_cuts_reason": "PASS"},
    ],
)
def test_authored_keep_all_claim_cannot_fill_missing_candidate_evidence(
    scenario, monkeypatch, changes
):
    scenario["install"](accepted=False)
    audit, _ = no_safe_audit(scenario, monkeypatch, **changes)
    with pytest.raises(TalkCutError):
        scenario["verify"]([scenario["review"](scope="analysis")], audit)


def test_no_safe_av_cannot_omit_source(scenario, monkeypatch):
    scenario["install"](accepted=False)
    audit, _ = no_safe_audit(scenario, monkeypatch)
    ref = scenario["review"](
        scope="analysis",
        change=lambda p: p["response"].update(observed_intervals=[["1", "6"]]),
    )
    with pytest.raises(TalkCutError, match="omits"):
        scenario["verify"]([ref], audit)


def test_below_frame_resolution_is_not_edited(scenario):
    report = copy.deepcopy(scenario["report"])
    report["candidates"][0].update(start="201/100", end="202/100")
    scenario["install"](report)
    state = binding.current_state(scenario["directory"], Path.cwd())
    assert state["timeline"]["cuts"][0]["status"] == "kept_below_frame_resolution"
    assert state["applied"] == []
    with pytest.raises(TalkCutError, match="No-safe-cuts"):
        scenario["verify"]()


def test_acceptance_reads_binding_not_original_analysis_decision_fields(
    scenario, monkeypatch
):
    verification = scenario["verify"]([scenario["review"]()])
    directory = scenario["directory"]
    evaluator = Evaluator(
        directory, "synthetic", directory / "frozen-contract.local.json", Path.cwd()
    )
    evaluator.index = {
        "analysis": verification["analysis"],
        "timeline": verification["timeline"],
        "editorial": store_artifact(
            directory, "unit-binding", {"receipt": {"test_only": True}}
        ),
        "edit_disposition": "EDITED",
    }
    evaluator.deps = verification["dependencies"]
    evaluator.render = {"output": verification["output"]}
    evaluator.deletions = [(Fraction(2), Fraction(3))]
    evaluator.valid_reviews = [{"ref": ref} for ref in verification["review_records"]]
    monkeypatch.setattr(binding, "verify_editorial_binding", lambda *args: verification)
    monkeypatch.setattr(
        evaluator, "receipt", lambda *args: {"synthetic_unit_gate": True}
    )
    assert evaluator.analysis_check()["disposition"] == "EDITED"
    evaluator.valid_reviews = []
    with pytest.raises(EvidenceError, match="missing"):
        evaluator.analysis_check()


def test_actual_analyze_indexes_original_and_preserves_prior_binding(
    inspected, tmp_path
):
    source, _ = inspected
    directory = tmp_path / "cli-project"

    def cli(*args):
        completed = subprocess.run(
            [sys.executable, "-m", "talkcut", *map(str, args), "--json"],
            cwd=Path.cwd(),
            capture_output=True,
            timeout=60,
            check=False,
        )
        prefix = (
            tmp_path / f"command-{len(list(tmp_path.glob('command-*.stdout.json')))}"
        )
        prefix.with_suffix(".stdout.json").write_bytes(completed.stdout)
        prefix.with_suffix(".stderr.log").write_bytes(completed.stderr)
        return read_json(prefix.with_suffix(".stdout.json")), completed.returncode

    assert cli("init", directory, "--screen", source, "--speaker", source)[1] == 0
    assert cli("inspect", directory, "--full-decode")[1] == 0
    old = {
        "schema_version": "acceptance-index/v1",
        "owner_acceptance": "pending",
        "editorial": {"path": "old", "sha256": "1" * 64},
        "edit_disposition": "EDITED",
    }
    atomic_json(directory / "acceptance.local.json", old)
    old_bytes = (directory / "acceptance.local.json").read_bytes()
    result, code = cli("analyze", directory)
    assert code == 1 and result["status"] == "ANALYSIS_UNAVAILABLE"
    index = read_json(directory / "acceptance.local.json")
    assert (
        index["analysis"]
        == load_project(directory)["analysis"]
        == result["artifact_ref"]
    )
    assert "editorial" not in index and "edit_disposition" not in index
    assert any(
        path.read_bytes() == old_bytes
        for path in (directory / "evidence" / "index-history").glob("*.json")
    )
    assert not any(
        "decision" in c for c in verified_json(index["analysis"])["candidates"]
    )
    snapshot = store_artifact(directory, "unit-negative-snapshot", {"test_only": True})
    result, code = cli("editorial", "bind", directory, "--snapshot", snapshot["path"])
    assert code != 0 and result["acceptance_status"] == "UNVERIFIED"
    execution = verified_json(result["execution"])
    assert execution["exit_code"] != 0 and "editorial-worker" in execution["command"]
    assert Path(execution["stdout"]["path"]).is_file()
    assert "editorial" not in read_json(directory / "acceptance.local.json")


def test_source_review_cannot_claim_speaker_or_outside_intervals(scenario, monkeypatch):
    scenario["install"](accepted=False)
    audit, _ = no_safe_audit(scenario, monkeypatch)
    for change in (
        lambda proof: proof["request"]["inputs"][0].update(parent_sha256="f" * 64),
        lambda proof: proof["response"].update(observed_intervals=[["0", "7"]]),
    ):
        with pytest.raises(TalkCutError):
            scenario["verify"](
                [scenario["review"](scope="analysis", change=change)], audit
            )


def test_no_safe_auditor_cannot_reuse_proposal_component(scenario, monkeypatch):
    scenario["install"](accepted=False)
    audit, _ = no_safe_audit(scenario, monkeypatch)
    original = binding._execution_evidence

    def ids(ref, execution):
        runs, refs = original(ref, execution)
        if execution["run_id"] == "synthetic-independent-audit":
            runs.add("synthetic-proposal")
        return runs, refs

    monkeypatch.setattr(binding, "_execution_evidence", ids)
    with pytest.raises(TalkCutError, match="component"):
        scenario["verify"]([scenario["review"](scope="analysis")], audit)


def synthetic_supervised_binding(scenario, tmp_path, monkeypatch):
    """Execute the actual CLI worker with external, explicit synthetic provider gates.

    No production test hook is installed. Gate source and all inputs are retained
    beside the actual process log. Registration is an isolated unit stub because
    synthetic capabilities must fail the actual registration authority.
    """
    review_ref = scenario["review"]()
    snapshot = scenario["prepared"]()
    project = scenario["directory"]
    verification = scenario["verify"]([review_ref])
    gate_data = tmp_path / "synthetic-provider-gates.json"
    atomic_json(
        gate_data,
        {
            "scope": "Synthetic provider gates, not real AV approval",
            "proofs": scenario["proofs"],
        },
    )
    bootstrap = tmp_path / "synthetic-worker-bootstrap"
    bootstrap.mkdir()
    (bootstrap / "sitecustomize.py").write_text(
        "# Explicit isolated synthetic provider gates; never real AV evidence.\n"
        "import json, os\n"
        "from talkcut import analysis, editorial_binding, review\n"
        "from talkcut.project import verified_json\n"
        "proofs=json.load(open(os.environ['TALKCUT_SYNTHETIC_UNIT_GATES']))['proofs']\n"
        "def original(ref, plan): return verified_json(ref)\n"
        "def proof(ref): return proofs[ref['sha256']]\n"
        "analysis.verify_analysis_report=editorial_binding.verify_analysis_report=original\n"
        "review.verify_imported_review=editorial_binding.verify_imported_review=proof\n"
        "review._receipt=editorial_binding._receipt=verified_json\n"
    )
    monkeypatch.setenv("TALKCUT_SYNTHETIC_UNIT_GATES", str(gate_data))
    monkeypatch.setenv(
        "PYTHONPATH", str(bootstrap) + os.pathsep + str(Path.cwd() / "src")
    )
    index = {
        "schema_version": "acceptance-index/v1",
        "owner_acceptance": "pending",
        "timeline": verification["timeline"],
        "analysis": verification["analysis"],
        "render": store_artifact(
            project,
            "unit-index-render",
            {
                "output": verification["output"],
                "dependencies": verification["dependencies"],
            },
        ),
        "reviews": [],
        "capabilities": [],
    }
    atomic_json(project / "acceptance.local.json", index)
    calls = []

    def synthetic_registration(project_dir, ref, repo_root):
        calls.append(ref)
        imported = verified_json(ref)
        current = read_json(project_dir / "acceptance.local.json")
        current["reviews"].append(imported["artifact_refs"]["record"])
        current["capabilities"].append(imported["artifact_refs"]["capability"])
        atomic_json(project_dir / "acceptance.local.json", current)
        return {"synthetic_unit_gate": True}

    monkeypatch.setattr(
        execution_module, "register_review_import", synthetic_registration
    )
    result, code = execution_module.run_editorial(
        project, snapshot, [review_ref], None, Path.cwd()
    )
    assert code == 0, result
    assert calls == [review_ref]
    atomic_json(
        tmp_path / "synthetic-scope.local.json",
        {
            "scope": "Actual worker command; isolated original provider and registration gates. No real AV acceptance.",
            "gate_source": artifact_ref(bootstrap / "sitecustomize.py"),
            "gate_inputs": artifact_ref(gate_data),
            "result": result,
        },
    )
    return result


def test_actual_supervisor_stdout_receipt_and_index_under_explicit_synthetic_gates(
    scenario, tmp_path, monkeypatch
):
    result = synthetic_supervised_binding(scenario, tmp_path, monkeypatch)
    directory = scenario["directory"]
    assert result["status"] == "INDEXED" and result["acceptance_status"] == "UNVERIFIED"
    index = read_json(directory / "acceptance.local.json")
    assert index["editorial"] == result["editorial"]
    record = verified_json(index["editorial"])
    receipt = verified_json(record["receipt"])
    actual = verified_json(record["verification"])
    assert receipt["operation"] == "editorial_binding"
    assert record["verification"] == receipt["stdout"] == receipt["result"]
    assert "provider_request_id" not in receipt and "model_revision" not in receipt
    assert verified_json(receipt["log"])["exit_code"] == 0
    assert (
        binding.verify_editorial_binding(index["editorial"], directory, Path.cwd())
        == actual
    )
    assert "decision" not in verified_json(index["analysis"])["candidates"][0]
    # Removing the isolated provider gates leaves this synthetic case UNVERIFIED.
    monkeypatch.undo()
    with pytest.raises((TalkCutError, KeyError, ValueError)):
        binding.verify_editorial_binding(index["editorial"], directory, Path.cwd())


@pytest.mark.parametrize(
    "change",
    [
        "receipt_exit_bool",
        "failed",
        "wrong_command",
        "changed_code",
        "provider_impersonation",
        "reversed_clock",
        "replaced_stdout",
    ],
)
def test_supervisor_receipt_cannot_be_relabelled(
    scenario, tmp_path, monkeypatch, change
):
    result = synthetic_supervised_binding(scenario, tmp_path, monkeypatch)
    record = verified_json(result["editorial"])
    verified = verified_json(record["verification"])
    receipt = verified_json(record["receipt"])
    process = verified_json(receipt["log"])
    if change == "receipt_exit_bool":
        receipt["exit_code"] = False
    elif change == "failed":
        process["exit_code"] = 1
    elif change == "wrong_command":
        receipt["command"][5] = "foreign-snapshot.json"
    elif change == "changed_code":
        process["after"]["code_tree_hash"] = "f" * 64
    elif change == "provider_impersonation":
        receipt["provider_request_id"] = "authored"
    elif change == "reversed_clock":
        receipt["started_at"] = process["started_at"] = "2100-01-01T00:00:00+00:00"
    else:
        receipt["stdout"] = store_artifact(
            scenario["directory"], "unit-replacement", {"status": "PASS"}
        )
        process["stdout"] = receipt["stdout"]
    receipt["log"] = store_artifact(
        scenario["directory"], "unit-mutated-process", process
    )
    record["receipt"] = store_artifact(
        scenario["directory"], "unit-mutated-receipt", receipt
    )
    with pytest.raises(TalkCutError):
        execution_module.verify_editorial_execution(
            record, verified, scenario["directory"], Path.cwd()
        )


@pytest.mark.parametrize("edited", [True, False])
def test_complete_collection_contributors_reach_current_authorization(
    scenario, monkeypatch, edited
):
    report = copy.deepcopy(scenario["report"])
    ids = ["second-proposal", "synthetic-proposal"]
    prompts = ["a" * 64, "c" * 64]
    report.update(
        proposer_run_id=None,
        proposer_run_ids=ids,
        proposer_prompt_sha256s=prompts,
        context_verification={"children": [{"execution_ids": ["original-leaf", *ids]}]},
    )
    report["candidates"][0].update(
        proposer_run_id=None,
        proposer_run_ids=ids,
        proposer_prompt_sha256s=prompts,
        proposers=[{"execution_ids": ["original-leaf", *ids]}],
    )
    scenario["install"](report, accepted=edited)

    def record_contributors(proof):
        proof["record"].update(
            proposer_run_id=None, proposer_run_ids=ids, proposer_prompt_sha256s=prompts
        )

    ref = scenario["review"](
        scope="deletion" if edited else "analysis", change=record_contributors
    )
    audit = None
    if not edited:
        audit, calls = no_safe_audit(scenario, monkeypatch)
    result = scenario["verify"]([ref], audit)
    assert result["edit_disposition"] == (
        "EDITED" if edited else "NO_SAFE_CUTS_VERIFIED"
    )
    if not edited:
        assert {"original-leaf", *ids} <= calls[0]["excluded_run_ids"]

    def omitted(proof):
        proof["record"].update(
            proposer_run_id=None,
            proposer_run_ids=[ids[0]],
            proposer_prompt_sha256s=prompts,
        )

    with pytest.raises(TalkCutError):
        scenario["verify"](
            [
                scenario["review"](
                    scope="deletion" if edited else "analysis", change=omitted
                )
            ],
            audit,
        )


def test_current_binding_rejects_mutated_retained_mapping(scenario):
    directory = scenario["directory"]
    project = load_project(directory)
    timeline = verified_json(project["active_timeline"])
    timeline["retained"][0]["source_end"] = {"num": 1, "den": 1}
    project["active_timeline"] = store_artifact(
        directory, "unit-timeline-rewrite", timeline
    )
    render = verified_json(project["active_render"])
    render["settings"]["timeline"] = project["active_timeline"]
    project["active_render"] = store_artifact(directory, "unit-render-rewrite", render)
    save_revision(
        directory, project, project["revision"], "unit_rewritten_retained_mapping", {}
    )
    with pytest.raises(TalkCutError, match="timeline differs"):
        scenario["prepared"]()


def test_current_compilation_conserves_original_protected_intervals(scenario):
    from talkcut.timeline import TimelineError

    report = copy.deepcopy(scenario["report"])
    report["protected_intervals"] = [
        {"start": "2", "end": "3", "kind": "definition", "reason": REASON}
    ]
    with pytest.raises(TimelineError, match="protected"):
        scenario["install"](report)
