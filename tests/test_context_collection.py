"""Authored AV policy/provenance units, never real provider/capability evidence.

Source and clips are actually FFmpeg-generated/reconstructed. Only the provider
and calibration gates are patched, and all fake receipts are test_only so these
artifacts cannot pass the unpatched production provider route.
"""

import subprocess
from pathlib import Path

import pytest

from talkcut.analysis import analyze_source
from talkcut.context_collection import (
    build_context_collection,
    verify_context_collection,
)
from talkcut.contracts import code_identity, freeze_contract
from talkcut.project import TalkCutError, artifact_ref, atomic_json, read_json
from talkcut.review import _clip, windows

PAUSE = {
    "no_speech": True,
    "no_learning_activity": True,
    "complete_context_checked": True,
}
PREP = {
    "before_first_substantive_content": True,
    "contains_introduction_or_instruction": False,
}


@pytest.fixture(scope="module")
def source(tmp_path_factory):
    path = tmp_path_factory.mktemp("context-collection-av") / "authored.mp4"
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
            "testsrc2=size=160x96:rate=30:duration=60",
            "-f",
            "lavfi",
            "-i",
            "sine=frequency=440:sample_rate=48000:duration=60",
            "-c:v",
            "libx264",
            "-preset",
            "ultrafast",
            "-c:a",
            "aac",
            str(path),
        ],
        check=True,
        capture_output=True,
        timeout=30,
    )
    return {**artifact_ref(path), "role": "screen"}


def segment(left, right, kind="lecture", positive=None):
    return {
        "start": str(left),
        "end": str(right),
        "kind": kind,
        "reason": "Authored synthetic unit observation, not a provider or ground-truth claim.",
        "positive_evidence": positive or {},
    }


@pytest.fixture
def scenario(tmp_path, source, monkeypatch):
    def receipt(ref):
        return read_json(ref["path"])

    def capability(value, **kwargs):
        if value.get("isolated_unit_gate") is not True:
            raise TalkCutError(
                "UNIT_CAPABILITY_REJECTED", "Unit capability gate rejected"
            )
        return {"model_revision": value["model_revision"]}

    monkeypatch.setattr("talkcut.review._receipt", receipt)
    monkeypatch.setattr("talkcut.review._capability", capability)
    contract = freeze_contract(Path.cwd(), tmp_path / "contract.json")
    contract = {k: v for k, v in contract.items() if k != "contract"}
    deps = {
        "source_hashes": {"screen": source["sha256"]},
        "code_tree_hash": code_identity(Path.cwd())["code_tree_hash"],
        "contract_hash": contract["sha256"],
        "output_hash": source["sha256"],
    }
    prompt = tmp_path / "prompt.txt"
    prompt.write_text(
        "Synthetic provider-gate unit only; no real audiovisual capability asserted."
    )
    cap_request = tmp_path / "cap-request.json"
    atomic_json(cap_request, {"dependencies": deps})
    cap_response = tmp_path / "cap-response.json"
    atomic_json(cap_response, {"unit_only": True})
    cap_execution = tmp_path / "cap-execution.json"
    atomic_json(
        cap_execution,
        {
            "schema_version": "execution-receipt/v1",
            "test_only": True,
            "completed": True,
            "exit_code": 0,
            "run_id": "unit-calibration",
            "model_revision": "unit-model",
            "provider_request_id": "unit-capability",
            "request": artifact_ref(cap_request),
            "response": artifact_ref(cap_response),
            "dependencies": deps,
        },
    )
    cap = tmp_path / "capability.json"
    atomic_json(
        cap,
        {
            "schema_version": "review-capability/v1",
            "receipt": artifact_ref(cap_execution),
            "model_revision": "unit-model",
            "isolated_unit_gate": True,
        },
    )
    children = []
    for index, interval in enumerate(windows(["0", "60"])):
        directory = tmp_path / f"child-{index}"
        directory.mkdir()
        clip = _clip(source, interval, directory / "media", deps)
        request = {
            "schema_version": "review-request/v1",
            "scope": "analysis",
            "source_sha256": source["sha256"],
            "input_clip_hashes": [clip["clip"]["sha256"]],
            "inputs": [clip],
            "intervals": [[str(x) for x in interval]],
            "dependencies": deps,
        }
        response = {
            "segments": [segment(*interval)],
            "observed_modalities": ["audio", "video"],
        }
        atomic_json(directory / "request.json", request)
        atomic_json(directory / "response.json", response)
        execution = {
            "schema_version": "execution-receipt/v1",
            "test_only": True,
            "completed": True,
            "exit_code": 0,
            "run_id": f"unit-proposer-{index}",
            "model_revision": "unit-model",
            "provider_request_id": f"unit-provider-{index}",
            "prompt": artifact_ref(prompt),
            "prompt_sha256": artifact_ref(prompt)["sha256"],
            "request": artifact_ref(directory / "request.json"),
            "response": artifact_ref(directory / "response.json"),
            "dependencies": deps,
        }
        atomic_json(directory / "execution.json", execution)
        context = {
            "schema_version": "lecture-context/v1",
            "source_sha256": source["sha256"],
            "dependencies": deps,
            "capability": artifact_ref(cap),
            "receipt": artifact_ref(directory / "execution.json"),
            "input_clips": [clip["clip"]],
            "segments": response["segments"],
            "proposer_run_id": execution["run_id"],
            "prompt_sha256": execution["prompt_sha256"],
        }
        atomic_json(directory / "context.json", context)
        children.append(artifact_ref(directory / "context.json"))
    collection = {
        "schema_version": "lecture-context-collection/v1",
        "source_sha256": source["sha256"],
        "domain": ["0", "60"],
        "dependencies": deps,
        "contract": contract,
        "capability": artifact_ref(cap),
        "children": children,
    }
    return {"root": tmp_path, "source": source, "collection": collection, "deps": deps}


def verify(scenario, collection=None):
    return verify_context_collection(
        collection or scenario["collection"],
        source_sha256=scenario["source"]["sha256"],
        domain=["0", "60"],
        expected_dependencies=scenario["deps"],
    )


def revise(
    scenario, index, *, request=None, response=None, execution=None, context=None
):
    path = scenario["root"] / f"child-{index}"
    req = read_json(path / "request.json")
    resp = read_json(path / "response.json")
    run = read_json(path / "execution.json")
    ctx = read_json(path / "context.json")
    if request:
        request(req)
    if response:
        response(resp)
    atomic_json(path / "request.json", req)
    atomic_json(path / "response.json", resp)
    run.update(
        request=artifact_ref(path / "request.json"),
        response=artifact_ref(path / "response.json"),
    )
    if execution:
        execution(run)
    atomic_json(path / "execution.json", run)
    ctx.update(receipt=artifact_ref(path / "execution.json"), segments=resp["segments"])
    if context:
        context(ctx)
    atomic_json(path / "context.json", ctx)
    scenario["collection"]["children"][index] = artifact_ref(path / "context.json")


def analysis(scenario, span=(26, 29)):
    raw = {
        "schema_version": "acoustic-analysis/v1",
        "source_sha256": scenario["source"]["sha256"],
        "source_path": scenario["source"]["path"],
        "domain": ["0", "60"],
        "completed": True,
        "status": "PASS",
        "run_id": "test-only-acoustic-gate",
        "intervals": [{"start": str(span[0]), "end": str(span[1])}],
    }
    path = scenario["root"] / "acoustic-unit.json"
    atomic_json(path, raw)
    return analyze_source(
        scenario["source"],
        ["0", "60"],
        {**raw, "artifact_ref": artifact_ref(path)},
        scenario["collection"],
        expected_dependencies=scenario["deps"],
    )


def all_activity(scenario, kind, positive=None):
    for index, interval in enumerate(windows(["0", "60"])):
        revise(
            scenario,
            index,
            response=lambda response, interval=interval: response.update(
                segments=[segment(*interval, kind, positive)]
            ),
        )


def test_actual_inputs_full_window_coverage_and_original_provenance(scenario):
    result = verify(scenario)
    assert (
        result["coverage"]["input_intervals"]
        == result["coverage"]["observed_intervals"]
        == [["0", "60"]]
    )
    assert len(result["children"]) == 3
    assert result["proposer_run_ids"] == [f"unit-proposer-{i}" for i in range(3)]
    assert not {"receipt", "run_id", "model_revision"} & result.keys()
    assert all(child["proposer"]["receipt"] for child in result["children"])
    reversed_collection = {
        **scenario["collection"],
        "children": list(reversed(scenario["collection"]["children"])),
    }
    assert verify(scenario, reversed_collection) == result


@pytest.mark.parametrize(
    "damage",
    [
        "missing_middle",
        "duplicate_ref",
        "repeat_window",
        "partial_window",
        "observation_gap",
        "empty_reason",
        "empty_segments",
        "transcript_only",
        "source",
        "code",
        "output_dependency",
        "capability_swap",
        "false_capability",
        "run_reuse",
        "provider_reuse",
        "prompt_swap",
        "child_bytes",
        "clip_hash_swap",
        "contract_threshold",
        "reduced_domain",
        "aggregate_pass",
    ],
)
def test_collection_refuses_missing_stale_fabricated_or_unobserved_children(
    scenario, damage
):
    collection = scenario["collection"]
    if damage == "missing_middle":
        collection["children"].pop(1)
    elif damage == "duplicate_ref":
        collection["children"][1] = collection["children"][0]
    elif damage == "repeat_window":
        first = read_json(collection["children"][0]["path"])
        path = scenario["root"] / "repeat.json"
        atomic_json(
            path, {**first, "note": "another wrapper cannot add source coverage"}
        )
        collection["children"][1] = artifact_ref(path)
    elif damage == "partial_window":
        revise(scenario, 1, request=lambda req: req.update(intervals=[["25", "54"]]))
    elif damage == "observation_gap":
        revise(
            scenario,
            1,
            response=lambda response: response.update(segments=[segment(25, 53)]),
        )
    elif damage == "empty_reason":
        revise(
            scenario,
            1,
            response=lambda response: response["segments"][0].update(reason=""),
        )
    elif damage == "empty_segments":
        revise(scenario, 1, response=lambda response: response.update(segments=[]))
    elif damage == "transcript_only":
        revise(
            scenario,
            1,
            response=lambda response: response.update(observed_modalities=["text"]),
        )
    elif damage == "source":
        revise(
            scenario, 1, context=lambda context: context.update(source_sha256="f" * 64)
        )
    elif damage == "code":
        revise(
            scenario,
            1,
            context=lambda context: context["dependencies"].update(
                code_tree_hash="f" * 64
            ),
        )
    elif damage == "output_dependency":
        revise(
            scenario,
            1,
            context=lambda context: context["dependencies"].update(
                output_hash="f" * 64
            ),
        )
    elif damage == "capability_swap":
        cap = read_json(collection["capability"]["path"])
        p = scenario["root"] / "another-cap.json"
        atomic_json(p, {**cap, "note": "different unbound capability"})
        revise(
            scenario,
            1,
            context=lambda context: context.update(capability=artifact_ref(p)),
        )
    elif damage == "false_capability":
        path = Path(collection["capability"]["path"])
        cap = read_json(path)
        cap["isolated_unit_gate"] = False
        atomic_json(path, cap)
        collection["capability"] = artifact_ref(path)
        for index in range(3):
            revise(
                scenario,
                index,
                context=lambda context: context.update(
                    capability=collection["capability"]
                ),
            )
    elif damage == "run_reuse":
        revise(
            scenario,
            1,
            execution=lambda run: run.update(run_id="unit-proposer-0"),
            context=lambda context: context.update(proposer_run_id="unit-proposer-0"),
        )
    elif damage == "provider_reuse":
        revise(
            scenario,
            1,
            execution=lambda run: run.update(provider_request_id="unit-provider-0"),
        )
    elif damage == "prompt_swap":
        revise(
            scenario, 1, context=lambda context: context.update(prompt_sha256="f" * 64)
        )
    elif damage == "child_bytes":
        Path(collection["children"][1]["path"]).write_text("{}")
    elif damage == "clip_hash_swap":
        original = read_json(collection["children"][0]["path"])
        revise(
            scenario,
            1,
            context=lambda context: context.update(input_clips=original["input_clips"]),
        )
    elif damage == "contract_threshold":
        p = Path(collection["contract"]["path"])
        value = read_json(p)
        value["review"]["overlap_seconds"] = 0
        atomic_json(p, value)
        collection["contract"] = artifact_ref(p)
    elif damage == "reduced_domain":
        collection["domain"] = ["0", "30"]
    elif damage == "aggregate_pass":
        collection.update(status="PASS", run_id="invented-aggregate")
    with pytest.raises((TalkCutError, ValueError)):
        verify(scenario)


def test_full_pause_consensus_uses_all_original_proposers(scenario):
    all_activity(scenario, "disposable_pause", PAUSE)
    report = analysis(scenario)
    candidate = report["candidates"][0]
    assert report["status"] == "ANALYZED" and candidate["policy_action"] == "auto_apply"
    assert candidate["proposer_run_id"] is None
    assert candidate["proposer_run_ids"] == ["unit-proposer-0", "unit-proposer-1"]
    assert len(candidate["proposers"]) == 2
    assert not report.get("receipt") and report["proposer_run_id"] is None


@pytest.mark.parametrize(
    "negative",
    [
        "demo",
        "question_wait",
        "correction",
        "negation",
        "uncertain",
        "disfluency",
        "missing_positive",
    ],
)
def test_overlap_negative_or_conflicting_observation_keeps_all_evidence(
    scenario, negative
):
    all_activity(scenario, "disposable_pause", PAUSE)
    kind = "disposable_pause" if negative == "missing_positive" else negative
    revise(
        scenario,
        1,
        response=lambda response: response.update(segments=[segment(25, 55, kind)]),
    )
    report = analysis(scenario)
    candidate = next(
        row
        for row in report["candidates"]
        if row["kind"] == "silence" and (row["start"], row["end"]) == ("26", "29")
    )
    assert candidate["policy_action"] == "keep"
    assert candidate["proposer_run_ids"] == ["unit-proposer-0", "unit-proposer-1"]
    refs = {row["sha256"] for row in candidate["evidence_refs"]}
    assert {scenario["collection"]["children"][i]["sha256"] for i in (0, 1)} <= refs
    assert any(
        part["original_observations"]
        for part in report["context_verification"]["segments"]
    )
    if negative != "missing_positive":
        assert report["protected_intervals"]


def test_preparation_positive_and_later_instruction_protection(scenario):
    revise(
        scenario,
        0,
        response=lambda response: response.update(
            segments=[
                segment(0, 5, "preparation", PREP),
                segment(5, 30, "introduction"),
            ]
        ),
    )
    report = analysis(scenario, span=(1, 4))
    candidate = next(
        row for row in report["candidates"] if row["kind"] == "preparation"
    )
    assert (
        candidate["policy_action"] == "auto_apply"
        and candidate["start"] == "0"
        and candidate["end"] == "5"
    )
    assert candidate["proposer_run_ids"] == ["unit-proposer-0"]
    assert any(row["kind"] == "introduction" for row in report["protected_intervals"])


def test_constructor_writes_refs_only_after_validation_and_refuses_overwrite(scenario):
    c = scenario["collection"]
    output = scenario["root"] / "collection.json"
    result = build_context_collection(
        list(reversed(c["children"])),
        source_sha256=c["source_sha256"],
        domain=c["domain"],
        dependencies=c["dependencies"],
        contract=c["contract"],
        capability=c["capability"],
        output=output,
    )
    assert result["status"] == "VERIFIED_SOURCE_CONTEXT"
    assert read_json(output)["children"] == c["children"]
    with pytest.raises(TalkCutError, match="overwrite"):
        build_context_collection(
            c["children"],
            source_sha256=c["source_sha256"],
            domain=c["domain"],
            dependencies=c["dependencies"],
            contract=c["contract"],
            capability=c["capability"],
            output=output,
        )
    output2 = scenario["root"] / "missing.json"
    with pytest.raises(TalkCutError):
        build_context_collection(
            c["children"][:2],
            source_sha256=c["source_sha256"],
            domain=c["domain"],
            dependencies=c["dependencies"],
            contract=c["contract"],
            capability=c["capability"],
            output=output2,
        )
    assert not output2.exists()


def test_nested_raw_response_mutation_after_early_child_validation_refuses(
    scenario, monkeypatch
):
    from talkcut import review

    original = review.verify_context_execution
    calls = 0

    def mutate(context):
        nonlocal calls
        result = original(context)
        calls += 1
        if calls == 3:
            path = scenario["root"] / "child-0/response.json"
            path.write_text("{}")
        return result

    monkeypatch.setattr(review, "verify_context_execution", mutate)
    with pytest.raises(TalkCutError, match="missing or changed"):
        verify(scenario)


@pytest.mark.parametrize("reuse", ["none", "other_window", "calibration"])
def test_component_ids_are_read_from_original_receipts_not_wrapper_labels(
    scenario, reuse
):
    # Only the provider gate is isolated as in scenario. These authored node
    # files are test_only and cannot pass the actual composite/native validator.
    for index in range(3):
        run_id = f"unit-native-{index}"
        if index == 1 and reuse == "other_window":
            run_id = "unit-native-0"
        if index == 1 and reuse == "calibration":
            run_id = "unit-calibration"
        base = scenario["root"] / f"child-{index}"
        atomic_json(
            base / "native-execution.json", {"run_id": run_id, "test_only": True}
        )
        atomic_json(
            base / "node.json",
            {
                "execution": artifact_ref(base / "native-execution.json"),
                "test_only": True,
            },
        )
        revise(
            scenario,
            index,
            execution=lambda run, base=base: run.update(
                schema_version="composite-review-receipt/v1",
                _composite_verified=True,
                nodes=[artifact_ref(base / "node.json")],
            ),
        )
    if reuse != "none":
        with pytest.raises(TalkCutError, match="component execution was reused"):
            verify(scenario)
    else:
        result = verify(scenario)
        assert all(len(child["execution_ids"]) == 2 for child in result["children"])
        assert result["children"][1]["proposer"]["execution_ids"] == [
            "unit-native-1",
            "unit-proposer-1",
        ]


def test_unit_receipts_fail_in_a_fresh_unpatched_process(scenario):
    import os
    import sys

    import talkcut.context_collection

    payload = scenario["root"] / "unit-collection.json"
    atomic_json(payload, scenario["collection"])
    output = scenario["root"] / "must-not-exist.json"
    env = {
        **os.environ,
        "PYTHONPATH": str(Path(talkcut.context_collection.__file__).parents[1]),
    }
    # Actual child process has no monkeypatches, so authored unit fixtures must
    # never become a registered provider execution or a verified collection.
    script = """from pathlib import Path
import json,sys
from talkcut.context_collection import build_context_collection
c=json.loads(Path(sys.argv[1]).read_text())
build_context_collection(c['children'], source_sha256=c['source_sha256'],domain=c['domain'],dependencies=c['dependencies'],contract=c['contract'],capability=c['capability'],output=Path(sys.argv[2]))
"""
    result = subprocess.run(
        [sys.executable, "-c", script, str(payload), str(output)],
        env=env,
        check=False,
        text=True,
        capture_output=True,
        timeout=30,
    )
    assert result.returncode != 0
    assert "Mock/test receipts cannot validate actual review" in result.stderr
    assert not output.exists()


@pytest.mark.parametrize(
    "damage",
    [None, "drop_contributor", "prompt_alias", "same_prompt", "component_reuse"],
)
def test_collection_candidate_requires_all_actual_proposers_and_separate_review(
    scenario, monkeypatch, damage
):
    from talkcut.project import content_hash
    from talkcut.review import authorize_candidate_review

    for index, span in enumerate(windows(["0", "60"])):
        revise(
            scenario,
            index,
            response=lambda response, span=span: response.update(
                segments=[segment(*span, "disfluency")]
            ),
        )
    candidate = next(
        item
        for item in analysis(scenario)["candidates"]
        if item["kind"] == "disfluency"
    )
    assert len(candidate["proposer_run_ids"]) == 3
    # Isolate the independent review validator and policy recomputation. Their
    # full real execution tests live separately; no authored unit passes them.
    monkeypatch.setattr(
        "talkcut.analysis.verify_analysis_report",
        lambda ref, plan: {"candidates": [candidate]},
    )
    inspection = scenario["root"] / "inspection.json"
    atomic_json(
        inspection,
        {"sha256": scenario["source"]["sha256"], "video": {"coverage": ["0", "60"]}},
    )
    plan = {
        "source_hashes": scenario["deps"]["source_hashes"],
        "contract_hash": scenario["deps"]["contract_hash"],
        "inspection_refs": {"screen": artifact_ref(inspection)},
        "protected_intervals": [],
        "analysis_ref": {"unit_only": True},
    }
    request = {
        "scope": "deletion",
        "details": {
            "candidate_id": candidate["id"],
            "requested_interval": ["0", "60"],
            "source_domain": ["0", "60"],
        },
        "intervals": [["0", "60"]],
        "inputs": [{"parent_sha256": scenario["source"]["sha256"]}],
        "dependencies": {**scenario["deps"], "plan_hash": content_hash(plan)},
    }
    response = {
        "candidate_id": candidate["id"],
        "candidate_decision": "approve_deletion",
        "complete_sentence_context": True,
    }
    for name, data in [("review-request", request), ("review-response", response)]:
        atomic_json(scenario["root"] / (name + ".json"), data)
    execution = {
        "run_id": "unit-independent-review",
        "prompt_sha256": "different-review-instruction",
        "request": artifact_ref(scenario["root"] / "review-request.json"),
        "response": artifact_ref(scenario["root"] / "review-response.json"),
        "test_only": True,
    }
    if damage == "same_prompt":
        execution["prompt_sha256"] = candidate["proposer_prompt_sha256s"][0]
    if damage == "component_reuse":
        atomic_json(
            scenario["root"] / "review-leaf.json",
            {"run_id": candidate["proposer_run_ids"][0], "test_only": True},
        )
        atomic_json(
            scenario["root"] / "review-node.json",
            {
                "execution": artifact_ref(scenario["root"] / "review-leaf.json"),
                "test_only": True,
            },
        )
        execution.update(
            schema_version="composite-review-receipt/v1",
            _composite_verified=True,
            nodes=[artifact_ref(scenario["root"] / "review-node.json")],
        )
    atomic_json(scenario["root"] / "review-execution.json", execution)
    record = {
        "proposer_run_ids": candidate["proposer_run_ids"],
        "proposer_prompt_sha256s": candidate["proposer_prompt_sha256s"],
        "receipt": artifact_ref(scenario["root"] / "review-execution.json"),
    }
    if damage == "drop_contributor":
        record["proposer_run_ids"] = record["proposer_run_ids"][:1]
    if damage == "prompt_alias":
        record["proposer_prompt_sha256s"] = ["invented-unrelated-prompt"]
    proof = {
        "import": {"artifact_ref": {"unit_only": True}},
        "record": record,
        "request": request,
        "response": response,
        "receipt": execution,
    }
    monkeypatch.setattr("talkcut.review.verify_imported_review", lambda ref: proof)
    if damage is None:
        assert (
            authorize_candidate_review({}, candidate, plan)["candidate_id"]
            == candidate["id"]
        )
    else:
        with pytest.raises(
            TalkCutError, match="actual proposal|prompt separation|reuses a component"
        ):
            authorize_candidate_review({}, candidate, plan)


def test_automatic_collection_candidate_recomputes_original_negative_and_contributor_evidence(
    scenario,
):
    from talkcut.analysis import authorize_automatic_candidate

    for index, span in enumerate(windows(["0", "60"])):
        revise(
            scenario,
            index,
            response=lambda response, span=span: response.update(
                segments=[segment(*span, "disposable_pause", PAUSE)]
            ),
        )
    report = analysis(scenario)
    path = scenario["root"] / "source-analysis.json"
    atomic_json(path, report)
    inspection = scenario["root"] / "source-inspection.json"
    atomic_json(
        inspection,
        {"sha256": scenario["source"]["sha256"], "video": {"coverage": ["0", "60"]}},
    )
    plan = {
        "source_hashes": scenario["deps"]["source_hashes"],
        "contract_hash": scenario["deps"]["contract_hash"],
        "inspection_refs": {"screen": artifact_ref(inspection)},
        "protected_intervals": report["protected_intervals"],
    }
    candidate = report["candidates"][0]
    assert (
        authorize_automatic_candidate(artifact_ref(path), candidate, plan)[
            "recomputed_policy_action"
        ]
        == "auto_apply"
    )
    with pytest.raises(TalkCutError, match="differs from recomputed source policy"):
        authorize_automatic_candidate(
            artifact_ref(path),
            {**candidate, "proposer_run_ids": candidate["proposer_run_ids"][:1]},
            plan,
        )
    # Actual response remains immutable. Cached positive policy cannot remove
    # its negative or omitted evidence and claim the old execution approved it.
    report["context_verification"]["segments"][0]["positive_evidence"][
        "no_learning_activity"
    ] = False
    atomic_json(path, report)
    with pytest.raises(TalkCutError, match="differs from source policy recomputation"):
        authorize_automatic_candidate(artifact_ref(path), candidate, plan)


def test_incomplete_collection_keeps_candidates_and_records_unknown_full_context(
    scenario,
):
    scenario["collection"]["children"].pop(1)
    report = analysis(scenario)
    assert report["status"] == "ANALYSIS_UNAVAILABLE"
    assert report["coverage"]["audiovisual_context_complete"] is False
    assert report["coverage"]["uncovered_context"] == [["0", "60"]]
    assert all(row["policy_action"] == "keep" for row in report["candidates"])
    assert "proposer_run_ids" not in report
    assert "omits or adds required source windows" in report["candidates"][0]["reason"]


@pytest.mark.parametrize(
    "kind,index,expected",
    [("preparation", 0, ("0", "30")), ("disfluency", 1, ("25", "55"))],
)
def test_original_candidate_not_shrunk_to_only_favorable_part(
    scenario, kind, index, expected
):
    positive = (
        {
            "before_first_substantive_content": True,
            "contains_introduction_or_instruction": False,
        }
        if kind == "preparation"
        else {}
    )
    revise(
        scenario,
        index,
        response=lambda response: response.update(
            segments=[segment(*expected, kind, positive)]
        ),
    )
    report = analysis(scenario)
    candidate = next(row for row in report["candidates"] if row["kind"] == kind)
    assert (candidate["start"], candidate["end"]) == expected
    assert candidate["policy_action"] == "keep"
    assert set(candidate["proposer_run_ids"]) == (
        {"unit-proposer-0", "unit-proposer-1"}
        if kind == "preparation"
        else {"unit-proposer-0", "unit-proposer-1", "unit-proposer-2"}
    )
    assert candidate["evidence_refs"] and all(
        p["response"] for p in candidate["proposers"]
    )
