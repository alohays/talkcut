"""Independent repaired-boundary controls with explicit synthetic provider gates."""

import copy
import sys
from pathlib import Path

import pytest
import test_editorial_binding as fixtures

from talkcut import editorial_binding as binding
from talkcut import editorial_execution as execution
from talkcut import review
from talkcut.project import TalkCutError, load_project, store_artifact, verified_json

inspected = fixtures.inspected
scenario = fixtures.scenario


@pytest.mark.parametrize("value", [None, False, 1, 1.0, [], {}, "", "relative/python"])
def test_executor_input_types_and_relative_paths_are_rejected(value):
    with pytest.raises(TalkCutError):
        execution.executor_identity(value)


def test_actual_interpreter_alias_identifies_the_same_binary(tmp_path):
    alias = tmp_path / "python-alias"
    alias.symlink_to(sys.executable)
    current = execution.executor_identity(sys.executable)
    through_alias = execution.executor_identity(str(alias))
    assert through_alias["invoked_path"] == str(alias)
    assert {k: v for k, v in through_alias.items() if k != "invoked_path"} == {
        k: v for k, v in current.items() if k != "invoked_path"
    }


@pytest.mark.parametrize("damage", [
    "null_identity", "identity_list", "missing_before", "missing_after",
    "hash", "bytes_string", "python_version", "tool_version", "resolved_path",
    "after_only", "unbound_alias", "fully_rebound_alias", "current_python_changed",
    "current_tool_changed",
])
def test_repaired_runtime_receipt_rejects_rebound_or_missing_identity(
    scenario, tmp_path, monkeypatch, damage
):
    outcome = fixtures.synthetic_supervised_binding(scenario, tmp_path, monkeypatch)
    directory = scenario["directory"]
    record = verified_json(outcome["editorial"])
    receipt = verified_json(record["receipt"])
    process = verified_json(receipt["log"])
    identity = copy.deepcopy(receipt["executor_identity"])
    if damage == "null_identity":
        receipt["executor_identity"] = None
    elif damage == "identity_list":
        receipt["executor_identity"] = []
    elif damage == "missing_before":
        process.pop("executor_before")
    elif damage == "missing_after":
        process.pop("executor_after")
    elif damage == "after_only":
        process["executor_after"]["python_version"] = "different actual version"
    elif damage in {"unbound_alias", "fully_rebound_alias"}:
        alias = tmp_path / "never-invoked-python-alias"
        alias.symlink_to(sys.executable)
        assert receipt["command"][0] != str(alias)
        receipt["executor"] = str(alias)
        receipt["command"][0] = process["command"][0] = str(alias)
        if damage == "fully_rebound_alias":
            identity = execution.executor_identity(str(alias))
            receipt["executor_identity"] = copy.deepcopy(identity)
            process["executor_before"] = copy.deepcopy(identity)
            process["executor_after"] = copy.deepcopy(identity)
    elif damage == "current_python_changed":
        monkeypatch.setattr(sys, "version", "changed runtime version after execution")
    elif damage == "current_tool_changed":
        monkeypatch.setattr(execution, "version", lambda _: "different-tool-version")
    else:
        if damage == "hash":
            identity["sha256"] = "f" * 64
        elif damage == "bytes_string":
            identity["bytes"] = str(identity["bytes"])
        elif damage == "python_version":
            identity["python_version"] = "forged runtime version"
        elif damage == "tool_version":
            identity["tool_version"] = receipt["tool_version"] = "talkcut forged"
        else:
            identity["resolved_path"] = "/bin/true"
        receipt["executor_identity"] = copy.deepcopy(identity)
        process["executor_before"] = copy.deepcopy(identity)
        process["executor_after"] = copy.deepcopy(identity)
    receipt["log"] = store_artifact(directory, "edge-process", process)
    record["receipt"] = store_artifact(directory, "edge-receipt", receipt)
    rebound = store_artifact(directory, "edge-binding", record)
    with pytest.raises(TalkCutError):
        binding.verify_editorial_binding(rebound, directory, Path.cwd())


def test_single_composite_proposal_leaf_is_rejected_at_direct_decision_gate(
    scenario, monkeypatch
):
    directory = scenario["directory"]
    report = copy.deepcopy(scenario["report"])
    raw = verified_json(report["context"]["receipt"])
    leaf = store_artifact(directory, "unit-composite-leaf", {
        "run_id": "original-single-composite-leaf", "request": raw["request"],
        "response": raw["response"], "test_only": True,
    })
    node = store_artifact(directory, "unit-composite-node", {"execution": leaf})
    raw.update(schema_version="composite-review-receipt/v1", nodes=[node])
    report["context"]["receipt"] = store_artifact(directory, "unit-composite-top", raw)
    scenario["install"](report)

    def normalized(ref):
        value = verified_json(ref)
        if value.get("schema_version") == "composite-review-receipt/v1":
            value["_composite_verified"] = True
        return value

    # The original source-provider authority is explicitly gated in this unit.
    # Return its normalized verified receipt to the existing upper binding gate.
    monkeypatch.setattr(binding, "_receipt", normalized)
    monkeypatch.setattr(review, "_receipt", normalized)
    ref = scenario["review"](change=lambda p: p["receipt"].update(
        run_id="original-single-composite-leaf"
    ))
    with pytest.raises(TalkCutError, match="original proposal"):
        scenario["verify"]([ref])
    plan = verified_json(load_project(directory)["active_plan"])
    with pytest.raises(TalkCutError, match="component|proposal"):
        review.authorize_candidate_review(ref, plan["candidates"][0], plan)
