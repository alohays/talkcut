"""Envelope binding unit fixtures, not evidence of actual provider execution."""

import copy

import pytest

from talkcut.project import TalkCutError, artifact_ref, atomic_json
from talkcut.review import verify_artifact_audit


def audit(tmp_path, mutation=None):
    for name in ("snapshot", "file"):
        atomic_json(tmp_path / f"{name}.json", {"test_only": True, "name": name})
    snapshot, item = (
        artifact_ref(tmp_path / f"{name}.json") for name in ("snapshot", "file")
    )
    deps = {"code_tree_hash": "isolated-envelope-unit-fixture"}
    request = {
        "scope": "unit_artifact_inventory",
        "snapshot_hash": snapshot["sha256"],
        "input_artifacts": [snapshot, item],
        "dependencies": deps,
    }
    response = {
        "snapshot_hash": snapshot["sha256"],
        "inspected_artifact_hashes": [snapshot["sha256"], item["sha256"]],
        "verdict": "PASS",
        "reason": "This is a unit test of byte binding; it is not a provider or media approval.",
        "findings": [],
    }
    execution = {
        "schema_version": "execution-receipt/v1",
        "completed": True,
        "exit_code": 0,
        "run_id": "separate-unit-auditor",
        "provider_request_id": "explicitly-isolated-unit-fixture",
        "model_revision": "unit-schema-test",
        "started_at": "2026-01-01T00:00:00+00:00",
        "finished_at": "2026-01-01T00:01:00+00:00",
        "dependencies": deps,
    }
    if mutation:
        mutation(request, response, execution)
    for name, value in (("request", request), ("response", response)):
        atomic_json(tmp_path / f"{name}.json", value)
    for name in ("prompt", "log"):
        (tmp_path / f"{name}.txt").write_text(
            "Isolated artifact-binding unit fixture, not an actual provider execution.\n"
        )
    execution.update(
        {
            name: artifact_ref(tmp_path / f"{name}.json")
            for name in ("request", "response")
        }
    )
    execution.update(
        {name: artifact_ref(tmp_path / f"{name}.txt") for name in ("prompt", "log")}
    )
    execution["prompt_sha256"] = execution["prompt"]["sha256"]
    atomic_json(tmp_path / "receipt.json", execution)
    envelope = {
        "schema_version": "artifact-audit/v1",
        "reviewer_role": "independent_auditor",
        "reviewer_run_id": execution["run_id"],
        "receipt": artifact_ref(tmp_path / "receipt.json"),
        "snapshot_hash": snapshot["sha256"],
        "dependencies": deps,
    }
    atomic_json(tmp_path / "audit.json", envelope)
    return verify_artifact_audit(
        artifact_ref(tmp_path / "audit.json"),
        scope="unit_artifact_inventory",
        snapshot_ref=snapshot,
        input_refs=[item],
        dependencies=deps,
        excluded_run_ids={"unit-author"},
    )


def test_bound_envelope_control(tmp_path):
    result = audit(tmp_path)
    assert result["request"]["snapshot_hash"] == result["response"]["snapshot_hash"]


@pytest.mark.parametrize(
    "mutation",
    [
        lambda q, r, e: q.update(scope="unrelated_audit"),
        lambda q, r, e: q.update(snapshot_hash="f" * 64),
        lambda q, r, e: r.update(snapshot_hash="f" * 64),
        lambda q, r, e: q.update(input_artifacts=q["input_artifacts"][:1]),
        lambda q, r, e: r.update(
            inspected_artifact_hashes=r["inspected_artifact_hashes"][:1]
        ),
        lambda q, r, e: q.update(
            input_artifacts=q["input_artifacts"] + copy.deepcopy(q["input_artifacts"])
        ),
        lambda q, r, e: e.update(run_id="unit-author"),
        lambda q, r, e: e.update(finished_at="2025-01-01T00:00:00+00:00"),
        lambda q, r, e: e.update(started_at="2026-01-01T00:00:00"),
        lambda q, r, e: e.update(dependencies={"code_tree_hash": "foreign-code"}),
        lambda q, r, e: r.update(
            findings=[{"severity": "P1", "reason": "still unresolved"}]
        ),
        lambda q, r, e: r.update(verdict="FAIL"),
    ],
)
def test_audit_requires_actual_snapshot_inputs_and_separate_execution(
    tmp_path, mutation
):
    with pytest.raises(TalkCutError):
        audit(tmp_path, mutation)
