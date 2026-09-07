"""Bounded synthetic provenance tests; these receipts never certify actual AI."""

import copy
import json
import subprocess
from pathlib import Path

import pytest

from talkcut import native_provenance as np
from talkcut.composite_review import digest
from talkcut.project import TalkCutError, artifact_ref


def put(tmp_path, name, value):
    p = tmp_path / name
    p.write_text(json.dumps(value))
    return artifact_ref(p)


@pytest.mark.parametrize(
    "scope,field,value",
    [
        ("run", "status", "FAILED"),
        ("run", "error", {"path": "/missing", "sha256": "f" * 64}),
        ("run", "execution_status", "FAILED"),
        ("run", "completed", False),
        ("run", "bindings_unchanged", False),
        ("case", "completed", False),
        ("case", "execution_status", "FAILED"),
        ("case", "bindings_unchanged", False),
    ],
)
def test_final_status_failure_rejected_before_any_claimed_binding(
    tmp_path, scope, field, value
):
    case = {
        "schema_version": "private-native-audio-case/v1",
        "execution_status": "COMPLETED",
        "completed": True,
        "bindings_unchanged": True,
    }
    run = {
        "schema_version": "private-native-audio-run/v1",
        "status": "UNVERIFIED_PENDING_SEPARATE_REVIEW",
        "error": None,
        "execution_status": "COMPLETED",
        "completed": True,
        "bindings_unchanged": True,
    }
    (case if scope == "case" else run)[field] = value
    c = put(tmp_path, "case.json", case)
    run["cases"] = [c]
    with pytest.raises(TalkCutError, match="Final native case/run failed"):
        np.verify_native_bundle(c, put(tmp_path, "run.json", run), {}, {})


def test_run_cannot_substitute_another_case_even_with_matching_labels(tmp_path):
    c = put(
        tmp_path,
        "case.json",
        {
            "schema_version": "private-native-audio-case/v1",
            "execution_status": "COMPLETED",
            "completed": True,
            "bindings_unchanged": True,
        },
    )
    r = put(
        tmp_path,
        "run.json",
        {
            "schema_version": "private-native-audio-run/v1",
            "status": "UNVERIFIED_PENDING_SEPARATE_REVIEW",
            "error": None,
            "execution_status": "COMPLETED",
            "completed": True,
            "bindings_unchanged": True,
            "cases": [{"path": "/other", "sha256": "a" * 64}],
        },
    )
    with pytest.raises(TalkCutError, match="Final native case/run failed"):
        np.verify_native_bundle(c, r, {}, {})


def test_actual_alias_component_order_and_literal_mutation(tmp_path):
    local = tmp_path / "local"
    outside = tmp_path / "outside"
    local.mkdir()
    outside.mkdir()
    (outside / "child").mkdir()
    (local / "target").write_bytes(b"A")
    (outside / "target").write_bytes(b"B")
    (local / "jump").symlink_to(outside / "child", target_is_directory=True)
    (local / "alias").symlink_to("jump/../target")
    original = np.alias_snapshot(str(local / "alias"))
    assert original["target"]["sha256"] == digest(b"B")
    assert [Path(row["path"]).name for row in original["hops"]] == ["alias", "jump"]
    (local / "alias").unlink()
    (local / "alias").symlink_to(outside / "target")
    assert np.alias_snapshot(str(local / "alias")) != original


@pytest.mark.parametrize(
    "mutation", ["runner", "model", "prompt", "parameter", "added_input"]
)
def test_native_profile_binds_recipe_semantics(tmp_path, mutation):
    prompt = tmp_path / "prompt"
    prompt.write_text(
        "Describe only the actually heard speech and other audio; do not invent time."
    )
    call = {
        "runner": {"sha256": "1" * 64},
        "runtime": {"path": "/runtime", "sha256": "2" * 64},
        "model_refs": [
            {"path": "/model", "sha256": "3" * 64},
            {"path": "/projector", "sha256": "4" * 64},
        ],
        "prompt": artifact_ref(prompt),
        "input": {"path": "/audio"},
        "argv": [
            "/usr/bin/time",
            "-l",
            "/runtime",
            "-m",
            "/model",
            "--mmproj",
            "/projector",
            "--threads",
            "4",
            "--audio",
            "/audio",
            "-p",
            prompt.read_text(),
        ],
    }
    call["native_child_scope"] = {
        "task": "audio_semantics_only",
        "scope": "synthetic fixture",
    }
    profile = np.native_profile(call)
    mutant = copy.deepcopy(call)
    if mutation == "runner":
        mutant["runner"]["sha256"] = "5" * 64
    elif mutation == "model":
        mutant["model_refs"][0]["sha256"] = "5" * 64
    elif mutation == "prompt":
        q = tmp_path / "other-prompt"
        q.write_text("Different instruction.")
        mutant["prompt"] = artifact_ref(q)
        mutant["argv"][-1] = q.read_text()
    elif mutation == "parameter":
        mutant["argv"][mutant["argv"].index("--threads") + 1] = "5"
    else:
        mutant["argv"] += ["--audio", "/audio"]
    if mutation == "added_input":
        with pytest.raises(TalkCutError, match="duplicated"):
            np.native_profile(mutant)
    else:
        assert np.native_profile(mutant) != profile


def test_actual_tiny_process_receipt_recheck_and_failure_mutations(tmp_path):
    import sys
    import time
    from datetime import UTC, datetime

    argv = [sys.executable, "-c", 'print("synthetic process control; no audio AI")']
    request = put(
        tmp_path, "request.json", {"schema_version": "synthetic-process-input/v1"}
    )
    started = datetime.now(UTC).isoformat()
    start = time.monotonic()
    child = subprocess.Popen(
        argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True
    )
    stdout, stderr = child.communicate(timeout=10)
    for name, data in [
        ("stdout", stdout),
        ("stderr", stderr),
        ("errors", b""),
        (
            "samples",
            json.dumps({"pid": child.pid, "actual_exit": child.returncode}).encode()
            + b"\n",
        ),
    ]:
        (tmp_path / name).write_bytes(data)
    value = {
        "schema_version": "private-bounded-process-execution/v1",
        "request": request,
        "argv": argv,
        "pid": child.pid,
        "pgid": child.pid,
        "execution_status": "COMPLETED",
        "exit_code": child.returncode,
        "termination_reason": None,
        "received_signals": [],
        "cleanup": {
            "status": "VERIFIED_EMPTY",
            "remaining_process_group_pids": [],
            "observation_errors": False,
        },
        "started_at": started,
        "finished_at": datetime.now(UTC).isoformat(),
        "elapsed_seconds": time.monotonic() - start,
        "stdout": artifact_ref(tmp_path / "stdout"),
        "stderr": artifact_ref(tmp_path / "stderr"),
        "runner_errors": artifact_ref(tmp_path / "errors"),
        "process_samples": artifact_ref(tmp_path / "samples"),
    }
    assert (
        np._supervisor(put(tmp_path, "execution.json", value), request, argv)["stdout"]
        == value["stdout"]
    )
    for key, changed in [
        ("execution_status", "FAILED"),
        ("termination_reason", "TIMEOUT"),
        ("exit_code", 7),
        ("received_signals", [15]),
    ]:
        wrong = copy.deepcopy(value)
        wrong[key] = changed
        with pytest.raises(TalkCutError, match="failed or cleanup"):
            np._supervisor(
                put(tmp_path, "mutant-" + key + ".json", wrong), request, argv
            )
    wrong = copy.deepcopy(value)
    wrong["cleanup"]["remaining_process_group_pids"] = [child.pid]
    with pytest.raises(TalkCutError, match="failed or cleanup"):
        np._supervisor(put(tmp_path, "mutant-cleanup.json", wrong), request, argv)
    (tmp_path / "stdout").write_bytes(b"fabricated replaced output")
    with pytest.raises(TalkCutError, match="Stale"):
        np._supervisor(put(tmp_path, "stale.json", value), request, argv)


def test_matching_before_after_labels_still_require_actual_artifact_bytes(tmp_path):
    body = {"launch": {}, "runtime": {}}
    before = put(tmp_path, "bindings.json", body)
    case = {
        "schema_version": "private-native-audio-case/v1",
        "execution_status": "COMPLETED",
        "completed": True,
        "bindings_unchanged": True,
        "dependencies": {},
        "request": {},
        "supervisor_execution": {},
        "bindings_before": before,
        "bindings_after": before,
    }
    c = put(tmp_path, "case.json", case)
    run = {
        "schema_version": "private-native-audio-run/v1",
        "status": "UNVERIFIED_PENDING_SEPARATE_REVIEW",
        "error": None,
        "execution_status": "COMPLETED",
        "completed": True,
        "bindings_unchanged": True,
        "cases": [c],
        "request": {},
        "execution": {},
        "bindings_before": before,
        "bindings_after": before,
    }
    Path(before["path"]).write_text('{"launch": "changed"}')
    with pytest.raises(TalkCutError, match="Stale"):
        np.verify_native_bundle(c, put(tmp_path, "run.json", run), {}, {})
