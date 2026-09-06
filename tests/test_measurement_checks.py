"""Actual public FFmpeg/CLI recovery, plus fail-closed raw evidence tests.

The generated sine/test pattern is a technical fixture, not DGIST or AI review.
"""

import copy
import subprocess
import sys
from pathlib import Path

import pytest

from talkcut.measurement_checks import (
    verify_recovery,
    verify_roundtrip,
    verify_workflow,
)
from talkcut.project import TalkCutError, artifact_ref, atomic_json, read_json


@pytest.fixture(scope="module")
def roundtrip(tmp_path_factory):
    root = Path(__file__).resolve().parents[1]
    directory = tmp_path_factory.mktemp("recovery") / "run"
    execution = subprocess.run(
        [sys.executable, str(root / "examples/recovery.py"), str(directory)],
        cwd=root,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert execution.returncode == 0, execution.stderr
    return read_json(directory / "result.json")


def altered_steps(run, tmp_path, mutate):
    result = copy.deepcopy(run)
    steps = read_json(result["executions"]["path"])
    mutate(steps)
    target = tmp_path / "altered-executions.json"
    atomic_json(target, steps)
    result["executions"] = artifact_ref(target)
    return result


def test_actual_public_cli_cut_restore_reapply_and_source_pts(roundtrip):
    result = verify_roundtrip(roundtrip)
    assert result["technical_roundtrip"] is True
    assert result["reopen"] and result["unchanged_rerun"]
    assert result["timing_preserved"] and result["history_preserved"]
    assert result["owner_event_fabricated"] is False
    assert "review_invalidated_and_regenerated" not in result


def test_comparison_only_source_is_preserved_but_not_a_native_render_track(
    roundtrip, monkeypatch
):
    from talkcut.measurement_checks import verify_render
    from talkcut.project import load_project, verified_json

    project = load_project(roundtrip["project"])
    # Isolate native input-role binding using actual generated MP4s. The
    # original plan/compiler and the comparison source preservation gates have
    # their own checks; this added reference must not become a rendered track.
    project["sources"]["comparison_baseline"] = {
        **project["sources"]["screen"],
        "role": "comparison_baseline",
    }
    output = roundtrip["outputs"]["baseline"]
    timeline = verified_json(output["settings"]["timeline"])
    monkeypatch.setattr(
        "talkcut.plan.compile_plan", lambda current_project, plan: timeline
    )
    assert verify_render(output, project)["validation"]["decode"]["exit_code"] == 0


def test_real_running_roundtrip_stays_unverified(roundtrip):
    result = {**roundtrip, "schema_version": "dgist-roundtrip/v1", "status": "RUNNING"}
    with pytest.raises(TalkCutError, match="has not completed"):
        verify_roundtrip(result)


def test_fixture_cannot_substitute_registered_source(roundtrip):
    with pytest.raises(TalkCutError, match="registered real DGIST"):
        verify_roundtrip(
            roundtrip, expected_source_hashes={"screen": "0" * 64, "speaker": "0" * 64}
        )


def test_owner_approval_cannot_be_inserted(roundtrip):
    with pytest.raises(TalkCutError, match="owner-pending"):
        verify_roundtrip({**roundtrip, "owner_acceptance": "accepted"})


def test_recovery_requires_all_four_preserved_outputs(roundtrip):
    run = copy.deepcopy(roundtrip)
    del run["outputs"]["restored"]
    with pytest.raises(TalkCutError, match="four successful"):
        verify_roundtrip(run)


def test_foreign_command_cannot_certify_recovery(roundtrip, tmp_path):
    def mutate(steps):
        steps[7]["argv"] = [sys.executable, "-c", "print(1+1)"]

    run = altered_steps(roundtrip, tmp_path, mutate)
    with pytest.raises(TalkCutError, match="Unrelated execution"):
        verify_roundtrip(run)


def test_rerun_requires_actual_cache_history(roundtrip, tmp_path):
    def mutate(steps):
        steps.pop(12)

    run = altered_steps(roundtrip, tmp_path, mutate)
    with pytest.raises(TalkCutError, match="execution ledger is incomplete"):
        verify_roundtrip(run)


def test_restore_cannot_be_relabelled_from_cut_stdout(roundtrip):
    run = copy.deepcopy(roundtrip)
    run["outputs"]["restored"] = run["outputs"]["cut"]
    with pytest.raises(TalkCutError, match="corresponding decision revision"):
        verify_roundtrip(run)


def test_unchanged_hash_does_not_prove_new_owner_state(roundtrip, tmp_path):
    def mutate(steps):
        changed = read_json(steps[-1]["stdout"]["path"])
        changed["active_render"] = roundtrip["outputs"]["baseline"]["native_render"]
        path = tmp_path / "wrong-reopen.json"
        atomic_json(path, changed)
        steps[-1]["stdout"] = artifact_ref(path)

    run = altered_steps(roundtrip, tmp_path, mutate)
    with pytest.raises(TalkCutError, match="Reopened project selected another render"):
        verify_roundtrip(run)


def test_workflow_copied_stage_labels_do_not_certify_execution(tmp_path):
    with pytest.raises(TalkCutError, match="Typed workflow inputs"):
        verify_workflow(
            {
                "steps_completed": [
                    "inspect",
                    "sync",
                    "analysis",
                    "plan",
                    "review",
                    "render",
                    "qc",
                    "prepare-release",
                ]
            },
            project_dir=tmp_path,
            dependencies={},
        )


def test_recovery_copied_measurements_have_no_raw_source_proof(tmp_path):
    with pytest.raises(TalkCutError, match="Typed recovery inputs"):
        verify_recovery(
            {"real_dgist_cut_restore_reapply": True, "fixture_roundtrip": True},
            project_dir=tmp_path,
            expected_source_hashes={},
            source_domain=None,
        )


def test_recovery_requires_complete_measured_real_domain(tmp_path):
    with pytest.raises(TalkCutError, match="source domain is unavailable"):
        verify_recovery(
            {"schema_version": "recovery-input/v1"},
            project_dir=tmp_path,
            expected_source_hashes={},
            source_domain=None,
        )


def test_actual_diagnostic_transport_control_cannot_be_relabelled_master(roundtrip):
    from talkcut.measurement_checks import verify_acceptance_render
    from talkcut.project import load_project

    project = load_project(roundtrip["project"])
    record = read_json(roundtrip["outputs"]["reapplied"]["acceptance_render"]["path"])
    verified = verify_acceptance_render(
        record,
        project,
        Path(__file__).parents[1],
        expected_profile="diagnostic",
        project_dir=Path(roundtrip["project"]),
    )
    assert verified["validation"]["decode"]["exit_code"] == 0
    forged = {**record, "profile": "master", "test_only": False}
    with pytest.raises(TalkCutError, match="relabelled"):
        verify_acceptance_render(forged, project, Path(__file__).parents[1])


def test_cli_render_metadata_must_match_actual_worker_stdout(roundtrip, tmp_path):
    from talkcut.measurement_checks import verify_render
    from talkcut.project import load_project

    output = copy.deepcopy(roundtrip["outputs"]["reapplied"])
    log = read_json(output["execution"]["path"])
    log["stdout"] = roundtrip["outputs"]["baseline"]["execution"]
    atomic_json(tmp_path / "changed-execution.json", log)
    output["execution"] = artifact_ref(tmp_path / "changed-execution.json")
    with pytest.raises(TalkCutError, match="Render transport differs"):
        verify_render(output, load_project(roundtrip["project"]))
