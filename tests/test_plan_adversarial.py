"""Independent rejection and roundtrip tests at public workflow boundaries."""

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from talkcut.media import inspect_source
from talkcut.plan import add_test_cut, build_plan, decide, persist_plan
from talkcut.project import (
    TalkCutError,
    artifact_ref,
    atomic_json,
    content_hash,
    init_project,
    load_project,
    project_lock,
    save_revision,
    sha256,
    store_artifact,
    verified_json,
)
from talkcut.workflow import render_project


@pytest.fixture(scope="module")
def inspected_fixture(tmp_path_factory):
    if not shutil.which("ffmpeg"):
        pytest.skip("Actual source fixture requires FFmpeg")
    directory = tmp_path_factory.mktemp("plan-source")
    source = directory / "fixture.mp4"
    subprocess.run([
        "ffmpeg", "-v", "error", "-f", "lavfi", "-i", "sine=sample_rate=44100:duration=6",
        "-f", "lavfi", "-i", "testsrc2=s=160x90:r=10:duration=6", "-map", "0:a", "-map", "1:v",
        "-c:a", "aac", "-c:v", "libx264", "-preset", "ultrafast", str(source),
    ], check=True)
    inspection = inspect_source(source, directory / "inspection")
    assert inspection["status"] == "PASS"
    return source, inspection


@pytest.fixture
def planned_project(tmp_path, inspected_fixture):
    source, inspection = inspected_fixture
    directory = tmp_path / "project"
    init_project(directory, source, source)
    with project_lock(directory):
        project = load_project(directory)
        ref = store_artifact(directory, "fixture-inspections", inspection)
        project["inspections"] = {role: ref for role in ("screen", "speaker")}
        save_revision(directory, project, project["revision"], "attach_real_fixture_inspection", {})
    build_plan(directory, diagnostic=True)
    return directory


def seed_candidate(directory, *, policy="auto_apply", kind="preparation"):
    with project_lock(directory):
        project = load_project(directory)
        plan = verified_json(project["active_plan"])
        dummy = store_artifact(directory, "adversarial", {"status": "PASS", "claim": "not an execution"})
        plan["candidates"] = [{
            "id": "source-linked-candidate", "start": "1", "end": "2", "kind": kind,
            "decision": "proposed", "policy_action": policy, "evidence_refs": [dummy],
            "proposer_run_id": "proposal-run", "test_only": False,
        }]
        persist_plan(directory, project, plan, "negative_fixture_candidate_setup")
    return dummy


def test_final_plan_rejects_raw_sync_pass(planned_project):
    with project_lock(planned_project):
        project = load_project(planned_project)
        timing = verified_json(project["active_plan"])["timing"]
        timing["status"] = "PASS"
        project["sync"] = store_artifact(planned_project, "adversarial", {
            "status": "PASS", "timing": timing, "evidence_refs": [{"unverified": True}],
        })
        save_revision(planned_project, project, project["revision"], "negative_raw_sync_setup", {})
    with pytest.raises((TalkCutError, ValueError)):
        build_plan(planned_project)


def test_auto_apply_requires_executed_context_bound_to_candidate(planned_project):
    seed_candidate(planned_project)
    revision = load_project(planned_project)["revision"]
    with pytest.raises((TalkCutError, ValueError)):
        decide(planned_project, "source-linked-candidate", "accept", revision)


def test_disfluency_rejects_fabricated_receipt_and_capability(planned_project):
    dummy = seed_candidate(planned_project, policy="requires_review", kind="disfluency")
    project = load_project(planned_project)
    plan = verified_json(project["active_plan"])
    review = store_artifact(planned_project, "adversarial", {
        "status": "PASS", "candidate_id": "source-linked-candidate",
        "proposer_run_id": "proposal-run", "run_id": "different-review-run",
        "source_hashes": plan["source_hashes"], "input_modalities": ["audio", "video"],
        "receipt": dummy, "capability_ref": dummy,
    })
    with pytest.raises((TalkCutError, ValueError)):
        decide(planned_project, "source-linked-candidate", "accept", project["revision"], review)


@pytest.mark.parametrize("corruption", ["foreign_timeline", "foreign_settings", "foreign_profile"])
def test_cache_rejects_valid_hash_from_wrong_render(planned_project, inspected_fixture, monkeypatch, corruption):
    import talkcut.media as media_module
    import talkcut.workflow as workflow_module

    source, _ = inspected_fixture
    project = load_project(planned_project)
    plan = verified_json(project["active_plan"])
    timeline = verified_json(project["active_timeline"])
    toolchain = {"test_only_cache_fault": "fixed toolchain identity"}
    monkeypatch.setattr(media_module, "doctor", lambda: toolchain)
    settings = {
        "plan": project["active_plan"], "timeline": project["active_timeline"], "layout": plan["layout"],
        "audio_processing": plan["audio_processing"],
        "implementation": {name: sha256(Path(workflow_module.__file__).with_name(name))
                           for name in ("render.py", "timeline.py", "audio_processing.py")},
        "toolchain": toolchain, "profile": "diagnostic", "preset": "medium", "crf": 18,
    }
    key = content_hash(settings)
    output = {**artifact_ref(source), "bytes": source.stat().st_size}
    native = store_artifact(planned_project, "adversarial", {
        "complete": True, "status": "succeeded", "output": output, "exit_code": 0,
        "audio_processing": plan["audio_processing"],
        "timeline_hash": "foreign-timeline" if corruption == "foreign_timeline" else timeline["timeline_hash"],
    })
    success = {
        "schema_version": "workflow-render/v1", "render_id": key, "native_render": native,
        "settings": {**settings, "crf": 51} if corruption == "foreign_settings" else settings,
        "output": output, "profile": "master" if corruption == "foreign_profile" else "diagnostic",
        "test_only": True, "status": "RENDERED", "ai_review": "UNVERIFIED", "owner_acceptance": "pending",
    }
    atomic_json(planned_project / "renders" / key / "success.json", success)
    with pytest.raises((TalkCutError, ValueError)):
        render_project(planned_project)


def test_master_barrier_rejects_diagnostic_plan_before_encoder(planned_project, monkeypatch):
    import talkcut.workflow as workflow_module

    def must_not_encode(*args, **kwargs):
        pytest.fail("Encoder reached before test-only master barrier")

    monkeypatch.setattr(workflow_module, "render", must_not_encode)
    with pytest.raises(TalkCutError, match="cannot render a master"):
        render_project(planned_project, "master")


def test_cut_restore_reapply_preserves_exact_mapping_and_artifact_history(planned_project):
    baseline_state = load_project(planned_project)
    baseline_ref = baseline_state["active_timeline"]
    baseline = verified_json(baseline_ref)
    proposal = add_test_cut(planned_project, "1", "2", baseline_state["revision"])
    candidate = proposal["candidate_id"]
    accepted = decide(planned_project, candidate, "accept", proposal["project_revision"])
    edited = verified_json(accepted["timeline"])
    restored = decide(planned_project, candidate, "restore", accepted["project_revision"])
    restored_timeline = verified_json(restored["timeline"])
    reapplied = decide(planned_project, candidate, "accept", restored["project_revision"])
    reapplied_timeline = verified_json(reapplied["timeline"])
    for key in ("domain", "retained", "frames", "sample_count", "duration", "speaker_omissions"):
        assert restored_timeline[key] == baseline[key]
        assert reapplied_timeline[key] == edited[key]
    assert verified_json(baseline_ref) == baseline
    assert verified_json(accepted["timeline"]) == edited
    assert load_project(planned_project)["owner_acceptance"] == "pending"


def test_cli_encoder_failure_returns_json_and_nonzero_exit(planned_project, monkeypatch, capsys):
    import talkcut.__main__ as cli
    from talkcut.render import RenderError

    def failed(args):
        raise RenderError("RENDER_FAILED: actual subprocess failure", planned_project / "failed.render.json")

    monkeypatch.setattr(cli, "execute", failed)
    monkeypatch.setattr("sys.argv", ["talkcut", "render", str(planned_project)])
    with pytest.raises(SystemExit) as error:
        cli.main()
    assert error.value.code != 0
    report = json.loads(capsys.readouterr().out)
    assert report["schema_version"] == "talkcut-error/v1"
    assert report["status"] == "FAIL"


def test_sync_anchor_time_cannot_be_moved_outside_actual_review(planned_project, monkeypatch):
    from talkcut.sync import verify_sync_model

    project = load_project(planned_project)
    timing = verified_json(project["active_plan"])["timing"]
    timing["status"] = "PASS"
    identities = {role: source["sha256"] for role, source in project["sources"].items()}
    anchors = []
    proofs = {}
    for kind in ("audio", "lip", "visual"):
        for role, claimed_time in (("fit", "0"), ("holdout", "5")):
            anchor_id = f"{kind}-{role}"
            measurement = {"residual_ms": 0, "uncertainty_ms": 1,
                           "uncertainty_method": "isolated timing-binding negative test",
                           "local_frame_duration_ms": 100}
            ref = store_artifact(planned_project, "adversarial", {"anchor_id": anchor_id})
            anchors.append({"id": anchor_id, "kind": kind, "role": role, "time": claimed_time,
                            "measurements": measurement, "review_ref": ref})
            proofs[ref["sha256"]] = {
                "request": {"scope": "sync", "intervals": [["0", "1"]],
                            "dependencies": {"source_hashes": identities},
                            "details": {"anchor_id": anchor_id, "timing": timing, "kind": kind,
                                        "role": role, "time": "0"}},
                "response": {"verdict": "PASS", "measurements": measurement,
                             "observed_intervals": [["0", "1"]]},
            }
    # Isolate the source-time binding after provider receipt verification. No
    # mock result is being used to claim that any real AI review took place.
    monkeypatch.setattr("talkcut.review.verify_imported_review", lambda ref: proofs[ref["sha256"]])
    model = store_artifact(planned_project, "adversarial", {
        "schema_version": "sync-model/v1", "status": "PASS", "test_only": False,
        "source_hashes": identities, "timing": timing, "anchors": anchors,
    })
    with pytest.raises((TalkCutError, ValueError)):
        verify_sync_model(model, project)


@pytest.mark.parametrize("change,reason", [("boundary", "different candidate or boundary"),
                                            ("plan_revision", "different plan revision")])
def test_candidate_review_cannot_replay_different_boundary_or_plan(planned_project, monkeypatch, change, reason):
    from talkcut.review import authorize_candidate_review

    seed_candidate(planned_project, policy="requires_review", kind="disfluency")
    project = load_project(planned_project)
    plan = verified_json(project["active_plan"])
    plan["test_only"] = False
    candidate = plan["candidates"][0]
    proof = {
        "record": {"proposer_run_id": "proposal-run"}, "receipt": {"run_id": "independent-review-run"},
        "response": {},
        "request": {
            "scope": "deletion",
            "details": {"candidate_id": candidate["id"],
                        "requested_interval": ["1", "3" if change == "boundary" else "2"]},
            "dependencies": {"source_hashes": plan["source_hashes"],
                             "plan_hash": "old-plan" if change == "plan_revision" else content_hash(plan)},
        },
    }
    # Receipt verification is covered separately. This test isolates the exact
    # candidate/plan binding and never produces an executable review artifact.
    monkeypatch.setattr("talkcut.review.verify_imported_review", lambda _: proof)
    with pytest.raises(TalkCutError, match=reason):
        authorize_candidate_review({}, candidate, plan)
