import subprocess
from pathlib import Path

import numpy as np
import pytest

from talkcut.__main__ import execute, parser_for_cli
from talkcut.project import (
    TalkCutError,
    atomic_json,
    load_project,
    read_json,
    verified_json,
)


def command(*args):
    return execute(parser_for_cli().parse_args([str(arg) for arg in args]))


@pytest.fixture(params=[1, 2], ids=["mono", "stereo"])
def inspected_project(tmp_path, request):
    source = tmp_path / "synthetic.mp4"
    subprocess.run(
        [
            "ffmpeg",
            "-v",
            "error",
            "-f",
            "lavfi",
            "-i",
            "testsrc2=size=320x180:rate=1000/33:duration=4",
            "-f",
            "lavfi",
            "-i",
            "sine=frequency=700:sample_rate=44100:duration=4.2"
            if request.param == 1 else
            "aevalsrc=0.1*sin(2*PI*700*t)|0.1*sin(2*PI*1100*t):s=44100:d=4.2",
            "-map",
            "1:a",
            "-map",
            "0:v",
            "-c:v",
            "libx264",
            "-c:a",
            "aac",
            "-video_track_timescale",
            "45000",
            str(source),
        ],
        check=True,
        timeout=60,
    )
    project = tmp_path / "project"
    command("init", project, "--screen", source, "--speaker", source)
    result, code = command("inspect", project, "--full-decode")
    assert code == 0 and result["status"] == "PASS"
    return project


def test_actual_cli_build_render_cut_restore_reapply_and_reopen(inspected_project):
    p = inspected_project
    command("plan", "build", p, "--diagnostic")
    original = verified_json(load_project(p)["active_timeline"])
    baseline, code = command(
        "render", p, "--profile", "diagnostic", "--preset", "ultrafast"
    )
    assert code == 0 and baseline["test_only"]
    baseline_bytes = Path(baseline["output"]["path"]).read_bytes()
    revision = load_project(p)["revision"]
    added, _ = command(
        "plan",
        "add-test-cut",
        p,
        "--start",
        "1",
        "--end",
        "2",
        "--expected-revision",
        revision,
    )
    candidate = added["candidate_id"]
    command(
        "plan",
        "decide",
        p,
        "--candidate",
        candidate,
        "--decision",
        "accept",
        "--expected-revision",
        added["project_revision"],
    )
    cut, _ = command("render", p, "--profile", "diagnostic", "--preset", "ultrafast")
    cut_timeline = verified_json(load_project(p)["active_timeline"])
    assert cut_timeline["frame_count"] < original["frame_count"]
    revision = load_project(p)["revision"]
    command(
        "plan", "restore", p, "--candidate", candidate, "--expected-revision", revision
    )
    restored_timeline = verified_json(load_project(p)["active_timeline"])
    assert restored_timeline["frames"] == original["frames"]
    assert restored_timeline["retained"] == original["retained"]
    restored, _ = command(
        "render", p, "--profile", "diagnostic", "--preset", "ultrafast"
    )
    qc, code = command("qc", p)
    assert code == 1  # Actual technical PASS is not final audiovisual acceptance.
    assert qc["technical"]["status"] == "PASS"
    revision = load_project(p)["revision"]
    command(
        "plan",
        "decide",
        p,
        "--candidate",
        candidate,
        "--decision",
        "accept",
        "--expected-revision",
        revision,
    )
    reapply, _ = command(
        "render", p, "--profile", "diagnostic", "--preset", "ultrafast"
    )
    assert (
        verified_json(load_project(p)["active_timeline"])["frames"]
        == cut_timeline["frames"]
    )
    cached, _ = command("render", p, "--profile", "diagnostic", "--preset", "ultrafast")
    assert cached["cache_hit"] and cached["output"] == reapply["output"]
    assert Path(baseline["output"]["path"]).read_bytes() == baseline_bytes
    assert (
        Path(cut["output"]["path"]).exists()
        and Path(restored["output"]["path"]).exists()
    )
    assert load_project(p)["owner_acceptance"] == "pending"


def test_unverified_timing_and_test_only_cannot_become_master(inspected_project):
    with pytest.raises(TalkCutError, match="verified track mapping"):
        command("plan", "build", inspected_project)
    command("plan", "build", inspected_project, "--diagnostic")
    result, code = command("render", inspected_project, "--profile", "master")
    assert code == 2 and result["status"] == "FAIL"
    assert result["worker_result"]["code"] == "SYNC_UNVERIFIED"
    assert "cannot render a master" in result["worker_result"]["message"]
    assert verified_json(result["execution"])["exit_code"] == 2
    assert load_project(inspected_project)["active_render"] is None


def test_render_records_actual_worker_without_promoting_diagnostic(inspected_project):
    from talkcut.acceptance import Evaluator, EvidenceError, rational
    from talkcut.media import probe

    project = inspected_project
    command("plan", "build", project, "--diagnostic")
    result, code = command("render", project, "--preset", "ultrafast")
    assert code == 0
    state = load_project(project)
    index = read_json(project / "acceptance.local.json")
    record = verified_json(index["render"])
    assert index["render"] == result["acceptance_render"]
    assert index["timeline"] == state["active_timeline"]
    assert record["test_only"] and record["profile"] == "diagnostic"
    receipt = verified_json(record["receipt"])
    actual = verified_json(receipt["stdout"])
    assert actual["render_id"] == record["render_id"]
    assert actual["output"] == record["output"]
    execution = verified_json(receipt["log"])
    assert execution["exit_code"] == 0 and execution["failure"] is None
    assert "render-worker" in execution["command"]
    source_inspection = verified_json(state["inspections"]["screen"])
    source_audio = next(stream for stream in verified_json(source_inspection["probe"])["streams"]
                        if stream["index"] == source_inspection["audio"]["index"])
    output_probe = probe(record["output"]["path"])
    atomic_json(project / "channel-probe.json", output_probe)
    output_audio = next(stream for stream in output_probe["streams"]
                        if stream["codec_type"] == "audio")
    channels = source_audio["channels"]
    assert output_audio["channels"] == channels
    decoded = subprocess.run(["ffmpeg", "-v", "error", "-nostdin", "-i", record["output"]["path"],
                              "-map", "0:a:0", "-t", "0.5", "-c:a", "pcm_f32le", "-f", "f32le", "pipe:1"],
                             capture_output=True, timeout=30, check=True)
    samples = np.frombuffer(decoded.stdout, dtype="<f4").reshape(-1, channels)
    bins = np.fft.rfftfreq(len(samples), 1 / 44100)
    peaks = bins[np.abs(np.fft.rfft(samples, axis=0)).argmax(axis=0)]
    np.testing.assert_allclose(peaks, [700] if channels == 1 else [700, 1100], atol=3)
    evaluator = Evaluator(project, result["render_id"], project / "unused.json", Path.cwd())
    evaluator.index = index
    timeline = verified_json(index["timeline"])
    evaluator.source_domain = (rational(timeline["domain"]["start"]), rational(timeline["domain"]["end"]))
    with pytest.raises(EvidenceError, match="Preview/sample/test-only"):
        evaluator.load_timeline_render()


def test_sync_import_rejects_unmeasured_mapping_without_mutating_project(
    inspected_project, tmp_path
):
    project = inspected_project
    before = (project / "project.json").read_bytes()
    model = tmp_path / "unsupported-sync.json"
    atomic_json(
        model, {"schema_version": "sync-model/v1", "status": "PASS", "anchors": []}
    )
    with pytest.raises(TalkCutError):
        command(
            "sync",
            "import",
            project,
            "--model",
            model,
            "--expected-revision",
            load_project(project)["revision"],
        )
    assert (project / "project.json").read_bytes() == before


def test_sync_adoption_invalidates_derived_artifacts_and_preserves_history(
    inspected_project, tmp_path, monkeypatch
):
    project = inspected_project
    command("plan", "build", project, "--diagnostic")
    prior = load_project(project)
    old_plan = verified_json(prior["active_plan"])
    model = tmp_path / "isolated-transaction-fixture.json"
    model_value = {
        "timing": {"audio_source": "screen"},
        "test_only_transaction_fixture": True,
    }
    atomic_json(model, model_value)
    # This unit test isolates the transaction after verification. The actual
    # verifier is separately tested to reject fabricated and stale AV evidence.
    monkeypatch.setattr("talkcut.sync.verify_sync_model", lambda *_: model_value)
    result, code = command(
        "sync",
        "import",
        project,
        "--model",
        model,
        "--expected-revision",
        prior["revision"],
    )
    assert code == 0 and result["output_sync"] == "UNVERIFIED"
    current = load_project(project)
    assert all(
        current[key] is None
        for key in ("active_plan", "active_timeline", "active_render")
    )
    assert current["owner_acceptance"] == "pending"
    assert verified_json(prior["active_plan"]) == old_plan
    assert current["events"][:-1] == prior["events"]
    saved = (project / "project.json").read_bytes()
    with pytest.raises(TalkCutError, match="latest project"):
        command(
            "sync",
            "import",
            project,
            "--model",
            model,
            "--expected-revision",
            prior["revision"],
        )
    assert (project / "project.json").read_bytes() == saved


def test_prepare_release_cannot_promote_unreviewed_real_render(
    inspected_project, tmp_path
):
    from talkcut.acceptance import empty_index
    from talkcut.contracts import freeze_contract

    project = inspected_project
    command("plan", "build", project, "--diagnostic")
    command("render", project, "--profile", "diagnostic", "--preset", "ultrafast")
    contract = tmp_path / "contract.json"
    freeze_contract(Path.cwd(), contract)
    atomic_json(project / "acceptance.local.json", empty_index())
    result, code = command("prepare-release", project, "--contract", contract)
    assert code == 1 and result["status"] == "UNVERIFIED"
    assert not (project / "releases").exists()
    assert load_project(project)["owner_acceptance"] == "pending"
