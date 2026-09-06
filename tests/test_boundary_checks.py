"""Actual generated media plus deliberate raw-artifact mutations."""

import copy
import sys
from pathlib import Path

import pytest

from talkcut import boundary_checks as BOUNDARY
from talkcut.project import TalkCutError, artifact_ref, atomic_json, read_json

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="module")
def fixture(tmp_path_factory):
    return BOUNDARY.run_boundary_fixture(
        tmp_path_factory.mktemp("boundaries") / "run", ROOT
    )


def changed_raw(fixture, tmp_path, edit):
    value = read_json(fixture["artifact_ref"]["path"])
    edit(value)
    path = tmp_path / "changed.json"
    atomic_json(path, value)
    return artifact_ref(path)


def test_actual_hundred_cut_frames_samples_and_aac_padding(fixture):
    measured = BOUNDARY.verify_boundary_fixture(fixture["artifact_ref"], ROOT)
    assert measured == {
        "video_error_local_frames": 0.75,
        "audio_error_samples": 0.5,
        "fixture_cut_count": 100,
        "actual_pts_verified": True,
        "aac_padding_separated": True,
    }


def test_reported_count_does_not_replace_missing_actual_cut(fixture, tmp_path):
    ref = changed_raw(fixture, tmp_path, lambda value: value["requested_cuts"].pop())
    with pytest.raises(TalkCutError, match="one hundred"):
        BOUNDARY.verify_boundary_fixture(ref, ROOT)


def test_copied_receipt_label_does_not_replace_generator(fixture, tmp_path):
    def edit(value):
        value["executions"][0]["argv"] = [sys.executable, "-c", "print(1+1)"]

    ref = changed_raw(fixture, tmp_path, edit)
    with pytest.raises(TalkCutError, match="Unrelated receipt"):
        BOUNDARY.verify_boundary_fixture(ref, ROOT)


def test_actual_source_pts_are_reobserved(fixture, tmp_path):
    def edit(value):
        probe = read_json(value["source_probe"]["path"])
        probe["frames"][1]["best_effort_timestamp"] += 1
        path = tmp_path / "forged-probe.json"
        atomic_json(path, probe)
        value["source_probe"] = artifact_ref(path)

    ref = changed_raw(fixture, tmp_path, edit)
    with pytest.raises(TalkCutError, match="actual source bytes"):
        BOUNDARY.verify_boundary_fixture(ref, ROOT)


def test_false_pcm_sample_schedule_is_reconstructed(fixture, tmp_path):
    def edit(value):
        timeline = read_json(value["timelines"]["edited"]["path"])
        timeline["retained"][30]["audio_source_sample_start"] += 1
        path = tmp_path / "forged-timeline.json"
        atomic_json(path, timeline)
        value["timelines"]["edited"] = artifact_ref(path)

    ref = changed_raw(fixture, tmp_path, edit)
    with pytest.raises(TalkCutError, match="PCM filter sample schedule"):
        BOUNDARY.verify_boundary_fixture(ref, ROOT)


def test_always_keep_fixture_cannot_be_called_hundred_cut(fixture, tmp_path):
    def edit(value):
        value["timelines"]["edited"] = copy.deepcopy(value["timelines"]["baseline"])

    ref = changed_raw(fixture, tmp_path, edit)
    with pytest.raises(TalkCutError, match="independently reconstructed source frames"):
        BOUNDARY.verify_boundary_fixture(ref, ROOT)
