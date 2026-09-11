"""Independent foundation regressions; synthetic faults never serve as media QC."""

from argparse import Namespace
from pathlib import Path

import numpy as np
import pytest

from talkcut.__main__ import execute
from talkcut.media import support_findings
from talkcut.project import (
    TalkCutError,
    artifact_ref,
    atomic_json,
    init_project,
    load_project,
    project_lock,
    read_json,
    save_revision,
)
from talkcut.sync import analyze_project, correlate


@pytest.fixture
def private_project(tmp_path):
    screen, speaker = tmp_path / "screen.mp4", tmp_path / "speaker.mp4"
    screen.write_bytes(b"independent synthetic screen bytes")
    speaker.write_bytes(b"independent synthetic speaker bytes")
    directory = tmp_path / "project"
    init_project(directory, screen, speaker)
    return directory


@pytest.mark.parametrize("sar", [None, "N/A", "0:1"])
def test_unknown_sar_must_not_become_supported_square_pixels(sar):
    video = {"codec_type": "video", "codec_name": "h264", "pix_fmt": "yuv420p"}
    if sar is not None:
        video["sample_aspect_ratio"] = sar
    audio = {"codec_type": "audio", "codec_name": "aac", "channels": 2}
    assert support_findings({"streams": [video, audio]}), "Unmeasured SAR was treated as square-pixel support"


@pytest.mark.parametrize("mutation", ["prior_event", "revision_count", "prior_revision"])
def test_reopen_detects_corrupt_revision_history(private_project, mutation):
    with project_lock(private_project):
        project = load_project(private_project)
        save_revision(private_project, project, 0, "first", {"test_only": True})
        save_revision(private_project, project, 1, "second", {"test_only": True})
    data = read_json(private_project / "project.json")
    if mutation == "prior_event":
        data["events"][0]["details"] = {"tampered": True}
    elif mutation == "revision_count":
        data["revision"] += 1
    else:
        data["events"][1]["prior_revision"] = 14
    atomic_json(private_project / "project.json", data)
    with pytest.raises((TalkCutError, ValueError)):
        load_project(private_project)


@pytest.mark.parametrize("mismatch", ["artifact_bytes", "source_identity"])
def test_sync_rejects_stale_inspection_before_audio_processing(private_project, monkeypatch, mismatch):
    import talkcut.sync as sync_module

    with project_lock(private_project):
        project = load_project(private_project)
        for role, source in project["sources"].items():
            inspection = {"status": "PASS", "sha256": source["sha256"],
                          "audio": {"index": 0, "coverage": ["0", "60"]}}
            if mismatch == "source_identity":
                inspection["sha256"] = "f" * 64
            path = private_project / "evidence" / f"{role}.json"
            atomic_json(path, inspection)
            project["inspections"][role] = artifact_ref(path)
            if mismatch == "artifact_bytes":
                inspection["tampered_after_hash"] = True
                atomic_json(path, inspection)
        save_revision(private_project, project, 0, "attach_test_inspections", {})

    def must_not_decode(*args, **kwargs):
        pytest.fail("Audio processing started before checking inspection identity")

    monkeypatch.setattr(sync_module, "pcm_window", must_not_decode)
    with pytest.raises((TalkCutError, ValueError)):
        analyze_project(private_project)


def test_inspection_cache_requires_current_toolchain_and_receipts(private_project, monkeypatch):
    import talkcut.media as media_module

    project = load_project(private_project)
    for source in project["sources"].values():
        path = private_project / "evidence" / f"inspect-{source['sha256']}" / "inspection.json"
        atomic_json(path, {"sha256": source["sha256"], "status": "PASS", "full_decode": True,
                           "toolchain": {"tools": {"ffmpeg": {"sha256": "obsolete-build"}}}})
    inspected = []

    def reinspection(path, directory, decode):
        inspected.append(Path(path))
        atomic_json(Path(directory) / "inspection.json", {"status": "PASS"})

    monkeypatch.setattr(media_module, "inspect_source", reinspection)
    execute(Namespace(command="inspect", project=private_project, full_decode=True))
    assert len(inspected) == 2, "An old build's PASS without frame/decode receipts was reused"


def test_periodic_audio_cannot_claim_unique_sample_level_alignment():
    rate = 16000
    # A steady tone has an equally plausible event every millisecond. Selecting
    # its center peak cannot establish a one-sample event-location uncertainty.
    samples = np.sin(2 * np.pi * 1000 * np.arange(rate * 8) / rate)
    assert correlate(samples, samples, rate)["status"] == "UNVERIFIED"
