"""Scope adapter and proof-denial tests; mock gate below is only unit isolation."""

from fractions import Fraction

import pytest

from talkcut import sync as SYNC
from talkcut import sync_checks as CHECKS
from talkcut.project import TalkCutError, artifact_ref, atomic_json


def test_sync_checks_reject_copied_pass_without_typed_inputs(tmp_path):
    with pytest.raises(TalkCutError, match="Typed source/output"):
        CHECKS.verify_sync_inputs(
            {"status": "PASS", "max_lip_uncertainty_ms": 1},
            project_dir=tmp_path,
            dependencies={},
        )


def test_audio_only_cannot_supply_output_av_sync(tmp_path):
    with pytest.raises(TalkCutError):
        CHECKS.verify_sync_inputs(
            {
                "schema_version": "sync-input/v1",
                "project": str(tmp_path),
                "audio_correlation": {"status": "PASS"},
            },
            project_dir=tmp_path,
            dependencies={},
        )


def test_audio_measurement_cannot_be_reused_for_another_time():
    raw = {"source_interval": ["30", "36"], "output_interval": ["29", "35"]}
    CHECKS._bind_audio_anchor(raw, Fraction(33), Fraction(32))
    for source_time, output_time in ((1200, 1199), (33, 36), (36, 34)):
        with pytest.raises(TalkCutError, match="did not observe this"):
            CHECKS._bind_audio_anchor(raw, Fraction(source_time), Fraction(output_time))


@pytest.mark.parametrize("scope,accepted", [("source_sync", True), ("sync", False)])
def test_source_sync_scope_matches_actual_review_validator(
    tmp_path, monkeypatch, scope, accepted
):
    # Actual provider provenance is tested elsewhere. This test replaces only
    # that prerequisite to isolate the source_sync naming integration defect.
    timing = {
        "status": "PASS",
        "audio_source": "screen",
        "audio_rate": "1",
        "speaker_rate": "1",
        "screen_origin": "0",
        "audio_origin": "0",
        "speaker_origin": "0",
        "audio_offset": "0",
        "speaker_offset": "0",
    }
    hashes = {"screen": "screen-input", "speaker": "speaker-input"}
    inspection = {
        "video": {
            "coverage": ["0", "1200"],
            "time_base": "1",
            "frames": [{"pts": i, "duration": 1} for i in range(1200)],
        }
    }
    inspection_path = tmp_path / "inspection.json"
    atomic_json(inspection_path, inspection)
    project = {
        "sources": {k: {"sha256": v} for k, v in hashes.items()},
        "inspections": {k: artifact_ref(inspection_path) for k in hashes},
    }
    anchors = []
    for kind in ("audio", "lip", "visual"):
        for i, time in enumerate((0, 50, 400, 450, 800, 1190)):
            anchors.append(
                {
                    "id": f"{kind}-{i}",
                    "kind": kind,
                    "role": "fit" if i % 2 == 0 else "holdout",
                    "time": str(time),
                    "review_ref": {"id": f"{kind}-{i}"},
                    "measurements": {
                        "residual_ms": 0,
                        "uncertainty_ms": 1,
                        "local_frame_duration_ms": 1000,
                        "uncertainty_method": "Isolated scope test",
                    },
                }
            )

    def proof(ref):
        anchor = next(a for a in anchors if a["id"] == ref["id"])
        return {
            "request": {
                "scope": scope,
                "request_id": anchor["id"],
                "intervals": [[anchor["time"], str(int(anchor["time"]) + 1)]],
                "inputs": [{"parent_sha256": digest} for digest in hashes.values()],
                "dependencies": {"source_hashes": hashes},
                "details": {
                    "kind": anchor["kind"],
                    "role": anchor["role"],
                    "anchor_id": anchor["id"],
                    "anchor_time": anchor["time"],
                    "timing": timing,
                },
            },
            "response": {"verdict": "PASS", "measurements": anchor["measurements"]},
        }

    monkeypatch.setattr("talkcut.review.verify_imported_review", proof)
    model = {
        "schema_version": "sync-model/v1",
        "source_hashes": hashes,
        "status": "PASS",
        "timing": timing,
        "anchors": anchors,
    }
    model_path = tmp_path / "model.json"
    atomic_json(model_path, model)
    if accepted:
        assert SYNC.verify_sync_model(artifact_ref(model_path), project) == model
    else:
        with pytest.raises(TalkCutError, match="not bound to the reviewed source"):
            SYNC.verify_sync_model(artifact_ref(model_path), project)
