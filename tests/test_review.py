import json
import shutil
import subprocess
from fractions import Fraction
from pathlib import Path

import pytest

from talkcut.project import TalkCutError, artifact_ref, sha256
from talkcut.review import _capability, build_review_bundle, import_review, windows


def write(tmp_path, name, value):
    path = tmp_path / name
    path.write_text(json.dumps(value))
    return path


def test_overlapping_windows_cover_start_and_end_without_duplicate_credit():
    result = windows(["0", "57"])
    assert result == [
        (Fraction(0), Fraction(30)),
        (Fraction(25), Fraction(55)),
        (Fraction(50), Fraction(57)),
    ]
    assert windows(["10", "12"]) == [(Fraction(10), Fraction(12))]
    with pytest.raises(TalkCutError):
        windows(["0", "100"], "30", "30")


@pytest.mark.parametrize(
    "response",
    [
        {},
        {"status": "PASS", "human_approved": True},
        {"schema_version": "multimodal-review/v1", "reviewer_role": "proposer"},
    ],
)
def test_fake_empty_and_self_approval_imports_remain_unverified(tmp_path, response):
    response_path = write(tmp_path, "response.json", response)
    request_path = write(
        tmp_path, "request.json", {"schema_version": "review-request/v1"}
    )
    capability_path = write(tmp_path, "capability.json", {})
    result = import_review(
        response_path, request_path, capability_path, tmp_path / "imports"
    )
    assert result["status"] == "UNVERIFIED"
    assert result["coverage"] == []
    assert result["owner_acceptance"] == "pending"
    response_path.write_text("changed after import")
    assert (
        sha256(result["artifact_refs"]["record"]["path"])
        == result["artifact_refs"]["record"]["sha256"]
    )


def test_sparse_frame_capability_rejects_model_claimed_40ms(monkeypatch, tmp_path):
    # Isolate the sampling gate after receipt validation: no model runs here.
    monkeypatch.setattr(
        "talkcut.review._receipt",
        lambda ref: {
            "model_revision": "negative-fixture",
            "request": {"sha256": "request"},
            "response": artifact_ref(challenge),
        },
    )
    challenge = write(
        tmp_path,
        "challenge.json",
        {"audio_events": ["beep"], "video_events": ["flash"]},
    )
    observation = write(
        tmp_path,
        "sampling.json",
        {
            "audio_continuous": True,
            "video_frame_timestamps": ["0", "1/4", "1/2"],
            "request_sha256": "request",
        },
    )
    capability = {
        "schema_version": "review-capability/v1",
        "model_revision": "negative-fixture",
        "challenge": artifact_ref(challenge),
        "observations": artifact_ref(challenge),
        "input_observation": artifact_ref(observation),
        "temporal_resolution_ms": 40,
    }
    with pytest.raises(TalkCutError, match="too sparse"):
        _capability(capability)


@pytest.mark.parametrize(
    "failure", ["wrongtime", "empty", "truncated", "transcript", "provider_timeout"]
)
def test_provider_failure_responses_cannot_create_coverage(
    tmp_path, monkeypatch, failure
):
    monkeypatch.setattr(
        "talkcut.review._capability", lambda value: {"model_revision": "unit-negative"}
    )
    request = {
        "schema_version": "review-request/v1",
        "intervals": [["0", "10"]],
        "input_clip_hashes": ["clip-fixture"],
        "dependencies": {},
        "inputs": [],
    }
    response = {
        "verdict": "PASS",
        "observed_modalities": ["audio", "video"],
        "continuous_video_observed": True,
        "reason": "This is an authored response for an isolated negative regression test.",
        "findings": [],
        "needs_source_comparison": False,
        "observed_intervals": [["0", "10"]],
    }
    if failure == "wrongtime":
        response["observed_intervals"] = [["0", "11"]]
    elif failure == "empty":
        response = {}
    elif failure == "truncated":
        response.pop("reason")
    elif failure == "transcript":
        response["observed_modalities"] = ["transcript"]
    request_path = write(tmp_path, "request.json", request)
    raw_response = write(tmp_path, "raw-response.json", response)
    execution = {
        "model_revision": "unit-negative",
        "run_id": "review",
        "prompt_sha256": "review-prompt",
        "request": artifact_ref(request_path),
        "response": artifact_ref(raw_response),
        "dependencies": {},
    }
    if failure == "provider_timeout":

        def failed(_):
            raise TalkCutError("REVIEW_UNVERIFIED", "Provider execution did not finish")

        monkeypatch.setattr("talkcut.review._receipt", failed)
    else:
        monkeypatch.setattr("talkcut.review._receipt", lambda ref: execution)
    record = {
        "schema_version": "multimodal-review/v1",
        "reviewer_role": "adversarial_reviewer",
        "proposer_run_id": "proposer",
        "proposer_prompt_sha256": "proposer-prompt",
        "dependencies": {},
    }
    record_path = write(tmp_path, "record.json", record)
    capability_path = write(tmp_path, "capability.json", {})
    result = import_review(
        record_path, request_path, capability_path, tmp_path / "imports"
    )
    assert result["status"] == "UNVERIFIED"
    assert not result["coverage"]


@pytest.mark.skipif(not shutil.which("ffmpeg"), reason="FFmpeg required")
def test_real_deletion_seam_and_output_clips_are_created_and_hashed(tmp_path):
    sources = []
    for name, duration in (("source", 6), ("output", 5)):
        path = tmp_path / f"{name}.mp4"
        subprocess.run(
            [
                "ffmpeg",
                "-v",
                "error",
                "-f",
                "lavfi",
                "-i",
                f"testsrc2=size=96x64:rate=10:duration={duration}",
                "-f",
                "lavfi",
                "-i",
                f"sine=frequency=440:sample_rate=44100:duration={duration}",
                "-c:v",
                "libx264",
                "-c:a",
                "aac",
                str(path),
            ],
            check=True,
        )
        sources.append(artifact_ref(path))
    timeline = {
        "domain": {"start": "0", "end": "6"},
        "duration": "5",
        "retained": [
            {
                "source_start": "0",
                "source_end": "1",
                "output_start": "0",
                "output_end": "1",
            },
            {
                "source_start": "2",
                "source_end": "6",
                "output_start": "1",
                "output_end": "5",
            },
        ],
        "deletions": [],
    }
    # Deliberately omit the claimed deletion ledger: the request denominator
    # must still come from retained source intervals.
    bundle = build_review_bundle(
        tmp_path,
        timeline,
        sources[0],
        sources[1],
        tmp_path / "reviews",
        {},
        include_source_analysis=False,
    )
    assert bundle["actual_deletions"] == [["1", "2"]]
    requests = [json.loads(Path(ref["path"]).read_text()) for ref in bundle["requests"]]
    assert [item["scope"] for item in requests] == ["deletion", "seam", "output"]
    for request in requests:
        clip = request["inputs"][0]
        assert sha256(clip["clip"]["path"]) == clip["clip"]["sha256"]
        assert {item["codec_type"] for item in clip["streams"]} == {"video", "audio"}
        assert request["status"] == "UNVERIFIED"
    assert bundle["verified_review_coverage"] == []
    assert all(sha256(ref["path"]) == ref["sha256"] for ref in sources)


def test_raw_pass_import_cannot_authorize_any_candidate(tmp_path):
    from talkcut.review import authorize_candidate_review, verify_imported_review

    fake = artifact_ref(
        write(
            tmp_path,
            "fake-import.json",
            {"schema_version": "review-import/v1", "status": "PASS"},
        )
    )
    with pytest.raises(TalkCutError, match="hashed artifact"):
        verify_imported_review(fake)
    with pytest.raises(TalkCutError):
        authorize_candidate_review(fake, {"id": "target"}, {})


def test_candidate_authorization_binds_exact_plan_span_and_source(
    tmp_path, monkeypatch
):
    from talkcut.contracts import code_identity
    from talkcut.project import content_hash
    from talkcut.review import authorize_candidate_review

    inspected = artifact_ref(
        write(
            tmp_path,
            "inspection.json",
            {"sha256": "source", "video": {"coverage": ["0", "100"]}},
        )
    )
    candidate = {
        "id": "candidate-a",
        "start": "20",
        "end": "30",
        "proposer_run_id": "proposal",
    }
    plan = {
        "source_hashes": {"screen": "source"},
        "contract_hash": "contract",
        "inspection_refs": {"screen": inspected},
        "timing": {"screen_origin": "0"},
        "protected_intervals": [],
        "candidates": [candidate],
    }
    request = {
        "scope": "deletion",
        "details": {
            "candidate_id": "candidate-a",
            "requested_interval": ["20", "30"],
            "source_domain": ["0", "100"],
        },
        "intervals": [["15", "35"]],
        "dependencies": {
            "source_hashes": plan["source_hashes"],
            "plan_hash": content_hash(plan),
            "code_tree_hash": code_identity(Path.cwd())["code_tree_hash"],
            "contract_hash": "contract",
        },
        "inputs": [{"parent_sha256": "source"}],
    }
    proof = {
        "import": {"artifact_ref": {"path": "unit-revalidated", "sha256": "unit"}},
        "record": {
            "proposer_run_id": "proposal",
            "receipt": {"path": "unit", "sha256": "unit"},
        },
        "request": request,
        "receipt": {"run_id": "review"},
        "response": {
            "candidate_id": "candidate-a",
            "candidate_decision": "approve_deletion",
            "complete_sentence_context": True,
        },
    }
    # This unit test isolates candidate binding after the separately tested raw
    # provider validator. It is not a provider execution or media acceptance.
    monkeypatch.setattr("talkcut.review.verify_imported_review", lambda ref: proof)
    assert (
        authorize_candidate_review({}, candidate, plan)["candidate_id"] == "candidate-a"
    )
    with pytest.raises(TalkCutError, match="different candidate or boundary"):
        authorize_candidate_review({}, {**candidate, "end": "31"}, plan)
    request["dependencies"]["plan_hash"] = "old-revision"
    with pytest.raises(TalkCutError, match="different plan revision"):
        authorize_candidate_review({}, candidate, plan)


@pytest.mark.skipif(not shutil.which("ffmpeg"), reason="FFmpeg required")
def test_review_clip_preserves_non_frame_aligned_audio_video_offset(tmp_path):
    from talkcut.review import _clip

    path = tmp_path / "common-clock.mp4"
    subprocess.run(
        [
            "ffmpeg",
            "-v",
            "error",
            "-f",
            "lavfi",
            "-i",
            "testsrc2=size=96x64:rate=10:duration=3",
            "-f",
            "lavfi",
            "-i",
            "sine=frequency=440:sample_rate=44100:duration=3",
            "-c:v",
            "libx264",
            "-c:a",
            "aac",
            str(path),
        ],
        check=True,
    )
    result = _clip(
        artifact_ref(path), (Fraction(1, 20), Fraction(41, 20)), tmp_path / "clip", {}
    )
    streams = {item["codec_type"]: item for item in result["streams"]}
    # First video frame belongs at +50 ms; resetting each stream to its first
    # selected frame would silently erase that real offset.
    delta = Fraction(streams["video"]["start_time"]) - Fraction(
        streams["audio"]["start_time"]
    )
    assert abs(delta - Fraction(1, 20)) <= Fraction(1, 1000)
    with pytest.raises(TalkCutError, match="verified explicit PTS"):
        _clip(
            artifact_ref(path),
            (Fraction(0), Fraction(1)),
            tmp_path / "unverified",
            {},
            audio_source={**artifact_ref(path), "offset": "0"},
        )
