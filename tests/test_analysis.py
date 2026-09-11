"""Authored policy examples, not claims of human-labelled DGIST ground truth."""

import shutil
import subprocess

import pytest

from talkcut.analysis import analyze_source, detect_silence
from talkcut.project import TalkCutError, artifact_ref, sha256


@pytest.fixture
def source(tmp_path):
    path = tmp_path / "explicit-policy-fixture.txt"
    path.write_text("Authored policy fixture; this is not real lecture evidence.")
    return {"path": str(path), "sha256": sha256(path), "role": "screen"}


def acoustic(source, spans=()):
    return {
        "source_sha256": source["sha256"],
        "domain": ["0", "100"],
        "completed": True,
        "status": "PASS",
        "run_id": "fixture-acoustic",
        "intervals": [{"start": str(a), "end": str(b)} for a, b in spans],
    }


def context(source, kind, positive=None):
    return {
        "schema_version": "lecture-context/v1",
        "source_sha256": source["sha256"],
        "test_only": True,
        "proposer_run_id": "fixture-proposer",
        "segments": [
            {
                "start": "0",
                "end": "100",
                "kind": kind,
                "reason": "Authored test case describes this activity throughout the interval.",
                "positive_evidence": positive or {},
            }
        ],
    }


def test_positive_silence_requires_acoustic_and_context_evidence(source):
    observation = context(
        source,
        "disposable_pause",
        {
            "no_speech": True,
            "no_learning_activity": True,
            "complete_context_checked": True,
        },
    )
    report = analyze_source(
        source,
        ["0", "100"],
        acoustic(source, [(20, 30)]),
        observation,
        source_kind="fixture",
    )
    assert report["candidates"][0]["policy_action"] == "auto_apply"
    assert report["test_only"] is True
    assert report["status"] == "ANALYZED"
    assert report["owner_acceptance"] == "pending"


def test_positive_preparation_and_disfluency_have_different_authorization(source):
    preparation = context(
        source,
        "preparation",
        {
            "before_first_substantive_content": True,
            "contains_introduction_or_instruction": False,
        },
    )
    report = analyze_source(
        source, ["0", "100"], acoustic(source), preparation, source_kind="fixture"
    )
    assert report["candidates"][0]["policy_action"] == "auto_apply"
    stutter = context(source, "disfluency")
    report = analyze_source(
        source, ["0", "100"], acoustic(source), stutter, source_kind="fixture"
    )
    assert report["candidates"][0]["policy_action"] == "requires_review"


@pytest.mark.parametrize(
    "kind",
    [
        "demo",
        "question_wait",
        "reading",
        "execution_wait",
        "negation",
        "correction",
        "emphasis",
        "introduction",
        "assignment",
        "definition",
    ],
)
def test_learning_activities_and_meaningful_statements_are_protected(source, kind):
    report = analyze_source(
        source,
        ["0", "100"],
        acoustic(source, [(20, 30)]),
        context(source, kind),
        source_kind="fixture",
    )
    assert report["candidates"][0]["policy_action"] == "keep"
    assert report["protected_intervals"][0]["kind"] == kind


@pytest.mark.parametrize(
    "missing", ["no_speech", "no_learning_activity", "complete_context_checked"]
)
def test_missing_positive_evidence_cannot_be_replaced_by_silence_duration(
    source, missing
):
    evidence = {
        "no_speech": True,
        "no_learning_activity": True,
        "complete_context_checked": True,
    }
    evidence.pop(missing)
    report = analyze_source(
        source,
        ["0", "100"],
        acoustic(source, [(1, 99)]),
        context(source, "disposable_pause", evidence),
        source_kind="fixture",
    )
    assert report["candidates"][0]["policy_action"] == "keep"


def test_absent_and_empty_analysis_are_unavailable_not_no_safe_cuts(source):
    for supplied in (None, {**context(source, "lecture"), "segments": []}):
        report = analyze_source(
            source,
            ["0", "100"],
            acoustic(source, [(20, 30)]),
            supplied,
            source_kind="fixture",
        )
        assert report["status"] == "ANALYSIS_UNAVAILABLE"
        assert report["edit_disposition"] == "ANALYSIS_UNAVAILABLE"
        assert report["segments"]
        assert report["candidates"][0]["policy_action"] == "keep"


def test_transcript_alone_cannot_authorize_deletion(source):
    transcript = {
        "schema_version": "transcript/v1",
        "source_sha256": source["sha256"],
        "segments": [{"start": "0", "end": "100", "text": ""}],
    }
    report = analyze_source(
        source,
        ["0", "100"],
        acoustic(source, [(20, 30)]),
        source_kind="fixture",
        transcript=transcript,
    )
    assert report["status"] == "ANALYSIS_UNAVAILABLE"
    assert report["candidates"][0]["policy_action"] == "keep"


def test_other_source_and_out_of_domain_context_are_rejected(source):
    changed = acoustic(source)
    changed["source_sha256"] = "wrong"
    with pytest.raises(TalkCutError, match="another source"):
        analyze_source(source, ["0", "100"], changed, source_kind="fixture")
    invalid = context(source, "demo")
    invalid["segments"][0]["end"] = "101"
    with pytest.raises(TalkCutError, match="invalid time"):
        analyze_source(
            source, ["0", "100"], acoustic(source), invalid, source_kind="fixture"
        )


@pytest.mark.skipif(not shutil.which("ffmpeg"), reason="FFmpeg required")
def test_real_full_audio_decode_detects_known_silence_but_cannot_auto_cut(tmp_path):
    path = tmp_path / "tone-and-silence.wav"
    subprocess.run(
        [
            "ffmpeg",
            "-v",
            "error",
            "-f",
            "lavfi",
            "-i",
            "sine=frequency=1000:sample_rate=16000:duration=1",
            "-f",
            "lavfi",
            "-i",
            "anullsrc=r=16000:cl=mono:d=3",
            "-filter_complex",
            "[0:a][1:a]concat=n=2:v=0:a=1[a]",
            "-map",
            "[a]",
            str(path),
        ],
        check=True,
    )
    registered = {**artifact_ref(path), "role": "screen"}
    result = detect_silence(
        registered, 0, ["0", "4"], tmp_path / "acoustic", min_seconds=1
    )
    assert result["completed"] is True
    assert result["intervals"]
    report = analyze_source(registered, ["0", "4"], result)
    assert report["status"] == "ANALYSIS_UNAVAILABLE"
    assert report["candidates"][0]["policy_action"] == "keep"
    assert sha256(path) == registered["sha256"]


def test_automatic_authorization_recomputes_policy_not_recorded_action(
    source, tmp_path, monkeypatch
):
    from talkcut.analysis import authorize_automatic_candidate
    from talkcut.project import atomic_json

    # Isolate deterministic policy re-execution after context provenance;
    # actual provider provenance has separate negative/integration coverage.
    monkeypatch.setattr(
        "talkcut.review.verify_context_execution", lambda value: {"status": "PASS"}
    )
    raw_acoustic = {**acoustic(source, [(20, 30)]), "source_path": source["path"]}
    acoustic_path = tmp_path / "acoustic.json"
    atomic_json(acoustic_path, raw_acoustic)
    acoustic_value = {**raw_acoustic, "artifact_ref": artifact_ref(acoustic_path)}
    ctx = context(
        source,
        "disposable_pause",
        {
            "no_speech": True,
            "no_learning_activity": True,
            "complete_context_checked": True,
        },
    )
    ctx.update(
        {
            "test_only": False,
            "receipt": artifact_ref(acoustic_path),
            "capability": artifact_ref(acoustic_path),
        }
    )
    report = analyze_source(source, ["0", "100"], acoustic_value, ctx)
    analysis_path = tmp_path / "source-analysis.json"
    atomic_json(analysis_path, report)
    inspection_path = tmp_path / "inspection.json"
    atomic_json(
        inspection_path,
        {"sha256": source["sha256"], "video": {"coverage": ["0", "100"]}},
    )
    plan = {
        "source_hashes": report["source_hashes"],
        "protected_intervals": report["protected_intervals"],
        "inspection_refs": {"screen": artifact_ref(inspection_path)},
        "timing": {"screen_origin": "0"},
    }
    candidate = report["candidates"][0]
    assert (
        authorize_automatic_candidate(artifact_ref(analysis_path), candidate, plan)[
            "recomputed_policy_action"
        ]
        == "auto_apply"
    )
    with pytest.raises(TalkCutError, match="differs from recomputed"):
        authorize_automatic_candidate(
            artifact_ref(analysis_path), {**candidate, "end": "31"}, plan
        )
    report["context"]["segments"][0]["positive_evidence"]["no_learning_activity"] = (
        False
    )
    atomic_json(analysis_path, report)
    with pytest.raises(TalkCutError, match="source policy recomputation"):
        authorize_automatic_candidate(artifact_ref(analysis_path), candidate, plan)
