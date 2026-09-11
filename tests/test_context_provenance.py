"""Actual AV extraction provenance after an isolated provider/capability gate.

The patched gate tests no AI capability. These fixtures never certify DGIST,
editorial meaning, or acceptance; they test bytes, time and parent binding.
"""

import subprocess
from fractions import Fraction

import pytest

from talkcut.project import artifact_ref, atomic_json, read_json
from talkcut.review import _clip, verify_context_execution


@pytest.fixture(scope="module")
def sources(tmp_path_factory):
    directory = tmp_path_factory.mktemp("context-sources")
    result = []
    for index, color in enumerate(("red", "blue")):
        path = directory / f"source-{index}.mp4"
        subprocess.run(
            [
                "ffmpeg",
                "-v",
                "error",
                "-nostdin",
                "-n",
                "-f",
                "lavfi",
                "-i",
                f"color=c={color}:size=160x96:rate=10:duration=2",
                "-f",
                "lavfi",
                "-i",
                f"sine=frequency={440 + index * 220}:sample_rate=48000:duration=2",
                "-c:v",
                "libx264",
                "-preset",
                "ultrafast",
                "-c:a",
                "aac",
                str(path),
            ],
            check=True,
            capture_output=True,
            timeout=30,
        )
        result.append(artifact_ref(path))
    return result


def context(tmp_path, sources, monkeypatch, *, mutation=None):
    deps = {
        "source_hashes": {"screen": sources[0]["sha256"]},
        "code_tree_hash": "unit-scope-code",
        "contract_hash": "unit-scope-contract",
    }
    clip = _clip(sources[0], (Fraction(), Fraction(2)), tmp_path / "clip", deps)
    request = {
        "schema_version": "review-request/v1",
        "scope": "analysis",
        "source_sha256": sources[0]["sha256"],
        "input_clip_hashes": [clip["clip"]["sha256"]],
        "inputs": [clip],
        "intervals": [["0", "2"]],
        "dependencies": deps,
    }
    response = {
        "segments": [
            {
                "start": "0",
                "end": "2",
                "kind": "explanation",
                "reason": "Synthetic extraction provenance unit fixture",
            }
        ],
        "observed_modalities": ["audio", "video"],
    }
    if mutation:
        mutation(request, response, deps)
    for name, value in (
        ("request", request),
        ("response", response),
        ("capability", {"model_revision": "isolated-unit-gate"}),
    ):
        atomic_json(tmp_path / f"{name}.json", value)
    execution = {
        "model_revision": "isolated-unit-gate",
        "run_id": "unit-proposal",
        "prompt_sha256": "unit-prompt",
        "request": artifact_ref(tmp_path / "request.json"),
        "response": artifact_ref(tmp_path / "response.json"),
        "dependencies": deps,
    }
    atomic_json(tmp_path / "execution.json", execution)
    monkeypatch.setattr("talkcut.review._capability", lambda value, **kwargs: value)
    monkeypatch.setattr("talkcut.review._receipt", lambda ref: read_json(ref["path"]))
    return {
        "schema_version": "lecture-context/v1",
        "source_sha256": request["source_sha256"],
        "dependencies": deps,
        "capability": artifact_ref(tmp_path / "capability.json"),
        "receipt": artifact_ref(tmp_path / "execution.json"),
        "input_clips": [clip["clip"]],
        "segments": response["segments"],
        "proposer_run_id": "unit-proposal",
        "prompt_sha256": "unit-prompt",
    }


def test_actual_source_clips_and_intervals_provenance_control(
    tmp_path, sources, monkeypatch
):
    assert (
        verify_context_execution(context(tmp_path, sources, monkeypatch))["status"]
        == "PASS"
    )


def test_old_source_clip_cannot_be_relabelled_as_current_source(
    tmp_path, sources, monkeypatch
):
    def mutation(request, response, deps):
        request["source_sha256"] = sources[1]["sha256"]
        deps["source_hashes"]["screen"] = sources[1]["sha256"]

    result = verify_context_execution(
        context(tmp_path, sources, monkeypatch, mutation=mutation)
    )
    assert result["status"] == "UNVERIFIED"
    assert "different source media" in result["reason"]


def test_context_cannot_claim_time_outside_submitted_source_clip(
    tmp_path, sources, monkeypatch
):
    def mutation(request, response, deps):
        response["segments"][0]["end"] = "3"

    result = verify_context_execution(
        context(tmp_path, sources, monkeypatch, mutation=mutation)
    )
    assert result["status"] == "UNVERIFIED"
    assert "provider did not receive" in result["reason"]


def test_plain_clip_hashes_without_extraction_proof_are_insufficient(
    tmp_path, sources, monkeypatch
):
    def mutation(request, response, deps):
        request["inputs"] = []

    result = verify_context_execution(
        context(tmp_path, sources, monkeypatch, mutation=mutation)
    )
    assert result["status"] == "UNVERIFIED"
    assert "extraction provenance" in result["reason"]


def test_audio_only_context_does_not_authorize_editing(tmp_path, sources, monkeypatch):
    def mutation(request, response, deps):
        response["observed_modalities"] = ["audio"]

    result = verify_context_execution(
        context(tmp_path, sources, monkeypatch, mutation=mutation)
    )
    assert result["status"] == "UNVERIFIED"
    assert "Transcript-only" in result["reason"]
