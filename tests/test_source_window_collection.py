"""Synthetic provider-gated collection integration; never real AV approval."""
import subprocess
from fractions import Fraction

import pytest
from test_context_collection import revise, segment, verify
from test_context_collection import scenario as base_scenario

from talkcut.project import TalkCutError, artifact_ref
from talkcut.review import _clip
from talkcut.source_window import prepare_source_window, verify_source_window


@pytest.fixture(scope="module")
def source(tmp_path_factory):
    path = tmp_path_factory.mktemp("expanded-collection-source") / "generated.mp4"
    subprocess.run(["ffmpeg", "-nostdin", "-v", "error", "-f", "lavfi", "-i",
        "testsrc2=size=64x48:rate=59/2:duration=60", "-f", "lavfi", "-i",
        "sine=frequency=440:sample_rate=48000:duration=60", "-c:v", "libx264", "-preset", "ultrafast",
        "-c:a", "aac", str(path)], capture_output=True, check=True, timeout=30)
    return {**artifact_ref(path), "role": "screen"}


@pytest.fixture
def scenario(tmp_path, source, monkeypatch):
    return base_scenario.__wrapped__(tmp_path, source, monkeypatch)


def expand(scenario):
    ref = {key: scenario["source"][key] for key in ("path", "sha256")}
    proof = prepare_source_window(ref, ["25", "55"], ["0", "60"], scenario["root"] / "proof")
    body = verify_source_window(proof)
    observed = body["observed_interval"]
    clip = _clip(ref, tuple(map(Fraction, observed)), scenario["root"] / "expanded", scenario["deps"], source_window=proof)
    revise(scenario, 1,
           request=lambda row: row.update(source_window=proof, inputs=[clip], intervals=[observed], input_clip_hashes=[clip["clip"]["sha256"]]),
           response=lambda row: row.update(segments=[segment(*observed)]),
           context=lambda row: row.update(input_clips=[clip["clip"]]))
    return proof, observed


def test_actual_expansion_preserves_raw_segments_and_exact_requested_grid(scenario):
    _, observed = expand(scenario)
    before = scenario["collection"]["children"][:]
    result = verify(scenario)
    child = result["children"][1]
    assert child["input_interval"] == ["25", "55"]
    assert child["actual_observed_input_interval"] == observed
    assert child["observed_intervals"] == [["25", "55"]]
    assert child["segments"][0]["start"] == observed[0]
    assert observed[0] != "25"
    assert observed[0] not in {row["start"] for row in result["segments"]}
    assert result["coverage"]["input_intervals"] == result["coverage"]["observed_intervals"] == [["0", "60"]]
    assert scenario["collection"]["children"] == before


def test_missing_observation_of_expansion_is_rejected_even_with_full_grid(scenario):
    expand(scenario)
    revise(scenario, 1, response=lambda row: row.update(segments=[segment("25", "55")]))
    with pytest.raises(TalkCutError, match="omit part"):
        verify(scenario)


def test_omitted_actual_request_expansion_binding_is_rejected(scenario):
    expand(scenario)
    revise(scenario, 1, request=lambda row: row.pop("source_window"))
    with pytest.raises(TalkCutError, match="binding differs"):
        verify(scenario)


def test_expansion_does_not_allow_wrong_observed_interval(scenario):
    expand(scenario)
    revise(scenario, 1, request=lambda row: row.update(intervals=[["25", "55"]]))
    with pytest.raises(TalkCutError, match="scope differs"):
        verify(scenario)


def test_expanded_duplicate_cannot_replace_another_grid_window(scenario):
    expand(scenario)
    scenario["collection"]["children"][2] = scenario["collection"]["children"][1]
    with pytest.raises(TalkCutError, match="Duplicate"):
        verify(scenario)
