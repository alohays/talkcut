"""Practical draft tests use generated recordings, never private lecture media."""

import copy
import subprocess
from pathlib import Path

import pytest

from talkcut.__main__ import execute, parser_for_cli
from talkcut.draft import build_draft, evaluate_draft, validate_draft_plan
from talkcut.media import inspect_source
from talkcut.plan import build_plan, decide, set_audio_profile
from talkcut.project import (
    TalkCutError,
    init_project,
    load_project,
    project_lock,
    save_revision,
    store_artifact,
    verified_json,
)
from talkcut.timeline import as_fraction
from talkcut.workflow import render_project


@pytest.fixture(scope="module")
def recordings(tmp_path_factory):
    root = tmp_path_factory.mktemp("draft-recordings")
    result = {}
    for role, frequency in (("screen", 440), ("speaker", 880)):
        path = root / f"{role}.mp4"
        subprocess.run([
            "ffmpeg", "-nostdin", "-v", "error", "-n", "-f", "lavfi", "-i",
            "testsrc2=size=160x96:rate=10:duration=6", "-f", "lavfi", "-i",
            f"sine=frequency={frequency}:sample_rate=44100:duration=6.2",
            "-c:v", "libx264", "-preset", "ultrafast", "-c:a", "aac", str(path),
        ], check=True, capture_output=True, timeout=30)
        result[role] = (path, inspect_source(path, root / f"inspection-{role}", True))
    return result


@pytest.fixture
def project(tmp_path, recordings):
    directory = tmp_path / "project"
    init_project(directory, recordings["screen"][0], recordings["speaker"][0])
    with project_lock(directory):
        value = load_project(directory)
        value["inspections"] = {role: store_artifact(directory, "inspections", pair[1]) for role, pair in recordings.items()}
        save_revision(directory, value, value["revision"], "attach_actual_fixture_inspection", {})
    return directory


def build(project, **overrides):
    return build_draft(project, **{
        "audio_source": "screen", "speaker_offset": "0", "audio_offset": "0",
        "trim_start": "1/2", "trim_end": "1/2", "reason": "Explicit preparation and ending trim",
        "expected_revision": load_project(project)["revision"], **overrides,
    })


@pytest.mark.parametrize("audio_source", ["screen", "speaker"])
def test_actual_draft_render_evaluate_and_restore(project, audio_source):
    old = build_plan(project, diagnostic=True)
    set_audio_profile(project, "-1", "Retain chosen constant gain", old["project_revision"])
    before = load_project(project)
    result = build(project, audio_source=audio_source, speaker_offset="1/10")
    plan = verified_json(result["plan"])
    timeline = verified_json(result["timeline"])
    assert plan["parent"] == before["active_plan"]
    assert not plan["test_only"] and plan["timing"]["status"] == "ASSUMED_COMMON_CLOCK"
    assert plan["layout"] == before["layout"] and plan["audio_processing"]["gain_db"] == "-1"
    assert timeline["frame_count"] == 50 and timeline["sample_count"] == 220500
    assert len(timeline["retained"]) == 1 and as_fraction(timeline["retained"][0]["source_start"]) == FractionHalf
    rendered = render_project(project, "draft", preset="ultrafast")
    output = Path(rendered["output"]["path"])
    saved = output.read_bytes()
    evaluated = evaluate_draft(project)
    assert evaluated["status"] == "DRAFT_TECHNICALLY_READY"
    assert evaluated["technical"]["status"] == "PASS"
    assert evaluated["technical"]["frame_count"] == 50
    assert evaluated["ai_review"] == "UNVERIFIED" and evaluated["owner_acceptance"] == "pending"
    native = verified_json(rendered["native_render"])
    assert native["sources"]["audio"]["sha256"] == load_project(project)["sources"][audio_source]["sha256"]
    assert native["layout"]["canvas_width"] == 160 and native["layout"]["canvas_height"] == 96
    with pytest.raises(TalkCutError, match="cannot render a master"):
        render_project(project, "master", preset="ultrafast")
    restored = decide(project, plan["candidates"][0]["id"], "restore", load_project(project)["revision"])
    assert verified_json(restored["timeline"])["frame_count"] == 55
    assert output.read_bytes() == saved and verified_json(result["plan"]) == plan
    with pytest.raises(TalkCutError, match="Render the draft"):
        evaluate_draft(project)


FractionHalf = as_fraction("1/2")


@pytest.mark.parametrize("field,value", [
    ("audio_source", "both"), ("speaker_offset", "NaN"), ("audio_offset", "1/0"),
    ("speaker_offset", "6"), ("audio_offset", "-6"), ("speaker_offset", "1/1000001"),
    ("audio_offset", "9" * 65), ("trim_start", "-1"), ("trim_end", "6"),
    ("trim_start", "11/2"), ("reason", " "), ("expected_revision", -1),
])
def test_invalid_draft_does_not_change_project(project, field, value):
    before = (project / "project.json").read_bytes()
    with pytest.raises(TalkCutError):
        build(project, **{field: value})
    assert (project / "project.json").read_bytes() == before


def test_audio_coverage_cannot_be_filled_by_silence(project):
    before = (project / "project.json").read_bytes()
    with pytest.raises(ValueError, match="AUDIO_UNCOVERED"):
        build(project, audio_offset="1", trim_start="0")
    assert (project / "project.json").read_bytes() == before


@pytest.mark.parametrize("fault", ["missing", "decode", "source"])
def test_requires_complete_current_inspections(project, fault):
    with project_lock(project):
        value = load_project(project)
        if fault == "missing":
            value["inspections"] = {}
        else:
            inspection = verified_json(value["inspections"]["speaker"])
            if fault == "decode":
                inspection["full_decode"] = False
            else:
                inspection["sha256"] = "0" * 64
            value["inspections"]["speaker"] = store_artifact(project, "fault", inspection)
        save_revision(project, value, value["revision"], "negative_inspection_fixture", {})
    with pytest.raises(TalkCutError, match="Inspect|complete"):
        build(project)


def test_draft_profile_refuses_legacy_and_internal_edits(project):
    build_plan(project, diagnostic=True)
    with pytest.raises(TalkCutError, match="explicit common-clock"):
        render_project(project, "draft")
    result = build(project)
    plan = verified_json(result["plan"])
    changed = copy.deepcopy(plan)
    changed["candidates"][0].update(start="1", end="2")
    with pytest.raises(TalkCutError, match="internal deletion"):
        validate_draft_plan(load_project(project), changed)


def test_cli_explicit_options_and_schema_protection(project):
    args = parser_for_cli().parse_args([
        "draft", "build", str(project), "--audio-source", "speaker", "--speaker-offset", "0",
        "--audio-offset", "0", "--trim-start", "0", "--trim-end", "0", "--reason", "Keep all",
        "--expected-revision", str(load_project(project)["revision"]), "--json",
    ])
    result, code = execute(args)
    assert code == 0 and result["applied_cuts"] == 0
    assert parser_for_cli().parse_args(["render", str(project), "--profile", "draft"]).profile == "draft"
    from talkcut.formal_schemas import formal_schema_types

    assert "draft-evaluation/v1" in formal_schema_types()


def test_evaluation_rejects_changed_output(project):
    build(project)
    rendered = render_project(project, "draft", preset="ultrafast")
    Path(rendered["output"]["path"]).write_bytes(b"changed output")
    with pytest.raises(TalkCutError, match="changed before evaluation"):
        evaluate_draft(project)
