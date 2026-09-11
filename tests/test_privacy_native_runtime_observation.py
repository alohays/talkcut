"""Current request bytes never certify an executed native/capability run."""

import json
import shutil
from pathlib import Path

import pytest
from test_privacy_runtime_alias import compiled as compiled_fixture
from test_privacy_runtime_alias import fixture

from talkcut import privacy_checks as privacy
from talkcut.native_provenance import verify_native_bundle
from talkcut.project import TalkCutError, artifact_ref, atomic_json

compiled = compiled_fixture


def native_fixture(tmp_path, compiled):
    parts = fixture(tmp_path, compiled)
    value = json.loads(parts[2].read_bytes())
    value.update(
        schema_version="local-audio-calibration-request/v1",
        input_modality="audio",
        video_input=None,
    )
    atomic_json(parts[2], value)
    atomic_json(
        parts[0] / "checkpoint.local.json",
        {"source_sha256": parts[1]["screen"], "request": artifact_ref(parts[2])},
    )
    return parts


def collect(parts):
    return privacy.build_private_inventory(
        parts[0],
        parts[1],
        Path.cwd(),
        native_runtime_request_observations=[artifact_ref(parts[2])],
    )


def test_current_library_bytes_and_private_parent_are_not_execution_approval(
    tmp_path, compiled
):
    parts = native_fixture(tmp_path, compiled)
    result = collect(parts)
    entries = {row["path"]: row for row in result["entries"]}
    assert entries[str(parts[2])]["classification"] == "review"
    for p in parts[3:]:
        assert entries[str(p)]["classification"] == "UNCLASSIFIED"
    graph = result["known_graph"]
    assert (
        not graph["auxiliary_runtime_requests"]
        and not graph["auxiliary_runtime_reobservations"]
    )
    row = graph["native_runtime_request_observations"][0]
    assert row["claim_status"] == row["execution_status"] == "UNVERIFIED"
    assert (
        row["history_supported"] is False
        and row["observation_role"] == "current_native_runtime_request_bytes"
    )
    assert (
        row["request"] == artifact_ref(parts[2])
        and len(row["libraries"][0]["hops"]) == 2
    )
    known, phrases, _ = privacy._known_private_inventory(
        parts[0],
        parts[1],
        Path.cwd(),
        native_runtime_request_observations=[artifact_ref(parts[2])],
    )
    assert known[artifact_ref(parts[2])["sha256"]] == "review"
    assert json.loads(parts[2].read_bytes())["private_note"] in phrases
    assert result["classification_status"] == "UNVERIFIED"
    # A current request is not an executed case/run, even after byte observation.
    with pytest.raises(TalkCutError, match="Legacy native records"):
        verify_native_bundle(artifact_ref(parts[2]), artifact_ref(parts[2]), {}, {})
    with pytest.raises(TalkCutError, match="Immutable"):
        privacy._auxiliary_json(parts[2], Path.cwd(), set(parts[1].values()))


@pytest.mark.parametrize(
    "damage",
    [
        "wrong_schema",
        "missing_schema",
        "video_modality",
        "video_input",
        "nested_review",
        "nested_transcript",
        "empty_libraries",
        "duplicate_library",
        "bad_parent_hash",
        "parent_alias",
        "private_namespace",
        "registered_identity",
        "history_locator",
        "target_changed",
        "target_not_library",
        "link_cycle",
        "dotdot",
        "missing_parent",
    ],
)
def test_native_current_role_rejects_substitution_and_scope_changes(
    tmp_path, compiled, damage
):
    parts = native_fixture(tmp_path, compiled)
    directory, sources, request, first, middle, target = parts
    value = json.loads(request.read_bytes())
    ref = artifact_ref(request)
    if damage == "wrong_schema":
        value["schema_version"] = "review-request/v1"
    elif damage == "missing_schema":
        value.pop("schema_version")
    elif damage == "video_modality":
        value["input_modality"] = "video"
    elif damage == "video_input":
        value["video_input"] = {
            "path": str(target),
            "sha256": artifact_ref(target)["sha256"],
        }
    elif damage == "nested_review":
        value["nested"] = {"schema_version": "review-request/v1"}
    elif damage == "nested_transcript":
        value["nested"] = {
            "schema_version": "transcript/v1",
            "source_sha256": sources["screen"],
        }
    elif damage == "empty_libraries":
        value["runtime_libraries"] = []
    elif damage == "duplicate_library":
        value["runtime_libraries"] *= 2
    elif damage == "bad_parent_hash":
        ref["sha256"] = "f" * 64
    elif damage == "parent_alias":
        alias = request.with_name("request-alias")
        alias.symlink_to(request.name)
        ref["path"] = str(alias)
    elif damage == "private_namespace":
        moved = directory / "transcripts/request.json"
        moved.parent.mkdir()
        shutil.copyfile(request, moved)
        ref = artifact_ref(moved)
    elif damage == "registered_identity":
        sources = {role: ref["sha256"] for role in sources}
    elif damage == "history_locator":
        ref = {"origin": ref, "snapshot": ref}
    elif damage == "target_changed":
        target.write_bytes(target.read_bytes() + b"changed")
    elif damage == "target_not_library":
        target.write_bytes(b"not a shared object")
        value["runtime_libraries"][0]["sha256"] = artifact_ref(target)["sha256"]
        value["runtime_libraries"][0]["bytes"] = target.stat().st_size
    elif damage == "link_cycle":
        middle.unlink()
        middle.symlink_to(first.name)
    elif damage == "dotdot":
        middle.unlink()
        middle.symlink_to("../runtime/" + target.name)
    elif damage == "missing_parent":
        request.unlink()
    if damage in {
        "wrong_schema",
        "missing_schema",
        "video_modality",
        "video_input",
        "nested_review",
        "nested_transcript",
        "empty_libraries",
        "duplicate_library",
        "target_not_library",
    }:
        atomic_json(request, value)
        ref = artifact_ref(request)
    with pytest.raises(TalkCutError):
        privacy._native_runtime_request_inventory(
            [ref], directory, Path.cwd(), set(sources.values())
        )


def test_native_role_does_not_grant_alias_authority_to_other_parent(tmp_path, compiled):
    parts = native_fixture(tmp_path, compiled)
    diagnostic = parts[0] / "evidence/diagnostic.json"
    diagnostic.parent.mkdir()
    atomic_json(
        diagnostic, {"ref": json.loads(parts[2].read_bytes())["runtime_libraries"][0]}
    )
    atomic_json(
        parts[0] / "checkpoint.local.json",
        {
            "source_sha256": parts[1]["screen"],
            "request": artifact_ref(parts[2]),
            "diagnostic": artifact_ref(diagnostic),
        },
    )
    with pytest.raises(TalkCutError, match="symlink"):
        collect(parts)


def test_native_role_cannot_replace_auxiliary_history_reader(tmp_path, compiled):
    parts = native_fixture(tmp_path, compiled)
    with pytest.raises(TalkCutError, match="Immutable"):
        privacy.build_private_inventory(
            parts[0],
            parts[1],
            Path.cwd(),
            auxiliary_runtime_requests=[artifact_ref(parts[2])],
        )
    original = artifact_ref(parts[2])
    saved = parts[2].with_name("saved-request")
    shutil.copyfile(parts[2], saved)
    value = json.loads(parts[2].read_bytes())
    value["new_note"] = "changed current request"
    atomic_json(parts[2], value)
    with pytest.raises(TalkCutError):
        privacy.build_private_inventory(
            parts[0],
            parts[1],
            Path.cwd(),
            native_runtime_request_observations=[original],
            auxiliary_metadata_history=[
                {"original": original, "snapshot": artifact_ref(saved)}
            ],
        )
