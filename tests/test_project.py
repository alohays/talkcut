import json
from pathlib import Path

import pytest

from talkcut.project import (
    TalkCutError,
    atomic_json,
    init_project,
    load_project,
    project_lock,
    save_revision,
    sha256,
)


@pytest.fixture
def project(tmp_path):
    a, b = tmp_path / "a.mp4", tmp_path / "b.mp4"
    a.write_bytes(b"source-a")
    b.write_bytes(b"source-b")
    path = tmp_path / "project"
    init_project(path, a, b)
    return path


def test_preservation_reopen_and_refuse_overwrite(project):
    state = load_project(project)
    assert state["owner_acceptance"] == "pending"
    for source in state["sources"].values():
        assert sha256(source["path"]) == sha256(source["original_path"])
        assert Path(source["path"]).stat().st_mode & 0o222 == 0
    with pytest.raises(TalkCutError, match="never overwritten"):
        init_project(project, "unused", "unused")


def test_source_replacement_is_not_valid_cache(project):
    source = Path(load_project(project)["sources"]["screen"]["path"])
    source.chmod(0o644)
    source.write_bytes(b"new-bytes")
    with pytest.raises(TalkCutError) as error:
        load_project(project)
    assert error.value.code == "SOURCE_CHANGED"


def test_revision_conflict_preserves_event_chain(project):
    with project_lock(project):
        state = load_project(project)
        save_revision(project, state, 0, "test", {"test_only": True})
        with pytest.raises(TalkCutError) as error:
            save_revision(project, state, 0, "overwrite", {})
        assert error.value.code == "REVISION_CONFLICT"
    reopened = load_project(project)
    assert reopened["revision"] == 1
    assert [event["action"] for event in reopened["events"]] == ["test"]


def test_disk_failure_preserves_previous_success(project, monkeypatch):
    import talkcut.project as module

    target = project / "success.json"
    atomic_json(target, {"previous_success": True})
    original = target.read_bytes()

    def no_space(*args):
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(module.os, "replace", no_space)
    with pytest.raises(OSError):
        atomic_json(target, {"partial": True})
    assert target.read_bytes() == original
    assert not list(project.glob(".success.json.*"))


def test_corrupt_json_and_unknown_major_rejected(project):
    target = project / "project.json"
    target.write_text('{"broken":')
    with pytest.raises(TalkCutError) as error:
        load_project(project)
    assert error.value.code == "INVALID_ARTIFACT"
    target.write_text(json.dumps({"schema_version": "talkcut-project/v99"}))
    with pytest.raises(TalkCutError) as error:
        load_project(project)
    assert error.value.code == "UNSUPPORTED_SCHEMA"


def test_nan_cannot_become_valid_artifact(tmp_path):
    with pytest.raises(ValueError):
        atomic_json(tmp_path / "nan.json", {"value": float("nan")})
