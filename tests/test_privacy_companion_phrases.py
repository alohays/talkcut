"""Private review metadata phrases do not spread to public code references."""

import hashlib
import io
import json
import tarfile
from pathlib import Path

import pytest
from test_privacy_checks import (
    archive_bytes,
    commit,
    publication_input,
)
from test_privacy_checks import (
    repository as repository_fixture,
)

from talkcut import privacy_checks as privacy
from talkcut.project import artifact_ref, atomic_json, init_project

repository = repository_fixture
PRIVATE_NOTE = "Invented companion note about the private task must not appear in a publication."
PUBLIC_NOTE = "This authored public mathematical fixture describes the identity function on integers."


def companion_fixture(tmp_path, contents=None):
    source = tmp_path / "registered-original.bin"
    source.write_bytes(b"Synthetic source identity without actual audiovisual content")
    directory = tmp_path / "task"
    project = init_project(directory, source, source)
    sources = {role: row["sha256"] for role, row in project["sources"].items()}
    companion = directory / "capability" / "companion.json"
    atomic_json(companion, {"note": PRIVATE_NOTE} if contents is None else contents)
    parent = directory / "evidence" / "parent.json"
    atomic_json(parent, {"runner": artifact_ref(companion)})
    atomic_json(directory / "checkpoint.local.json", {
        "source_sha256": sources["screen"], "parent": artifact_ref(parent),
    })
    return directory, sources, parent, companion


def publication(parts, repository, tmp_path, destination=None, text=None):
    raw_ref = publication_input(repository, tmp_path)
    raw_path = Path(raw_ref["path"])
    raw = json.loads(raw_path.read_bytes())
    payload = ("Public surrounding text.\n" + (text or PRIVATE_NOTE) + "\nMore public text.\n").encode()
    if destination in {"pr_body", "release_body"}:
        body = Path(raw[destination]["path"])
        body.write_bytes(payload)
        raw[destination] = artifact_ref(body)
    elif destination == "wheel":
        row = next(row for row in raw["archives"] if row["name"].endswith(".whl"))
        path = Path(row["path"])
        path.write_bytes(archive_bytes({"package/data/note.txt": payload}))
        row.update(artifact_ref(path))
    elif destination == "sdist":
        row = next(row for row in raw["archives"] if row["name"].endswith(".tar.gz"))
        path = Path(row["path"])
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
            member = tarfile.TarInfo("fixture/docs/note.txt")
            member.size = len(payload)
            archive.addfile(member, io.BytesIO(payload))
        path.write_bytes(buffer.getvalue())
        row.update(artifact_ref(path))
    atomic_json(raw_path, raw)
    result = privacy.verify_release_privacy(artifact_ref(raw_path), repository,
        project_dir=parts[0], expected_source_hashes=parts[1])
    atomic_json(tmp_path / "observed-publication-result.json", result)
    return result


@pytest.mark.parametrize("destination", ["pr_body", "release_body", "wheel", "sdist"])
def test_copied_companion_note_fails_actual_publication_scan(tmp_path, repository, destination):
    parts = companion_fixture(tmp_path)
    result = publication(parts, repository, tmp_path, destination)
    assert result["status"] == "FAIL"
    assert any(row["kind"] == "protected_transcript_phrase"
               and row["matched_sha256"] == hashlib.sha256(PRIVATE_NOTE.encode()).hexdigest()
               for row in result["findings"])
    assert PRIVATE_NOTE not in json.dumps(result["findings"])
    assert result["user_ready"] is False
    assert result["coverage"]["private_corpus_complete"] is None


@pytest.mark.parametrize("contents", [
    {"note": PRIVATE_NOTE}, {"context": {"note": PRIVATE_NOTE}},
    {"observations": [{"note": PRIVATE_NOTE}]},
])
def test_review_companion_preserves_complete_identity_and_nested_phrases(tmp_path, repository, contents):
    parts = companion_fixture(tmp_path, contents)
    before = {str(path): artifact_ref(path) for path in parts[0].rglob("*") if path.is_file()}
    known, phrases, graph = privacy._known_private_inventory(parts[0], parts[1], repository)
    assert known[artifact_ref(parts[3])["sha256"]] == "review"
    assert PRIVATE_NOTE in phrases
    inventory = privacy.build_private_inventory(parts[0], parts[1], repository)
    rows = {row["path"]: row for row in inventory["entries"]}
    assert set(before) <= rows.keys()
    assert all(rows[path]["sha256"] == ref["sha256"] for path, ref in before.items())
    assert graph["completeness"] == inventory["classification_status"] == "UNVERIFIED"
    assert all(artifact_ref(Path(path)) == ref for path, ref in before.items())


@pytest.mark.parametrize("extension", [".py", ".json"])
def test_public_code_or_fixture_reference_does_not_inherit_phrase_privacy(tmp_path, repository, extension):
    target = repository / "tests" / ("authored_fixture" + extension)
    target.parent.mkdir()
    target.write_text(('"""' + PUBLIC_NOTE + '"""\nvalue = 42\n') if extension == ".py"
                      else json.dumps({"description": PUBLIC_NOTE}) + "\n")
    commit(repository)
    parts = companion_fixture(tmp_path)
    copied = parts[0] / "runtime" / target.name
    copied.parent.mkdir()
    copied.write_bytes(target.read_bytes())
    atomic_json(parts[3], {"note": PRIVATE_NOTE, "public_fixture": artifact_ref(copied)})
    atomic_json(parts[2], {"runner": artifact_ref(parts[3])})
    atomic_json(parts[0] / "checkpoint.local.json", {
        "source_sha256": parts[1]["screen"], "parent": artifact_ref(parts[2]),
    })
    known, phrases, graph = privacy._known_private_inventory(parts[0], parts[1], repository)
    assert PRIVATE_NOTE in phrases and PUBLIC_NOTE not in phrases
    assert artifact_ref(target)["sha256"] not in known
    assert any(row["path"] == str(copied) and row["classification"] == "UNCLASSIFIED"
               for row in graph["public_work_candidates"])
    result = publication(parts, repository, tmp_path, "pr_body", PUBLIC_NOTE)
    assert not result["findings"]
    assert result["status"] == "UNVERIFIED"
    assert result["user_ready"] is False


def test_unrelated_outside_note_is_not_inferred_private(tmp_path, repository):
    outside = tmp_path / "unrelated.json"
    atomic_json(outside, {"note": PUBLIC_NOTE})
    parts = companion_fixture(tmp_path)
    known, phrases, _ = privacy._known_private_inventory(parts[0], parts[1], repository)
    assert artifact_ref(outside)["sha256"] not in known
    assert PUBLIC_NOTE not in phrases
    result = publication(parts, repository, tmp_path, "release_body", PUBLIC_NOTE)
    assert not result["findings"] and result["status"] == "UNVERIFIED"


def test_private_phrase_protection_does_not_require_invented_transcript_role(tmp_path, repository):
    parts = companion_fixture(tmp_path, {"schema_version": "invented-companion-metadata/v1", "note": PRIVATE_NOTE})
    known, phrases, graph = privacy._known_private_inventory(parts[0], parts[1], repository)
    assert known[artifact_ref(parts[3])["sha256"]] == "review"
    assert PRIVATE_NOTE in phrases
    assert graph["completeness"] == "UNVERIFIED"
    assert not graph["native_runtime_request_observations"]
    assert not graph["auxiliary_runtime_requests"]
