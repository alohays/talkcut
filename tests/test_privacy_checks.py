"""Actual local Git/history and in-memory publication archive privacy cases.

Tokens and transcripts below are generated test strings, never credentials or
private user media. No test publishes a commit or invokes a real remote API.
"""

import gzip
import hashlib
import io
import json
import shutil
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path

import pytest

import talkcut.privacy_checks as privacy
from talkcut.project import TalkCutError, artifact_ref, atomic_json, init_project


def git(root, *args):
    return subprocess.run(["git", "-C", str(root), *args], capture_output=True, check=True).stdout.decode().strip()


def commit(root, message="public fixture"):
    git(root, "add", "-A")
    git(root, "-c", "user.name=Public Fixture", "-c", "user.email=fixture@example.invalid", "commit", "-m", message)


@pytest.fixture
def repository(tmp_path):
    root = tmp_path / "repository"
    root.mkdir()
    git(root, "init", "--initial-branch=main")
    (root / "README.md").write_text("Public mathematical fixture source\n")
    commit(root)
    return root


def archive_bytes(items):
    data = io.BytesIO()
    with zipfile.ZipFile(data, "w") as archive:
        for name, value in items.items():
            archive.writestr(name, value)
    return data.getvalue()


def publication_input(root, directory):
    wheel, sdist = directory / "talkcut-fixture.whl", directory / "talkcut-fixture.tar.gz"
    wheel.write_bytes(archive_bytes({"talkcut/__init__.py": b'__version__ = "0"\n'}))
    contents = io.BytesIO()
    with tarfile.open(fileobj=contents, mode="w:gz") as archive:
        payload = b"Public package source\n"
        member = tarfile.TarInfo("talkcut-fixture/README.md")
        member.size = len(payload)
        archive.addfile(member, io.BytesIO(payload))
    sdist.write_bytes(contents.getvalue())
    pr, release = directory / "pr-body.txt", directory / "release-body.txt"
    pr.write_text("Public synthetic fixture PR description\n")
    release.write_text("Public synthetic fixture alpha release description\n")
    corpus = directory / "corpus.json"
    atomic_json(corpus, {"schema_version": "private-exclusion-corpus/v1",
                         "file_hashes": [{"sha256": hashlib.sha256(b"excluded synthetic recording").hexdigest(), "kind": "media"}]})
    raw = directory / "publication.json"
    atomic_json(raw, {"schema_version": "publication-privacy-input/v1", "expected_head": git(root, "rev-parse", "HEAD"),
                      "archives": [{**artifact_ref(wheel), "name": wheel.name}, {**artifact_ref(sdist), "name": sdist.name}],
                      "release_assets": [], "pr_body": artifact_ref(pr), "release_body": artifact_ref(release),
                      "private_corpus": artifact_ref(corpus)})
    return artifact_ref(raw)


def test_deleted_credential_is_detected_in_actual_reachable_history(repository):
    token = "ghp_" + "A" * 36
    private = repository / "removed-token.txt"
    private.write_text(token)
    commit(repository, "Add generated privacy test material")
    private.unlink()
    commit(repository, "Remove generated privacy test material")
    scanner, traces = privacy.Scan({}, []), []
    result = privacy._git_inventory(repository, git(repository, "rev-parse", "HEAD"), scanner, traces)
    assert len(result["reachable_commits"]) == 3
    assert scanner.credentials == {hashlib.sha256(token.encode()).hexdigest()}
    assert any(item["kind"] == "github_token" for item in scanner.findings)
    assert all(token not in json.dumps(item) for item in scanner.findings)
    assert not scanner.unknown and all(item["exit_code"] == 0 for item in traces)


def test_commit_message_is_scanned_as_public_content(repository):
    token = "AKIA" + "A" * 16
    (repository / "another.txt").write_text("Another public file")
    commit(repository, "Generated fixture token " + token)
    scanner = privacy.Scan({}, [])
    privacy._git_inventory(repository, git(repository, "rev-parse", "HEAD"), scanner, [])
    assert scanner.credentials


def test_git_symlink_is_not_followed_or_counted_as_fully_scanned(repository):
    (repository / "symlink").symlink_to("README.md")
    commit(repository)
    scanner = privacy.Scan({}, [])
    privacy._git_inventory(repository, git(repository, "rev-parse", "HEAD"), scanner, [])
    assert any("symlink" in item["reason"] for item in scanner.unknown)


def test_unknown_binary_never_becomes_zero_private_files():
    scanner = privacy.Scan({}, [])
    scanner.payload(b"\x89PNG\x00synthetic unknown image", "asset:image")
    assert scanner.unknown and not scanner.findings


def test_known_private_media_hash_is_detected_without_decoding_or_leaking_bytes():
    content = b"\x00generated private media bytes"
    digest = hashlib.sha256(content).hexdigest()
    scanner = privacy.Scan({digest: "media"}, [])
    scanner.payload(content, "archive!recording.mp4")
    assert scanner.media == {digest}
    assert scanner.findings[0]["kind"] == "private_media"
    assert content.decode("latin1") not in json.dumps(scanner.findings)


def test_nested_zip_and_gzip_are_actually_scanned():
    token = "sk-proj-" + "B" * 48
    nested = archive_bytes({"inner.txt": token.encode()})
    outer = archive_bytes({"nested.gz": gzip.compress(nested)})
    scanner = privacy.Scan({}, [])
    scanner.payload(outer, "asset:archive.zip")
    assert scanner.credentials and not scanner.unknown
    assert len(scanner.units) == 4


def test_tar_symlink_and_zip_traversal_remain_unverified():
    tar = io.BytesIO()
    with tarfile.open(fileobj=tar, mode="w") as archive:
        link = tarfile.TarInfo("link")
        link.type, link.linkname = tarfile.SYMTYPE, "/external/file"
        archive.addfile(link)
    scanner = privacy.Scan({}, [])
    scanner.payload(tar.getvalue(), "asset:tar")
    scanner.payload(archive_bytes({"../escape.txt": b"must not extract"}), "asset:zip")
    assert len(scanner.unknown) == 2


def test_archive_expansion_budget_cannot_claim_inspected_contents(monkeypatch):
    monkeypatch.setattr(privacy, "MAX_UNIT_BYTES", 1024)
    scanner = privacy.Scan({}, [])
    scanner.payload(gzip.compress(b"A" * 4096), "asset:bomb.gz")
    assert scanner.unknown and "expansion" in scanner.unknown[0]["reason"]


def test_total_scan_budget_stops_further_content_processing(monkeypatch):
    monkeypatch.setattr(privacy, "MAX_TOTAL_BYTES", 10)
    scanner = privacy.Scan({}, [])
    scanner.payload(b"A" * 8, "first")
    scanner.payload(b"B" * 8, "second")
    scanner.payload(b"C", "third")
    assert scanner.exhausted and scanner.unknown
    assert len(scanner.units) == 1


def test_protected_transcript_long_phrase_is_matched_by_hash_only():
    phrase = "A completely invented teaching example used only to test transcript privacy."
    scanner = privacy.Scan({}, [phrase])
    scanner.payload(("prefix " + phrase + " suffix").encode(), "body")
    assert scanner.transcripts == {hashlib.sha256(phrase.encode()).hexdigest()}
    assert phrase not in json.dumps(scanner.findings)


def test_unbound_remote_bodies_and_assets_cannot_pass_publication(repository, tmp_path):
    report = privacy.verify_release_privacy(publication_input(repository, tmp_path), repository)
    assert report["status"] == "UNVERIFIED"
    assert report["coverage"]["all_selected_payloads_read"]
    assert report["measurements"]["tracked_content_scanned"] is True
    assert report["measurements"]["assets_scanned"] is None
    assert report["measurements"]["body_scanned"] is None
    assert report["measurements"]["private_media_count"] is None
    assert report["remote_publication"] is None


def test_private_history_match_survives_current_tree_removal_in_full_scan(repository, tmp_path):
    content = b"excluded synthetic recording"
    (repository / "old.txt").write_bytes(content)
    commit(repository)
    (repository / "old.txt").unlink()
    commit(repository)
    report = privacy.verify_release_privacy(publication_input(repository, tmp_path), repository)
    assert report["observed_matches"]["private_media_count"] == 1
    assert report["findings"]


def test_stale_publication_head_is_rejected(repository, tmp_path):
    ref = publication_input(repository, tmp_path)
    (repository / "new.txt").write_text("A change after selected publication snapshot")
    commit(repository)
    with pytest.raises(TalkCutError, match="HEAD changed"):
        privacy.verify_release_privacy(ref, repository)


def test_wrong_remote_repository_cannot_borrow_publication_binding(repository, tmp_path):
    git(repository, "remote", "add", "origin", "https://github.com/expected/fixture.git")
    raw = {"remote_publication": {"repository": "another/repository", "pr_number": 1, "tag": "v0"}}
    with pytest.raises(TalkCutError, match="configured GitHub"):
        privacy._remote(raw, repository, {}, [])


def test_asset_inventory_requires_explicit_unique_names(tmp_path):
    path = tmp_path / "text.txt"
    path.write_text("public")
    ref = {**artifact_ref(path), "name": "text.txt"}
    with pytest.raises(TalkCutError, match="duplicated"):
        privacy._asset_refs([ref, ref])


def private_project(tmp_path):
    # Registration/hash graph fixture only: these bytes are deliberately not
    # presented as decoded audiovisual content or an acceptance certificate.
    screen, speaker = tmp_path / "screen-fixture.bin", tmp_path / "speaker-fixture.bin"
    screen.write_bytes(b"generated screen registration identity")
    speaker.write_bytes(b"generated speaker registration identity")
    directory = tmp_path / "lecture-project"
    value = init_project(directory, screen, speaker)
    return directory, {role: source["sha256"] for role, source in value["sources"].items()}


def historical_indexes(tmp_path, directory, count=1):
    """Keep actual old index bytes; expected digests alone are not evidence."""
    index = directory / "acceptance.local.json"
    history = tmp_path / "preserved-indexes"
    history.mkdir()
    old_refs, preserved = [], []
    for version in range(count):
        atomic_json(index, {"schema_version": "acceptance-index/v1", "owner_acceptance": "pending",
                            "checks": {}, "fixture_revision": version})
        ref = artifact_ref(index)
        target = history / ref["sha256"]
        target.write_bytes(index.read_bytes())
        old_refs.append(ref)
        preserved.append(artifact_ref(target))
    atomic_json(index, {"schema_version": "acceptance-index/v1", "owner_acceptance": "pending",
                        "checks": {}, "fixture_revision": count})
    atomic_json(directory / "checkpoint.local.json", {"previous_index_versions": old_refs})
    return index, old_refs, preserved


@pytest.mark.parametrize("count", [1, 2])
def test_actual_preserved_index_versions_are_distinct_mandatory_private_nodes(tmp_path, repository, count):
    directory, sources = private_project(tmp_path)
    index, old_refs, preserved = historical_indexes(tmp_path, directory, count)
    known, _, report = privacy._known_private_inventory(directory, sources, repository, historical_artifacts=preserved)
    actual = artifact_ref(index)
    assert report["historical_unresolved"] == []
    assert len(report["historical_refs"]) == count
    assert all(row["status"] == "RESOLVED" for row in report["historical_refs"])
    assert known[actual["sha256"]] == "review"
    for old, saved in zip(old_refs, preserved, strict=True):
        assert known[old["sha256"]] == "review"
        assert {**saved, "kind": "review"} in report["known_refs"]
        assert {**old, "kind": "review"} not in report["known_refs"]
    snapshot = privacy.build_private_inventory(directory, sources, repository, historical_artifacts=preserved)
    assert snapshot["unresolved"] == []
    assert all(any(row["path"] == ref["path"] and row["sha256"] == ref["sha256"]
                   and row["classification"] == "review" for row in snapshot["entries"]) for ref in preserved)
    assert snapshot["classification_status"] == "UNVERIFIED"


def test_unread_historical_index_allows_observation_but_never_complete_corpus(tmp_path, repository, monkeypatch):
    directory, sources = private_project(tmp_path)
    _, old_refs, preserved = historical_indexes(tmp_path, directory)
    Path(preserved[0]["path"]).unlink()
    known, _, report = privacy._known_private_inventory(directory, sources, repository)
    assert known[old_refs[0]["sha256"]] == "review"  # Deny-list hash only; bytes remain unread.
    assert all(ref["sha256"] != old_refs[0]["sha256"] for ref in report["known_refs"])
    assert len(report["historical_unresolved"]) == 1
    snapshot = privacy.build_private_inventory(directory, sources, repository)
    assert snapshot["unresolved"] == report["historical_unresolved"]
    ref = publication_input(repository, tmp_path)
    result = privacy.verify_release_privacy(ref, repository, project_dir=directory, expected_source_hashes=sources)
    assert result["coverage"]["all_selected_payloads_read"] is True
    assert result["coverage"]["private_corpus_complete"] is None
    assert result["status"] == "UNVERIFIED"
    assert result["measurements"]["private_transcript_count"] is None
    snapshot_path = tmp_path / "unresolved-snapshot.json"
    atomic_json(snapshot_path, snapshot)
    from talkcut import review
    monkeypatch.setattr(review, "verify_artifact_audit", lambda *args, **kwargs: pytest.fail("Unread historical bytes must reject before any audit verdict"))
    with pytest.raises(TalkCutError, match="unresolved"):
        privacy._audited_private_inventory({"private_inventory_snapshot": artifact_ref(snapshot_path),
                                            "inventory_audit": {"test_only": True}}, directory, sources, repository, {}, [])


def test_suffixless_history_archive_is_parsed_even_if_first_seen_as_ordinary_ref(tmp_path, repository):
    directory, sources = private_project(tmp_path)
    index = directory / "acceptance.local.json"
    note = directory / "historical-private-note.txt"
    note.write_text("An authored private note reachable only through the preserved historical index.")
    atomic_json(index, {"schema_version": "acceptance-index/v1", "owner_acceptance": "pending", "checks": {"note": artifact_ref(note)}})
    old = artifact_ref(index)
    archive = directory / old["sha256"]
    archive.write_bytes(index.read_bytes())
    saved = artifact_ref(archive)
    atomic_json(index, {"schema_version": "acceptance-index/v1", "owner_acceptance": "pending", "checks": {}})
    # Dict traversal sees the ordinary suffixless file first. Its later parse
    # promotion must still follow all historical refs exactly once.
    atomic_json(directory / "checkpoint.local.json", {"a_archive": saved, "z_historical": old})
    known, _, report = privacy._known_private_inventory(directory, sources, repository, historical_artifacts=[saved])
    assert known[artifact_ref(note)["sha256"]] == "review"
    assert report["historical_unresolved"] == []
    assert sum(ref["path"] == str(archive) for ref in report["known_refs"]) == 1
    snapshot = privacy.build_private_inventory(directory, sources, repository, historical_artifacts=[saved])
    assert next(row for row in snapshot["entries"] if row["path"] == str(note))["classification"] == "review"


def test_unread_prior_digest_still_detects_published_old_index_bytes(tmp_path, repository):
    directory, sources = private_project(tmp_path)
    _, old_refs, preserved = historical_indexes(tmp_path, directory)
    old_path = Path(preserved[0]["path"])
    (repository / "mislabelled-public-notes.json").write_bytes(old_path.read_bytes())
    commit(repository)
    old_path.unlink()
    result = privacy.verify_release_privacy(publication_input(repository, tmp_path), repository,
                                           project_dir=directory, expected_source_hashes=sources)
    assert result["status"] == "FAIL"
    assert any(row.get("sha256") == old_refs[0]["sha256"] for row in result["findings"])
    assert result["private_inventory"]["historical_unresolved"]
    assert result["coverage"]["private_corpus_complete"] is None
    assert result["measurements"]["private_transcript_count"] is None


def test_forged_historical_index_hash_cannot_relabel_registered_media(tmp_path, repository):
    directory, sources = private_project(tmp_path)
    index = directory / "acceptance.local.json"
    atomic_json(index, {"schema_version": "acceptance-index/v1", "owner_acceptance": "pending", "checks": {}})
    atomic_json(directory / "checkpoint.local.json", {"forged_prior_index": {"path": str(index), "sha256": sources["screen"]}})
    with pytest.raises(TalkCutError, match="relabelled"):
        privacy._known_private_inventory(directory, sources, repository)


def test_asr_runtime_code_is_inventory_candidate_without_becoming_speech(tmp_path, repository):
    directory, sources = private_project(tmp_path)
    transcripts = directory / "transcripts"
    transcripts.mkdir()
    runtime = directory / "runtime/tokenizer.py"
    runtime.parent.mkdir()
    code_line = "from collections import defaultdict as synthetic_public_fixture_collection"
    runtime.write_text(code_line + "\n")
    (repository / "public-helper.py").write_bytes(runtime.read_bytes())
    commit(repository)
    metadata = transcripts / "asr-runtime-provenance.json"
    atomic_json(metadata, {"python_executable": "/generated/fixture/python", "packages": {},
                           "actual_whisper_source_assets_and_mlx_binary": [artifact_ref(runtime)],
                           "toolchain_tree_hash": "1" * 64})
    spoken = "This authored sentence is the actual synthetic transcript content that remains protected."
    atomic_json(transcripts / "normalized.json", {"schema_version": "transcript/v1", "source_sha256": sources["screen"],
                                                "segments": [{"text": spoken}]})
    atomic_json(transcripts / "raw.json", {"text": spoken, "segments": [{"text": spoken}], "language": "en"})
    atomic_json(transcripts / "unknown.json", {"schema": "unknown-transcript/v1", "utterance": "An unknown transcript shape still contains this substantial private utterance."})
    known, phrases, report = privacy._known_private_inventory(directory, sources, repository)
    assert code_line not in phrases and spoken in phrases
    assert "An unknown transcript shape still contains this substantial private utterance." in phrases
    assert known[artifact_ref(metadata)["sha256"]] == "transcript"
    assert artifact_ref(runtime)["sha256"] not in known
    assert next(row for row in report["public_work_candidates"] if row["path"] == str(runtime))["classification"] == "UNCLASSIFIED"
    snapshot = privacy.build_private_inventory(directory, sources, repository)
    assert next(row for row in snapshot["entries"] if row["path"] == str(runtime))["classification"] == "UNCLASSIFIED"
    assert snapshot["classification_status"] == "UNVERIFIED"
    result = privacy.verify_release_privacy(publication_input(repository, tmp_path), repository,
                                           project_dir=directory, expected_source_hashes=sources)
    assert result["observed_matches"]["private_transcript_count"] == 0
    assert result["measurements"]["private_transcript_count"] is None
    assert result["coverage"]["private_corpus_complete"] is None


def test_referenced_public_source_copy_and_archive_require_classification(tmp_path, repository):
    directory, sources = private_project(tmp_path)
    copy = directory / "audit-code-copy.txt"
    copy.write_bytes((repository / "README.md").read_bytes())
    package = directory / "candidate.whl"
    package.write_bytes(archive_bytes({"talkcut/__init__.py": b"# authored public fixture package\n"}))
    atomic_json(directory / "checkpoint.local.json", {"copy": artifact_ref(copy), "package": artifact_ref(package)})
    known, _, report = privacy._known_private_inventory(directory, sources, repository)
    assert all(artifact_ref(path)["sha256"] not in known for path in (copy, package))
    candidates = {row["path"]: row for row in report["public_work_candidates"]}
    assert candidates[str(copy)]["matching_git_source_bytes"]
    assert candidates[str(package)]["classification"] == "UNCLASSIFIED"
    snapshot = privacy.build_private_inventory(directory, sources, repository)
    assert all(next(row for row in snapshot["entries"] if row["path"] == str(path))["classification"] == "UNCLASSIFIED"
               for path in (copy, package))


def test_relative_historical_public_readme_ref_remains_covered_by_git_payload(tmp_path, repository):
    directory, sources = private_project(tmp_path)
    prior = {"path": "README.md", "sha256": artifact_ref(repository / "README.md")["sha256"]}
    (repository / "README.md").write_text("Updated public fixture documentation\n")
    commit(repository)
    atomic_json(directory / "goal-handoff.local.json", {"prior_public_document": prior})
    known, _, report = privacy._known_private_inventory(directory, sources, repository)
    assert prior["sha256"] not in known
    assert all(ref["path"] != "README.md" for ref in report["unfollowed_refs"])
    snapshot = privacy.build_private_inventory(directory, sources, repository)
    assert not snapshot["unresolved"]
    result = privacy.verify_release_privacy(publication_input(repository, tmp_path), repository,
                                           project_dir=directory, expected_source_hashes=sources)
    assert any(unit["sha256"] == prior["sha256"] for unit in result["units"])
    assert len(result["git"]["reachable_commits"]) == 2
    assert result["coverage"]["private_corpus_complete"] is None


@pytest.mark.parametrize("representation", ["unknown_schema", "metadata_schema", "runtime_manifest", "plain_py", "json_py"])
def test_transcript_namespace_body_protection_does_not_depend_on_labels(tmp_path, repository, representation):
    directory, sources = private_project(tmp_path)
    transcripts = directory / "transcripts"
    transcripts.mkdir()
    phrase = "An authored confidential lecture sentence about nine silver pentagons beside an amber ocean."
    target = transcripts / ("recording.py" if representation.endswith("py") else "recording.json")
    if representation == "plain_py":
        target.write_text(phrase + "\n")
    elif representation == "json_py":
        atomic_json(target, {"text": phrase})
    elif representation == "runtime_manifest":
        atomic_json(target, {"python_executable": "/generated/python", "packages": {"utterance": phrase},
                             "actual_whisper_source_assets_and_mlx_binary": [], "toolchain_tree_hash": "0" * 64})
    else:
        atomic_json(target, {"schema": "talkcut-private-asr-evidence/v1" if representation == "metadata_schema" else "unknown/v1",
                             "utterance": phrase})
    (repository / "excerpt.txt").write_text("Public wrapper\n" + phrase + "\nUnrelated suffix\n")
    commit(repository)
    result = privacy.verify_release_privacy(publication_input(repository, tmp_path), repository,
                                           project_dir=directory, expected_source_hashes=sources)
    assert result["status"] == "FAIL"
    assert any(row["kind"] == "protected_transcript_phrase" for row in result["findings"])
    assert artifact_ref(target)["sha256"] in {ref["sha256"] for ref in result["private_inventory"]["known_refs"]}
    assert result["coverage"]["private_corpus_complete"] is None


@pytest.mark.parametrize("location", ["external", "external_py", "external_json_py", "public_docs", "public_duplicate"])
def test_explicit_registered_transcript_precedes_all_public_candidate_routes(tmp_path, repository, location):
    directory, sources = private_project(tmp_path)
    phrase = "An explicitly registered private transcript sentence about turquoise moons and seven copper stars."
    if location == "public_docs":
        target = repository / "docs/recording.txt"
        target.parent.mkdir()
    else:
        target = tmp_path / ("recording.py" if "py" in location else "recording.txt")
    if location == "external_json_py":
        atomic_json(target, {"text": phrase})
    else:
        target.write_text(phrase + "\n")
    atomic_json(directory / "checkpoint.local.json", {"producer": {"transcript": {
        "schema_version": "transcript/v1", "source_sha256": sources["screen"], **artifact_ref(target)}}})
    if location == "public_duplicate":
        (repository / "docs").mkdir()
        (repository / "docs/public-copy.txt").write_bytes(target.read_bytes())
    (repository / "excerpt.txt").write_text("Unrelated prefix\n" + phrase + "\nUnrelated suffix\n")
    commit(repository)
    result = privacy.verify_release_privacy(publication_input(repository, tmp_path), repository,
                                           project_dir=directory, expected_source_hashes=sources)
    assert result["status"] == "FAIL"
    assert any(row["kind"] == "protected_transcript_phrase" for row in result["findings"])
    assert any(ref["path"] == str(target) and ref["kind"] == "transcript" for ref in result["private_inventory"]["known_refs"])
    snapshot = privacy.build_private_inventory(directory, sources, repository)
    assert next(row for row in snapshot["entries"] if row["path"] == str(target))["classification"] == "transcript"
    assert result["coverage"]["private_corpus_complete"] is None


def test_public_source_directory_alone_cannot_hide_wrong_historical_locator(tmp_path, repository):
    directory, sources = private_project(tmp_path)
    old = artifact_ref(repository / "README.md")
    atomic_json(directory / "goal-handoff.local.json", {"forged_path": {**old, "path": "docs/nonexistent.txt"}})
    with pytest.raises(TalkCutError, match="absent"):
        privacy._known_private_inventory(directory, sources, repository)


@pytest.mark.parametrize("damage", [None, "missing_locator", "forged_bytes", "current_owner", "old_schema"])
def test_goal_checkpoint_history_requires_typed_current_and_preserved_bytes(tmp_path, repository, damage):
    directory, sources = private_project(tmp_path)
    checkpoint = directory / "checkpoint.local.json"
    original = {"schema_version": "goal-checkpoint/v1", "owner_acceptance": "pending", "criteria": {"AC01": "UNVERIFIED"}}
    atomic_json(checkpoint, original)
    old_ref = artifact_ref(checkpoint)
    backup = tmp_path / "old-checkpoint"
    backup.write_bytes(checkpoint.read_bytes())
    preserved = artifact_ref(backup)
    atomic_json(checkpoint, {**original, "criteria": {"AC01": "PASS"}})
    atomic_json(directory / "goal-handoff.local.json", {"recorded_old_checkpoint": old_ref})
    if damage == "forged_bytes":
        backup.write_text("Changed old bytes")
    elif damage == "current_owner":
        atomic_json(checkpoint, {**original, "owner_acceptance": "accepted"})
    elif damage == "old_schema":
        atomic_json(backup, {"schema_version": "unrelated/v1", "owner_acceptance": "pending", "criteria": {}})
        preserved = artifact_ref(backup)
        atomic_json(directory / "goal-handoff.local.json", {"recorded_old_checkpoint": {"path": str(checkpoint), "sha256": preserved["sha256"]}})
    locators = [] if damage == "missing_locator" else [preserved]
    if damage in {"forged_bytes", "current_owner", "old_schema"}:
        with pytest.raises(TalkCutError):
            privacy._known_private_inventory(directory, sources, repository, historical_artifacts=locators)
    else:
        known, _, graph = privacy._known_private_inventory(directory, sources, repository, historical_artifacts=locators)
        assert known[old_ref["sha256"]] == known[artifact_ref(checkpoint)["sha256"]] == "review"
        snapshot = privacy.build_private_inventory(directory, sources, repository, historical_artifacts=locators)
        assert bool(snapshot["unresolved"]) == (damage == "missing_locator")
        assert bool(graph["historical_unresolved"]) == (damage == "missing_locator")
        if damage is None:
            assert {**preserved, "kind": "review"} in graph["known_refs"]


def test_actual_evaluate_and_project_revision_preserve_reachable_metadata_history(tmp_path):
    """Actual CLI FAIL reports and the normal revision writer, no media PASS."""
    from talkcut.contracts import freeze_contract
    from talkcut.project import load_project, project_lock, save_revision
    directory, sources = private_project(tmp_path)
    root = Path(privacy.__file__).resolve().parents[2]
    contract = tmp_path / "frozen-contract.json"
    note = tmp_path / "historical-project-note.txt"
    note.write_text("An invented private transcript from a recorded project revision must remain protected.")
    with project_lock(directory):
        project = load_project(directory)
        project["analysis"] = {"schema_version": "transcript/v1", "source_sha256": sources["screen"], **artifact_ref(note)}
        save_revision(directory, project, project["revision"], "set-analysis-fixture", {})
    argv = [sys.executable, "-m", "talkcut", "acceptance", "evaluate", str(directory),
            "--render", "missing", "--contract", str(contract), "--json"]
    first = subprocess.run(argv, cwd=root, capture_output=True, check=False)
    assert first.returncode == 1
    report = directory / "reports/acceptance-latest.local.json"
    first_report = json.loads(first.stdout)
    assert first_report["schema_version"] == "goal-acceptance/v1" and not first_report["goal_achieved"]
    old_refs, locators = [], []
    for path in (report, directory / "project.json"):
        old = artifact_ref(path)
        backup = tmp_path / old["sha256"]  # Suffixless archives must still be parsed.
        backup.write_bytes(path.read_bytes())
        old_refs.append(old)
        locators.append(artifact_ref(backup))
    # The old active-analysis reference disappears from the current project.
    # Its exact saved revision must still be recursively inspected.
    with project_lock(directory):
        project = load_project(directory)
        project["analysis"] = None
        save_revision(directory, project, project["revision"], "reset-analysis-fixture", {})
    # A real contract appearing between evaluations changes the actual report;
    # all missing-media/reviewer gates still fail.
    freeze_contract(root, contract)
    second = subprocess.run(argv, cwd=root, capture_output=True, check=False)
    assert second.returncode == 1 and artifact_ref(report) != old_refs[0]
    assert json.loads(second.stdout)["owner_acceptance"] == "pending"
    atomic_json(directory / "goal-handoff.local.json", {"before_normal_commands": old_refs})
    known, phrases, graph = privacy._known_private_inventory(directory, sources, root, historical_artifacts=locators)
    assert graph["historical_unresolved"] == [] and len(graph["historical_refs"]) == 2
    assert note.read_text() in phrases and known[artifact_ref(note)["sha256"]] == "transcript"
    for old, saved in zip(old_refs, locators, strict=True):
        assert known[old["sha256"]] == known[artifact_ref(Path(old["path"]))["sha256"]] == "review"
        assert {**saved, "kind": "review"} in graph["known_refs"]
    inventory = privacy.build_private_inventory(directory, sources, root, historical_artifacts=locators)
    assert inventory["unresolved"] == [] and inventory["classification_status"] == "UNVERIFIED"


@pytest.mark.parametrize("metadata", ["project.json", "reports/acceptance-latest.local.json"])
@pytest.mark.parametrize("damage", ["missing_locator", "wrong_bytes", "symlink", "old_schema", "old_owner", "current_owner", "wrong_source_or_criteria", "wrong_path"])
def test_project_and_acceptance_report_history_rejects_invalid_provenance(tmp_path, repository, metadata, damage):
    from talkcut.project import load_project, project_lock, save_revision
    directory, sources = private_project(tmp_path)
    path = directory / metadata
    if metadata.startswith("reports/"):
        atomic_json(path, {"schema_version": "goal-acceptance/v1", "criteria": [], "owner_acceptance": "pending"})
    old = artifact_ref(path)
    backup = tmp_path / "preserved-old-metadata"
    backup.write_bytes(path.read_bytes())
    saved = artifact_ref(backup)
    if metadata == "project.json":
        with project_lock(directory):
            value = load_project(directory)
            save_revision(directory, value, value["revision"], "metadata-regression", {})
    else:
        value = json.loads(path.read_text())
        atomic_json(path, {**value, "criteria": [{"id": "AC01", "status": "UNVERIFIED"}]})
    if damage == "wrong_bytes":
        backup.write_text("Not the preserved bytes")
    elif damage == "symlink":
        contents = tmp_path / "real-old-metadata"
        contents.write_bytes(backup.read_bytes())
        backup.unlink()
        backup.symlink_to(contents)
    elif damage in {"old_schema", "old_owner", "wrong_source_or_criteria"}:
        value = json.loads(backup.read_text())
        if damage == "old_schema":
            value["schema_version"] = "unrelated/v1"
        elif damage == "old_owner":
            value["owner_acceptance"] = "accepted"
        elif metadata == "project.json":
            value["sources"]["screen"]["sha256"] = "0" * 64
        else:
            value["criteria"] = {}
        atomic_json(backup, value)
        saved = artifact_ref(backup)
        old["sha256"] = saved["sha256"]
    elif damage == "current_owner":
        value = json.loads(path.read_text())
        atomic_json(path, {**value, "owner_acceptance": "accepted"})
    elif damage == "wrong_path":
        other = directory / "reviews" / path.name
        other.parent.mkdir(exist_ok=True)
        other.write_bytes(path.read_bytes())
        old["path"] = str(other)
    atomic_json(directory / "goal-handoff.local.json", {"old_metadata": old})
    locators = [] if damage == "missing_locator" else [saved]
    if damage == "missing_locator":
        known, _, graph = privacy._known_private_inventory(directory, sources, repository, historical_artifacts=locators)
        assert known[old["sha256"]] == "review" and len(graph["historical_unresolved"]) == 1
        assert privacy.build_private_inventory(directory, sources, repository, historical_artifacts=locators)["unresolved"]
    else:
        with pytest.raises((TalkCutError, ValueError)):
            privacy._known_private_inventory(directory, sources, repository, historical_artifacts=locators)


@pytest.mark.parametrize("damage", [None, "wrong_snapshot", "missing_snapshot", "wrong_origin", "explicit_transcript", "transcript_json"])
def test_preserved_source_locator_is_unclassified_and_cannot_restore_private_changes(tmp_path, repository, damage):
    directory, sources = private_project(tmp_path)
    original = repository / "src/helper.py"
    original.parent.mkdir()
    if damage in {"explicit_transcript", "transcript_json"}:
        atomic_json(original, {"schema_version": "transcript/v1", "source_sha256": sources["screen"],
                               "text": "A protected private transcript that must not be recovered as a public source candidate."})
    else:
        original.write_text("def generated_helper():\n    return 7\n")
    old_ref = artifact_ref(original)
    saved = tmp_path / "immutable-source-snapshot.txt"
    saved.write_bytes(original.read_bytes())
    locator = {"original": old_ref, "snapshot": artifact_ref(saved)}
    original.write_text("def generated_helper():\n    return 8\n")
    edge = old_ref if damage != "explicit_transcript" else {**old_ref, "schema_version": "transcript/v1", "source_sha256": sources["screen"]}
    atomic_json(directory / "checkpoint.local.json", {"prior_code": edge})
    if damage == "wrong_snapshot":
        saved.write_text("Different bytes from the recorded snapshot")
    elif damage == "missing_snapshot":
        saved.unlink()
    elif damage == "wrong_origin":
        locator["original"] = {**old_ref, "path": str(directory / "private.py")}
    if damage is not None:
        with pytest.raises(TalkCutError):
            privacy._known_private_inventory(directory, sources, repository, source_snapshots=[locator])
    else:
        known, _, graph = privacy._known_private_inventory(directory, sources, repository, source_snapshots=[locator])
        assert old_ref["sha256"] not in known
        candidate = next(row for row in graph["public_work_candidates"] if row["path"] == str(saved))
        assert candidate["classification"] == "UNCLASSIFIED" and candidate["original_reference"] == old_ref
        assert candidate["sha256"] == artifact_ref(saved)["sha256"]
        snapshot = privacy.build_private_inventory(directory, sources, repository, source_snapshots=[locator])
        assert next(row for row in snapshot["entries"] if row["path"] == str(saved))["classification"] == "UNCLASSIFIED"
        assert snapshot["classification_status"] == "UNVERIFIED"


def test_unpreserved_public_source_keeps_observations_but_blocks_inventory_audit(tmp_path, repository, monkeypatch):
    directory, sources = private_project(tmp_path)
    original = repository / "src/helper.py"
    original.parent.mkdir()
    original.write_text("def helper():\n    return 1\n")
    commit(repository)
    original.write_text("def helper():\n    return 2\n")
    old_ref = artifact_ref(original)
    original.write_text("def helper():\n    return 3\n")
    private = tmp_path / "external-transcript.txt"
    private.write_text("This invented private statement remains protected through an unresolved source edge.")
    # Nested private evidence still has to be traversed after the unread edge.
    atomic_json(directory / "checkpoint.local.json", {"prior_code": {
        **old_ref, "nested": {"schema_version": "transcript/v1", "source_sha256": sources["screen"], **artifact_ref(private)}}})
    known, phrases, graph = privacy._known_private_inventory(directory, sources, repository)
    assert old_ref["sha256"] not in known
    assert all(ref["sha256"] != old_ref["sha256"] for ref in graph["known_refs"])
    assert known[artifact_ref(private)["sha256"]] == "transcript" and private.read_text() in phrases
    unresolved = graph["unresolved_source_candidates"]
    assert len(unresolved) == 1 and unresolved[0]["sha256"] == old_ref["sha256"]
    assert unresolved[0]["current_ref"] == artifact_ref(original)
    assert unresolved[0]["status"] == "UNVERIFIED"
    snapshot = privacy.build_private_inventory(directory, sources, repository)
    assert snapshot["unresolved"] == unresolved
    result = privacy.verify_release_privacy(publication_input(repository, tmp_path), repository,
                                           project_dir=directory, expected_source_hashes=sources)
    assert result["coverage"]["all_selected_payloads_read"] is True
    assert result["coverage"]["private_corpus_complete"] is None and result["status"] == "UNVERIFIED"
    assert result["measurements"]["private_transcript_count"] is None
    snapshot_path = tmp_path / "unresolved-source-inventory.json"
    atomic_json(snapshot_path, snapshot)
    from talkcut import review
    monkeypatch.setattr(review, "verify_artifact_audit", lambda *args, **kwargs: pytest.fail("Unread source bytes cannot be approved by classification"))
    with pytest.raises(TalkCutError, match="unresolved"):
        privacy._audited_private_inventory({"private_inventory_snapshot": artifact_ref(snapshot_path),
                                            "inventory_audit": {"test_only": True}}, directory, sources, repository, {}, [])


@pytest.mark.parametrize("damage", ["missing", "symlink", "invalid_digest", "explicit_transcript"])
def test_unpreserved_source_observation_does_not_ignore_invalid_or_private_refs(tmp_path, repository, damage):
    directory, sources = private_project(tmp_path)
    original = repository / "src/helper.py"
    original.parent.mkdir()
    original.write_text("def helper():\n    return 1\n")
    commit(repository)
    original.write_text("def helper():\n    return 2\n")
    old_ref = artifact_ref(original)
    original.write_text("def helper():\n    return 3\n")
    if damage == "missing":
        original.unlink()
    elif damage == "symlink":
        target = tmp_path / "actual-helper.py"
        target.write_bytes(original.read_bytes())
        original.unlink()
        original.symlink_to(target)
    elif damage == "invalid_digest":
        old_ref["sha256"] = "not-a-digest"
    else:
        old_ref.update({"schema_version": "transcript/v1", "source_sha256": sources["screen"]})
    atomic_json(directory / "checkpoint.local.json", {"prior_code": old_ref})
    with pytest.raises(TalkCutError):
        privacy._known_private_inventory(directory, sources, repository)


@pytest.mark.parametrize("historical", [False, True])
def test_exact_git_json_transcript_is_private_before_public_source_matching(tmp_path, repository, historical):
    directory, sources = private_project(tmp_path)
    transcript = repository / "docs/foo.json"
    transcript.parent.mkdir()
    text = "A private invented lecture statement inside a canonical Git source path must stay protected."
    atomic_json(transcript, {"schema_version": "transcript/v1", "source_sha256": sources["screen"], "text": text})
    old = artifact_ref(transcript)
    commit(repository)
    atomic_json(directory / "checkpoint.local.json", {"generic_ref": old})
    if historical:
        transcript.write_text("{}\n")
        commit(repository)
        with pytest.raises(TalkCutError):
            privacy._known_private_inventory(directory, sources, repository)
    else:
        known, phrases, graph = privacy._known_private_inventory(directory, sources, repository)
        assert known[old["sha256"]] == "transcript" and text in phrases
        assert {**old, "kind": "transcript"} in graph["known_refs"]
        scanner = privacy.Scan(known, phrases)
        privacy._git_inventory(repository, git(repository, "rev-parse", "HEAD"), scanner, [])
        assert scanner.transcripts and scanner.findings


@pytest.mark.parametrize("private_kind", [None, "transcript_marker", "known_review", "registered_source"])
def test_typed_publication_body_is_unclassified_unless_private_provenance_wins(tmp_path, repository, private_kind):
    directory, sources = private_project(tmp_path)
    raw_ref = publication_input(repository, tmp_path)
    raw = privacy._json(raw_ref)
    if private_kind == "transcript_marker":
        body = directory / "proposed-body.md"
        atomic_json(body, {"schema_version": "transcript/v1", "source_sha256": sources["screen"],
                           "text": "An invented private lecture phrase cannot be published by relabelling its body role."})
        raw["pr_body"] = artifact_ref(body)
    elif private_kind == "known_review":
        body = directory / "reviews/private.json"
        body.parent.mkdir()
        atomic_json(body, {"source_sha256": sources["screen"], "private_review": "Confidential authored fixture review metadata"})
        raw["pr_body"] = artifact_ref(body)
    elif private_kind == "registered_source":
        body = directory / "sources/screen.bin"
        project = json.loads((directory / "project.json").read_text())
        raw["pr_body"] = {"path": project["sources"]["screen"]["path"], "sha256": sources["screen"]}
    else:
        body = directory / "draft-note.md"
        body.write_bytes(Path(raw["pr_body"]["path"]).read_bytes())
        raw["pr_body"] = artifact_ref(body)
        # A previous computed inventory is reference evidence, not authority
        # that can turn intended publication bytes into private lecture data.
        atomic_json(directory / "checkpoint.local.json", {"old_inventory": {"known_refs": [{**raw["pr_body"], "kind": "review"}]}})
    atomic_json(Path(raw_ref["path"]), raw)
    result = privacy.verify_release_privacy(artifact_ref(Path(raw_ref["path"])), repository,
                                           project_dir=directory, expected_source_hashes=sources)
    graph = result["private_inventory"]
    if private_kind is None:
        candidate = next(row for row in graph["public_work_candidates"] if row["sha256"] == raw["pr_body"]["sha256"])
        assert candidate["publication_role"] == "pr_body" and candidate["classification"] == "UNCLASSIFIED"
        assert result["observed_matches"]["private_transcript_count"] == 0
        assert result["status"] == "UNVERIFIED" and result["coverage"]["private_corpus_complete"] is None
    else:
        assert any(ref["sha256"] == raw["pr_body"]["sha256"] for ref in graph["known_refs"])
        assert result["status"] == "FAIL" and result["findings"]


@pytest.mark.parametrize("kind", ["registered_source", "transcript", "private_review"])
def test_public_byte_match_cannot_override_known_private_content(tmp_path, repository, kind):
    directory, sources = private_project(tmp_path)
    if kind == "registered_source":
        original = Path(json.loads((directory / "project.json").read_text())["sources"]["screen"]["path"])
    elif kind == "transcript":
        original = directory / "transcripts/unknown.py"
        original.parent.mkdir()
        original.write_text("A private transcript deliberately renamed with a public-looking code extension.\n")
    else:
        original = directory / "evidence/private-review.json"
        original.parent.mkdir()
        atomic_json(original, {"source_sha256": sources["screen"], "reason": "Actual authored private review fixture; never declassify based on a public duplicate"})
    # This deliberately leaked Git copy must not become its own justification.
    public = repository / "docs/leaked-copy.md"
    public.parent.mkdir()
    public.write_bytes(original.read_bytes())
    commit(repository)
    alias = directory / "public-looking.py"
    alias.write_bytes(original.read_bytes())
    atomic_json(directory / "checkpoint.local.json", {"alias": artifact_ref(alias)})
    result = privacy.verify_release_privacy(publication_input(repository, tmp_path), repository,
                                           project_dir=directory, expected_source_hashes=sources)
    assert result["status"] == "FAIL"
    assert any(row.get("sha256") == artifact_ref(original)["sha256"] for row in result["findings"])
    assert all(row["sha256"] != artifact_ref(original)["sha256"] for row in result["private_inventory"]["public_work_candidates"])
    assert result["coverage"]["private_corpus_complete"] is None


@pytest.mark.parametrize("damage", ["missing", "wrong_bytes", "symlink", "forged_hash", "wrong_old_schema"])
def test_historical_locator_requires_actual_unchanged_regular_index_bytes(tmp_path, repository, damage):
    directory, sources = private_project(tmp_path)
    _, _, preserved = historical_indexes(tmp_path, directory)
    path = Path(preserved[0]["path"])
    if damage == "missing":
        path.unlink()
    elif damage == "wrong_bytes":
        path.write_text("Changed after the actual old digest was recorded")
    elif damage == "symlink":
        real = tmp_path / "old-index-copy.json"
        real.write_bytes(path.read_bytes())
        path.unlink()
        path.symlink_to(real)
    elif damage == "forged_hash":
        preserved[0]["sha256"] = "0" * 64
    else:
        # A forged old index with internally consistent SHA still lacks its
        # required schema. Keep the old reference bound to these same bytes.
        atomic_json(path, {"schema_version": "unrelated/v1", "owner_acceptance": "pending", "checks": {}})
        preserved[0] = artifact_ref(path)
        atomic_json(directory / "checkpoint.local.json", {"previous_index": {
            "path": str(directory / "acceptance.local.json"), "sha256": preserved[0]["sha256"]}})
    with pytest.raises(TalkCutError):
        privacy._known_private_inventory(directory, sources, repository, historical_artifacts=preserved)


@pytest.mark.parametrize("field,value", [("schema_version", "unrelated/v1"), ("owner_acceptance", "accepted"), ("checks", [])])
def test_historical_locator_cannot_hide_invalid_current_index(tmp_path, repository, field, value):
    directory, sources = private_project(tmp_path)
    index, _, preserved = historical_indexes(tmp_path, directory)
    current = json.loads(index.read_text())
    current[field] = value
    atomic_json(index, current)
    with pytest.raises(TalkCutError, match="bookkeeping"):
        privacy._known_private_inventory(directory, sources, repository, historical_artifacts=preserved)


@pytest.mark.parametrize("kind", ["source", "transcript", "render", "inspection"])
def test_history_does_not_relax_immutable_source_or_artifact_references(tmp_path, repository, kind):
    directory, sources = private_project(tmp_path)
    if kind == "source":
        project = json.loads((directory / "project.json").read_text())
        path = Path(project["sources"]["screen"]["path"])
    else:
        suffix = ".mp4" if kind == "render" else ".json"
        path = directory / (kind + suffix)
        atomic_json(path, {"schema_version": "transcript/v1" if kind == "transcript" else "fixture/v1",
                           "source_sha256": sources["screen"], "text": "An authored private reference fixture only"})
    old_ref = artifact_ref(path)
    backup = tmp_path / "immutable-backup"
    backup.write_bytes(path.read_bytes())
    atomic_json(directory / "checkpoint.local.json", {"immutable": old_ref})
    path.chmod(0o600)  # Fault injection into this generated source fixture only.
    path.write_bytes(b"Changed immutable private artifact bytes")
    with pytest.raises(TalkCutError, match="registered hash|Registered source bytes changed"):
        privacy._known_private_inventory(directory, sources, repository, historical_artifacts=[artifact_ref(backup)])


def test_one_hash_corpus_cannot_omit_registered_task_transcript(repository, tmp_path, monkeypatch):
    directory, sources = private_project(tmp_path)
    transcripts = directory / "transcripts"
    transcripts.mkdir()
    transcript = transcripts / "full-renamed.txt"
    transcript.write_text("An invented lecture sentence that must stay private in this regression fixture.\n")
    (repository / "apparently-public-notes.txt").write_bytes(transcript.read_bytes())
    commit(repository)
    # Even a positive remote transport control must not turn an incomplete
    # exclusion inventory into zero counters. This is a negative control only.
    monkeypatch.setattr(privacy, "_remote", lambda *args: {"test_transport_control": True})
    result = privacy.verify_release_privacy(publication_input(repository, tmp_path), repository,
                                           project_dir=directory, expected_source_hashes=sources)
    assert result["status"] == "FAIL"
    assert result["observed_matches"]["private_transcript_count"] >= 1
    assert artifact_ref(transcript)["sha256"] in result["private_inventory"]["missing_from_submitted_corpus"]
    assert result["measurements"]["private_transcript_count"] is None
    assert result["coverage"]["private_corpus_complete"] is None


def test_caller_complete_boolean_is_not_inventory_provenance(repository, tmp_path, monkeypatch):
    ref = publication_input(repository, tmp_path)
    raw = privacy._json(ref)
    corpus = privacy._json(raw["private_corpus"])
    corpus["complete"] = True
    atomic_json(tmp_path / "corpus.json", corpus)
    raw["private_corpus"] = artifact_ref(tmp_path / "corpus.json")
    atomic_json(tmp_path / "publication.json", raw)
    monkeypatch.setattr(privacy, "_remote", lambda *args: {"test_transport_control": True})
    result = privacy.verify_release_privacy(artifact_ref(tmp_path / "publication.json"), repository)
    assert result["status"] == "UNVERIFIED"
    assert result["coverage"]["private_corpus_available"] is True
    assert result["coverage"]["private_corpus_complete"] is None
    assert all(result["measurements"][name] is None for name in
               ("private_media_count", "private_transcript_count", "credentials_count"))


def test_public_staging_and_synthetic_fixtures_are_not_inferred_private_by_parent_path(tmp_path):
    directory, sources = private_project(tmp_path)
    staging = directory / "implementation-staging"
    staging.mkdir()
    code = staging / "public.py"
    code.write_text("print('public executable example')\n")
    synthetic = directory / "evidence/recovery-example"
    synthetic.mkdir(parents=True)
    generated = synthetic / "screen.mp4"
    generated.write_bytes(b"generated public fixture media identity")
    atomic_json(synthetic / "manifest.json", {"source_sha256": artifact_ref(generated)["sha256"], "source": artifact_ref(generated)})
    known, _, report = privacy._known_private_inventory(directory, sources)
    assert artifact_ref(code)["sha256"] not in known
    assert artifact_ref(generated)["sha256"] not in known
    assert report["completeness"] == "UNVERIFIED"


def test_private_inventory_cannot_substitute_evaluator_source_identity(tmp_path):
    directory, sources = private_project(tmp_path)
    with pytest.raises(TalkCutError, match="evaluator-registered"):
        privacy._known_private_inventory(directory, {**sources, "screen": "0" * 64})


def test_task_snapshot_includes_public_work_candidates_without_declassifying_them(tmp_path, repository):
    directory, sources = private_project(tmp_path)
    staging = directory / "implementation-staging"
    staging.mkdir()
    copied = staging / "example.py"
    copied.write_text("print('public synthetic implementation fixture')\n")
    snapshot = privacy.build_private_inventory(directory, sources, repository)
    assert snapshot["entry_count"] == len(snapshot["entries"])
    assert snapshot["excluded_directories"] == []
    entry = next(row for row in snapshot["entries"] if row["path"] == str(copied))
    assert entry["classification"] == "UNCLASSIFIED"
    assert entry["sha256"] == artifact_ref(copied)["sha256"]
    assert snapshot["classification_status"] == "UNVERIFIED"


def test_inventory_file_mutation_invalidates_the_exact_audit_snapshot(tmp_path, repository):
    directory, sources = private_project(tmp_path)
    snapshot = tmp_path / "inventory.json"
    atomic_json(snapshot, privacy.build_private_inventory(directory, sources, repository))
    (directory / "new-private-note.txt").write_text("New task-local private artifact after the audit snapshot")
    raw = {"private_inventory_snapshot": artifact_ref(snapshot), "inventory_audit": {"not": "an execution"},
           "implementation_run_ids": ["fixture-builder"]}
    with pytest.raises(TalkCutError, match="stale"):
        privacy._audited_private_inventory(raw, directory, sources, repository, {}, [])


def test_inventory_snapshot_cannot_be_saved_inside_its_own_denominator(tmp_path, repository):
    directory, sources = private_project(tmp_path)
    snapshot = directory / "self-referential.json"
    atomic_json(snapshot, {"schema_version": "private-task-inventory/v1"})
    raw = {"private_inventory_snapshot": artifact_ref(snapshot), "inventory_audit": {"not": "an execution"}}
    with pytest.raises(TalkCutError, match="outside"):
        privacy._audited_private_inventory(raw, directory, sources, repository, {}, [])


def test_even_a_positive_audit_adapter_cannot_declassify_registered_sources(tmp_path, repository, monkeypatch):
    directory, sources = private_project(tmp_path)
    snapshot = privacy.build_private_inventory(directory, sources, repository)
    path = tmp_path / "inventory.json"
    atomic_json(path, snapshot)
    classifications = [{"path": row["path"], "sha256": row["sha256"],
                        "classification": "public_work" if row["classification"] != "UNCLASSIFIED" else "review",
                        "reason": "Authored negative control attempts to declassify mandatory private artifacts"}
                       for row in snapshot["entries"]]
    from talkcut import review
    monkeypatch.setattr(review, "verify_artifact_audit", lambda *args, **kwargs: {"response": {"private_classifications": classifications}})
    raw = {"private_inventory_snapshot": artifact_ref(path), "inventory_audit": {"test_only": True},
           "implementation_run_ids": ["fixture-builder"]}
    with pytest.raises(TalkCutError, match="mandatory"):
        privacy._audited_private_inventory(raw, directory, sources, repository, {}, [])


def test_transcript_symlink_is_not_silently_followed_outside_task(tmp_path):
    directory, sources = private_project(tmp_path)
    transcripts = directory / "transcripts"
    transcripts.mkdir()
    external = tmp_path / "external.txt"
    external.write_text("An invented transcript outside the registered task namespace")
    (transcripts / "alias.txt").symlink_to(external)
    with pytest.raises(TalkCutError, match="symlink"):
        privacy._known_private_inventory(directory, sources)


def classification_control(tmp_path, directory, sources, repository):
    """Authored adapter control only; real provider binding has separate tests."""
    raw_ref = publication_input(repository, tmp_path)
    raw = privacy._json(raw_ref)
    snapshot = privacy.build_private_inventory(directory, sources, repository, archive_dir=tmp_path / "frozen-private-inputs",
                                               publication_bodies={role: raw[role] for role in ("pr_body", "release_body")})
    snapshot_path = tmp_path / "inventory.json"
    atomic_json(snapshot_path, snapshot)
    response = {"private_classifications": [
        {"path": row["path"], "sha256": row["sha256"],
         "classification": row["classification"] if row["classification"] != "UNCLASSIFIED" else "review",
         "reason": "Authored structural fixture classifies task material private; not a media or provider certificate"}
        for row in snapshot["entries"]]}
    public_bodies = {raw[role]["path"]: raw[role] for role in ("pr_body", "release_body")}
    for row in response["private_classifications"]:
        if row["path"] in public_bodies:
            row.update({"classification": "public_work", "evidence_refs": [public_bodies[row["path"]]],
                        "reason": "Authored public fixture body from publication_input; structural adapter control only"})
    response["inspected_artifact_hashes"] = [ref["sha256"] for ref in public_bodies.values()]
    raw.update({"private_inventory_snapshot": artifact_ref(snapshot_path), "inventory_audit": {"test_only": True},
                "implementation_run_ids": ["authored-fixture-builder"]})
    atomic_json(tmp_path / "publication.json", raw)
    return artifact_ref(tmp_path / "publication.json"), response


def test_actual_measurement_wrapper_adds_private_logs_without_invalidating_prior_audit(tmp_path, repository, monkeypatch):
    """Exercise actual Popen/stdout/receipt/index mechanics with a bounded worker.

    The child calls the real privacy scanner on a real local Git history. Its
    artifact-auditor transport is an authored control. Remote publication is
    absent, private counters remain null, and this never certifies DGIST/media.
    """
    directory, sources = private_project(tmp_path)
    atomic_json(directory / "acceptance.local.json", {"schema_version": "acceptance-index/v1", "owner_acceptance": "pending", "checks": {}})
    transcripts = directory / "transcripts"
    transcripts.mkdir()
    transcript = transcripts / "full.txt"
    transcript.write_text("A complete invented private lecture transcript for the removal regression.\n")
    raw_ref, response = classification_control(tmp_path, directory, sources, repository)
    control_path = tmp_path / "authored-audit-control.json"
    atomic_json(control_path, response)
    worker = tmp_path / "worker/talkcut"
    worker.mkdir(parents=True)
    source_root = Path(privacy.__file__).resolve().parent
    shutil.copytree(source_root / "schemas", worker / "schemas")
    (worker / "__init__.py").write_text("__path__.append(" + repr(str(source_root)) + ")\n")
    (worker / "__main__.py").write_text('''import json,os,sys
from pathlib import Path
from talkcut import review
from talkcut.contracts import code_identity
from talkcut.project import artifact_ref,atomic_json
from talkcut.privacy_checks import verify_release_privacy
project,root,raw = (Path(os.environ[name]) for name in ("PRIVACY_FIXTURE_PROJECT","PRIVACY_FIXTURE_REPO","PRIVACY_FIXTURE_RAW"))
review.verify_artifact_audit=lambda *args,**kwargs:{"response":json.loads(Path(os.environ["PRIVACY_FIXTURE_CONTROL"]).read_text())}
sources={role:source["sha256"] for role,source in json.loads((project/"project.json").read_text())["sources"].items()}
result=verify_release_privacy(artifact_ref(raw),root,project_dir=project,expected_source_hashes=sources)
atomic_json(Path(os.environ["PRIVACY_FIXTURE_OBSERVATION"]),result)
print(json.dumps({"schema_version":"measurement-result/v1","check_id":"release_privacy",
 "dependencies":{"code_tree_hash":code_identity(root)["code_tree_hash"]},"raw_inputs":artifact_ref(raw),
 "measurements":result["measurements"],"evidence_refs":[artifact_ref(raw)],"test_only":True}))
''')
    env = {"PYTHONPATH": str(worker.parent), "PRIVACY_FIXTURE_PROJECT": str(directory),
           "PRIVACY_FIXTURE_REPO": str(repository), "PRIVACY_FIXTURE_RAW": raw_ref["path"],
           "PRIVACY_FIXTURE_CONTROL": str(control_path), "PRIVACY_FIXTURE_OBSERVATION": str(tmp_path / "observed.json")}
    for name, value in env.items():
        monkeypatch.setenv(name, value)
    from talkcut.measurements import run_measurement
    positive = run_measurement(directory, "release_privacy", Path(raw_ref["path"]), tmp_path / "unused-contract", repository)
    assert positive["status"] == "MEASURED" and positive["evidence"]
    observed = json.loads((tmp_path / "observed.json").read_text())
    assert observed["private_inventory"]["completeness"] == "PASS"
    assert observed["status"] == "UNVERIFIED" and observed["measurements"]["private_media_count"] is None
    atomic_json(directory / "acceptance.local.json", {"schema_version": "acceptance-index/v1", "owner_acceptance": "pending",
                                                       "checks": {"release_privacy": positive["evidence"]}})
    from talkcut import review
    monkeypatch.setattr(review, "verify_artifact_audit", lambda *args, **kwargs: {"response": response})
    replay = privacy.verify_release_privacy(raw_ref, repository, project_dir=directory, expected_source_hashes=sources)
    audit = replay["private_inventory"]["classification_audit"]
    assert audit["entry_count"] > audit["audited_entry_count"]
    assert any(row["action"] == "preserve_old_and_add_current_private_hash" for row in audit["private_transitions"])
    # A real second worker run must fail when a transcript from the audited
    # denominator disappears, even while unrelated bookkeeping can grow.
    transcript.unlink()
    negative = run_measurement(directory, "release_privacy", Path(raw_ref["path"]), tmp_path / "unused-contract", repository)
    assert negative["status"] == "FAIL" and negative["evidence"] is None
    assert Path(positive["receipt"]["path"]).is_file()


def test_changed_audited_public_exclusion_requires_another_audit(tmp_path, repository, monkeypatch):
    directory, sources = private_project(tmp_path)
    public_copy = directory / "public-helper.py"
    public_copy.write_text("print('public fixture helper')\n")
    raw_ref, response = classification_control(tmp_path, directory, sources, repository)
    row = next(item for item in response["private_classifications"] if item["path"] == str(public_copy))
    row.update({"classification": "public_work", "evidence_refs": [artifact_ref(repository / "README.md")]})
    response["inspected_artifact_hashes"] = [artifact_ref(repository / "README.md")["sha256"]]
    from talkcut import review
    monkeypatch.setattr(review, "verify_artifact_audit", lambda *args, **kwargs: {"response": response})
    public_copy.write_text("print('changed bytes after the audit')\n")
    with pytest.raises(TalkCutError):
        privacy.verify_release_privacy(raw_ref, repository, project_dir=directory, expected_source_hashes=sources)
