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
    snapshot = privacy.build_private_inventory(directory, sources, repository, archive_dir=tmp_path / "frozen-private-inputs")
    snapshot_path = tmp_path / "inventory.json"
    atomic_json(snapshot_path, snapshot)
    response = {"private_classifications": [
        {"path": row["path"], "sha256": row["sha256"],
         "classification": row["classification"] if row["classification"] != "UNCLASSIFIED" else "review",
         "reason": "Authored structural fixture classifies task material private; not a media or provider certificate"}
        for row in snapshot["entries"]]}
    raw_ref = publication_input(repository, tmp_path)
    raw = privacy._json(raw_ref)
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
