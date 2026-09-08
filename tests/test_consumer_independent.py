"""Bounded real consumer traversal; synthetic artifacts, no producer execution."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from test_privacy_checks import publication_input
from test_privacy_machine_consumer import PHRASE, fixture, observe

from talkcut import privacy_checks as privacy
from talkcut.project import TalkCutError, artifact_ref, atomic_json


def direct(parts, *, authorities=None):
    root, directory, registered, _, authority, locators = parts
    return privacy._review_text_origin_inventory(
        locators, directory, root, set(registered.values()),
        [authority] if authorities is None else authorities,
    )


def test_standalone_authority_closure_survives_without_checkpoint(tmp_path):
    parts = fixture(tmp_path)
    root, directory, registered, parent, authority, locators = parts
    (directory / "checkpoint.local.json").unlink()
    observations = direct(parts)
    required = {
        (ref["path"], ref["sha256"])
        for row in observations for ref in row["authority_refs"]
    }
    result = privacy.build_private_inventory(
        directory, registered, root, review_text_origins=locators,
        review_text_origin_authorities=[authority], archive_dir=tmp_path / "archive",
    )
    entries = {(row["path"], row["sha256"]): row for row in result["entries"]}
    assert required <= set(entries)
    assert len(required) >= 7
    for path, digest in required:
        assert hashlib.sha256(Path(path).read_bytes()).hexdigest() == digest
    saved = result["preserved_private_inputs"][parent["path"]]
    assert Path(saved["path"]).read_bytes() == Path(parent["path"]).read_bytes()
    assert result["known_graph"]["completeness"] == "UNVERIFIED"


@pytest.mark.parametrize("namespace", ["audits", "transcripts"])
def test_byte_identical_unscoped_parent_remains_phrase_protected(tmp_path, namespace):
    parts = fixture(tmp_path)
    _, directory, _, parent, _, _ = parts
    copy = directory / namespace / "unselected-identical-parent.json"
    copy.parent.mkdir(exist_ok=True)
    copy.write_bytes(Path(parent["path"]).read_bytes())
    atomic_json(directory / "checkpoint.local.json", {"copy": artifact_ref(copy)})
    _, phrases, graph = observe(parts)
    assert PHRASE in phrases
    assert any(row["path"] == str(copy) for row in graph["known_refs"])
    scan = privacy.Scan({}, phrases)
    scan.payload(PHRASE.encode(), "synthetic-ordinary-body")
    assert any(row["kind"] == "protected_transcript_phrase" for row in scan.findings)


def test_private_source_digest_cannot_become_authority_after_graph_walk(tmp_path):
    parts = fixture(tmp_path)
    _, directory, _, _, authority, _ = parts
    source = json.loads(Path(authority["path"]).read_bytes())["source"]
    private_copy = directory / "transcripts" / "copied-private-source.py"
    private_copy.parent.mkdir(exist_ok=True)
    private_copy.write_bytes(Path(source["path"]).read_bytes())
    with pytest.raises(TalkCutError, match="Known private bytes cannot supply review text source authority"):
        observe(parts)


@pytest.mark.parametrize("mutation", ["missing", "duplicate_ref", "same_bytes_different_path", "unconsumed"])
def test_explicit_authority_roots_remain_complete_and_unambiguous(tmp_path, mutation):
    parts = fixture(tmp_path)
    authority = parts[-2]
    if mutation == "missing":
        roots = []
    elif mutation == "duplicate_ref":
        roots = [authority, authority]
    elif mutation == "same_bytes_different_path":
        copy = Path(authority["path"]).with_name("authority-copy.json")
        copy.write_bytes(Path(authority["path"]).read_bytes())
        roots = [authority, artifact_ref(copy)]
    else:
        extra = Path(authority["path"]).with_name("unconsumed.json")
        atomic_json(extra, {"schema_version": "synthetic-unused-authority/v1"})
        roots = [authority, artifact_ref(extra)]
    with pytest.raises(TalkCutError):
        direct(parts, authorities=roots)


@pytest.mark.parametrize("target", ["parent", "source", "script", "command"])
def test_stale_complete_dependency_is_rejected(tmp_path, target):
    parts = fixture(tmp_path)
    parent, authority = parts[-3:-1]
    selected = json.loads(Path(authority["path"]).read_bytes())
    path = Path(parent["path"] if target == "parent" else selected[target]["path"])
    path.write_bytes(path.read_bytes() + b"\n")
    with pytest.raises(TalkCutError):
        observe(parts)


def test_unselected_sibling_change_during_real_traversal_is_rejected(tmp_path, monkeypatch):
    parts = fixture(tmp_path)
    parent = Path(parts[-3]["path"])
    original = Path.read_text
    fired = []

    def changing_read(path, *args, **kwargs):
        value = original(path, *args, **kwargs)
        if path == parent and not fired:
            fired.append(str(path))
            data = json.loads(value)
            data["staged_execution"]["scope"] += " Synthetic concurrent sibling change."
            atomic_json(path, data)
        return value

    monkeypatch.setattr(Path, "read_text", changing_read)
    with pytest.raises(TalkCutError, match="Review text origin bytes or identity changed"):
        observe(parts)
    assert fired == [str(parent)]


def publication(parts, tmp_path, *, private_source=False):
    root, _, _, _, authority, locators = parts
    ref = publication_input(root, tmp_path)
    raw = json.loads(Path(ref["path"]).read_bytes())
    corpus_path = Path(raw["private_corpus"]["path"])
    corpus = json.loads(corpus_path.read_bytes())
    corpus["protected_transcript_phrases"] = [PHRASE]
    if private_source:
        source = json.loads(Path(authority["path"]).read_bytes())["source"]
        corpus["file_hashes"].append({"sha256": source["sha256"], "kind": "review"})
    atomic_json(corpus_path, corpus)
    raw["private_corpus"] = artifact_ref(corpus_path)
    body = Path(raw["pr_body"]["path"])
    body.write_text(PHRASE)
    raw["pr_body"] = artifact_ref(body)
    raw["review_text_origins"] = locators
    raw["review_text_origin_authorities"] = [authority]
    atomic_json(ref["path"], raw)
    return artifact_ref(ref["path"])


def test_explicit_submitted_phrase_survives_in_complete_publication_consumer(tmp_path):
    parts = fixture(tmp_path)
    root, directory, registered, _, _, _ = parts
    ref = publication(parts, tmp_path)
    result = privacy.verify_release_privacy(ref, root, project_dir=directory,
                                            expected_source_hashes=registered)
    assert result["status"] != "PASS"
    digest = hashlib.sha256(PHRASE.encode()).hexdigest()
    assert any(row["kind"] == "protected_transcript_phrase" and row["matched_sha256"] == digest
               for row in result["findings"])


def test_explicit_private_source_digest_refused_by_publication_consumer(tmp_path):
    parts = fixture(tmp_path)
    root, directory, registered, _, _, _ = parts
    ref = publication(parts, tmp_path, private_source=True)
    with pytest.raises(TalkCutError, match="Explicit or audited private corpus bytes"):
        privacy.verify_release_privacy(ref, root, project_dir=directory,
                                       expected_source_hashes=registered)
