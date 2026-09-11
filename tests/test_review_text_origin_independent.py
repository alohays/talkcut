"""Synthetic opposition of selected-origin gates; no genuine audit execution claim."""
import copy
import json
from pathlib import Path

import pytest
from test_privacy_checks import commit, git
from test_privacy_review_text_origins import PHRASE, authorize, fixture, observe

from talkcut import privacy_checks as privacy
from talkcut.project import TalkCutError, artifact_ref, atomic_json


def direct(parts, locators=None, authorities=None):
    root, directory, registered, _, locator = parts
    return privacy._review_text_origin_inventory(
        locators or [locator], directory, root, set(registered.values()),
        authorities or [locator["authority"]],
    )


@pytest.mark.parametrize("kind", ["python_inspection", "document_paragraph"])
@pytest.mark.parametrize("field", ["reason", "metadata", "producer", "code_identity", "approved", "source_provenance"])
def test_equal_text_in_unselected_nested_field_still_blocks_publication(tmp_path, kind, field):
    parts = fixture(tmp_path, kind)
    parent = parts[3]
    original = json.loads(parent.read_bytes())
    original[field] = {"schema_version": "unverified-note/v1", "text": [PHRASE]}
    atomic_json(parent, original)
    authorize(parts)  # Declare this synthetic fixture's fixed original parent.
    _, protected, _ = observe(parts)
    scan = privacy.Scan({}, protected)
    scan.payload(PHRASE.encode(), "synthetic-publication")
    assert PHRASE in protected
    assert any(f["kind"] == "protected_transcript_phrase" for f in scan.findings)


@pytest.mark.parametrize("kind", ["python_inspection", "document_paragraph"])
def test_new_commit_does_not_replace_fixed_original_source_authority(tmp_path, kind):
    parts = fixture(tmp_path, kind)
    root, _, _, _, locator = parts
    source = root / locator["source"]["git_path"]
    source.write_text(source.read_text() + "\n# An unrelated later public change.\n")
    commit(root)
    changed = copy.deepcopy(locator)
    changed["source"]["git_revision"] = git(root, "rev-parse", "HEAD")
    changed["source"]["git_blob"] = git(root, "rev-parse", "HEAD:" + changed["source"]["git_path"])
    preserved = tmp_path / "later-source.txt"
    preserved.write_bytes(source.read_bytes())
    changed["source"]["snapshot"] = artifact_ref(preserved)
    with pytest.raises(TalkCutError, match="original request and verification maps"):
        direct(parts, [changed])
    assert len(direct(parts)) == 1


@pytest.mark.parametrize("member", ["producer", "request", "verification"])
@pytest.mark.parametrize("mutation", ["content", "same_byte_inode"])
def test_authority_mutation_after_last_long_read_rejects(tmp_path, monkeypatch, member, mutation):
    parts = fixture(tmp_path)
    locator = parts[-1]
    root = json.loads(Path(locator["authority"]["path"]).read_bytes())
    target = Path(root[member]["path"])
    original = target.read_bytes()
    original_command = privacy._command
    fired = []

    def command(argv, cwd, traces, **kwargs):
        value = original_command(argv, cwd, traces, **kwargs)
        if argv[:4] == ["git", "--no-replace-objects", "cat-file", "blob"] and not fired:
            fired.append(True)
            if mutation == "same_byte_inode":
                replacement = target.with_suffix(".replacement")
                replacement.write_bytes(original)
                replacement.replace(target)
            else:
                target.write_bytes(original + b"\n")
        return value

    monkeypatch.setattr(privacy, "_command", command)
    with pytest.raises(TalkCutError, match="identity changed"):
        direct(parts)
    assert fired == [True]


@pytest.mark.parametrize("position", ["authority", "snapshot"])
def test_ordinary_origin_file_bound_rejects_before_read(tmp_path, monkeypatch, position):
    parts = fixture(tmp_path)
    huge = tmp_path / "oversized-origin"
    with huge.open("wb") as stream:
        stream.truncate(privacy.MAX_UNIT_BYTES + 1)
    ref = {"path": str(huge), "sha256": "0" * 64}
    locator = copy.deepcopy(parts[-1])
    authorities = None
    if position == "authority":
        locator["authority"] = ref
        authorities = [ref]
    else:
        locator["source"]["snapshot"] = ref
    original_read = Path.read_bytes
    attempted = []

    def read(path):
        if path == huge:
            attempted.append(True)
            raise AssertionError("oversized payload was opened")
        return original_read(path)

    monkeypatch.setattr(Path, "read_bytes", read)
    with pytest.raises(TalkCutError, match="oversized"):
        direct(parts, [locator], authorities)
    assert not attempted


@pytest.mark.parametrize("kind", ["document_paragraph", "document_complete"])
def test_two_valid_document_authorities_do_not_depend_on_cache_order(tmp_path, kind):
    parts = fixture(tmp_path, "document_paragraph")
    if kind == "document_complete":
        parent = parts[3]
        value = json.loads(parent.read_bytes())
        value["documentation_reviews"][0]["claims"][0]["quote"] = Path(parts[-1]["source"]["snapshot"]["path"]).read_text().strip()
        atomic_json(parent, value)
        parts[-1]["kind"] = kind
        del parts[-1]["paragraph_index"]
        authorize(parts)
    locator = parts[-1]
    second = copy.deepcopy(locator)
    second_parent = parts[3].with_name("second-response.json")
    second_parent.write_bytes(parts[3].read_bytes())
    second["parent"] = artifact_ref(second_parent)
    authority = json.loads(Path(locator["authority"]["path"]).read_bytes())
    authority["response"] = second["parent"]
    second_root = tmp_path / "second-root.json"
    atomic_json(second_root, authority)
    second["authority"] = artifact_ref(second_root)
    # Each declared structural packet is accepted on its own.
    assert len(direct(parts, [locator], [locator["authority"]])) == 1
    assert len(direct(parts, [second], [second["authority"]])) == 1
    both = direct(parts, [locator, second], [locator["authority"], second["authority"]])
    assert len(both) == 2
    assert sum(len(row["extractions"]) for row in both) == 2
    assert all(row["claim_status"] == "UNVERIFIED" for row in both)
