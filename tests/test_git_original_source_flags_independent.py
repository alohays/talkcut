"""Selected original source authority survives unrelated Git replacement objects."""

import hashlib
from pathlib import Path

import pytest
from test_privacy_git_structural import git
from test_privacy_review_text_origins import fixture
from test_review_text_origin_independent import direct

from talkcut import privacy_checks as privacy


@pytest.mark.parametrize("kind", ["blob", "tree", "commit"])
def test_original_bound_source_is_read_with_replacement_disabled(tmp_path, monkeypatch, kind):
    parts = fixture(tmp_path)
    root, _, _, _, locator = parts
    source = locator["source"]
    snapshot = Path(source["snapshot"]["path"])
    before = hashlib.sha256(snapshot.read_bytes()).hexdigest()
    original_commit = source["git_revision"]
    original_tree = git(root, "rev-parse", original_commit + "^{tree}").strip().decode()
    empty_tree = git(root, "mktree", data=b"").strip().decode()
    if kind == "blob":
        selected = source["git_blob"]
        replacement = git(root, "hash-object", "-w", "--stdin", data=b"unrelated bytes\n").strip().decode()
    elif kind == "tree":
        selected, replacement = original_tree, empty_tree
    else:
        selected = original_commit
        replacement = git(root, "commit-tree", empty_tree, data=b"unrelated commit\n").strip().decode()
    git(root, "replace", selected, replacement)
    assert git(root, "cat-file", kind, selected) != git(root, "--no-replace-objects", "cat-file", kind, selected)
    command = privacy._command
    calls = []

    def observed(argv, cwd, traces, **kwargs):
        calls.append(argv)
        return command(argv, cwd, traces, **kwargs)

    monkeypatch.setattr(privacy, "_command", observed)
    assert len(direct(parts)) == 1
    assert len(calls) == 3
    assert all(argv[:2] == ["git", "--no-replace-objects"] for argv in calls)
    assert hashlib.sha256(snapshot.read_bytes()).hexdigest() == before
