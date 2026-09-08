"""Actual synthetic Git replacement refs must not hide publishable object bytes."""
from test_privacy_git_structural import (
    commit_value,
    found,
    git,
    object_value,
    repository,
)

from talkcut import privacy_checks as privacy


def test_blob_replacement_ref_payload_remains_in_selected_scan(tmp_path):
    root, _, parent, _ = repository(tmp_path)
    original = object_value("blob", b"Public synthetic fixture bytes.\n")
    phrase = "Synthetic protected prose retained only inside a replacement blob object."
    replacement = object_value("blob", phrase.encode())
    for obj in (original, replacement):
        assert git(root, "hash-object", "-w", "--stdin", data=obj.data).strip().decode() == obj.oid
    tree_oid = git(root, "mktree", data=f"100644 blob {original.oid}\tfixture.txt\n".encode()).strip().decode()
    tree = privacy._verified_git_object(tree_oid, "tree", "sha1", git(root, "cat-file", "tree", tree_oid))
    child = commit_value(tree, (parent,))
    git(root, "hash-object", "-t", "commit", "-w", "--stdin", data=child.data)
    git(root, "update-ref", "refs/heads/main", child.oid)
    git(root, "replace", original.oid, replacement.oid)
    assert git(root, "cat-file", "blob", original.oid) == replacement.data
    assert git(root, "--no-replace-objects", "cat-file", "blob", original.oid) == original.data
    assert replacement.oid.encode() in git(root, "for-each-ref", "--format=%(objectname)")
    scanner = privacy.Scan({}, [phrase])
    result = privacy._git_inventory(root, child.oid, scanner, [])
    assert not scanner.unknown
    assert result["original_objects_without_replacements"] is True
    assert found(scanner, phrase), "selected replacement blob ref's full payload was never scanned"
