"""Generated selected refs across object formats; no retained private payloads."""
import pytest
from test_privacy_git_structural import (
    commit_value,
    found,
    git,
    object_value,
    repository,
)

from talkcut import privacy_checks as privacy


@pytest.mark.parametrize("algorithm", ["sha1", "sha256"])
@pytest.mark.parametrize("kind", ["blob", "tree", "tag", "commit"])
def test_every_selected_direct_ref_payload_is_accounted(tmp_path, algorithm, kind):
    root, empty_tree, _, child = repository(tmp_path, algorithm)
    phrase = "Synthetic protected field found only beyond a selected direct reference."
    blob = object_value("blob", phrase.encode(), algorithm)
    git(root, "hash-object", "-w", "--stdin", data=blob.data)
    if kind == "blob":
        oid = blob.oid
    elif kind == "tree":
        oid = git(root, "mktree", data=f"100644 blob {blob.oid}\tnote.txt\n".encode()).strip().decode()
    elif kind == "tag":
        tag = f"object {blob.oid}\ntype blob\ntag fixture\ntagger Fixture <fixture@example.invalid> 1 +0000\n\nPublic synthetic tag\n".encode()
        oid = git(root, "hash-object", "-t", "tag", "-w", "--stdin", data=tag).strip().decode()
    else:
        commit = commit_value(empty_tree, message=phrase.encode())
        oid = git(root, "hash-object", "-t", "commit", "-w", "--stdin", data=commit.data).strip().decode()
    git(root, "update-ref", "refs/fixture/selected", oid)
    scanner = privacy.Scan({}, [phrase])
    privacy._git_inventory(root, child.oid, scanner, [])
    assert found(scanner, phrase), "a supported selected object and its payload were omitted"


@pytest.mark.parametrize("algorithm", ["sha1", "sha256"])
def test_replacement_tree_retains_original_and_replacement_leaves(tmp_path, algorithm):
    root, _, parent, _ = repository(tmp_path, algorithm)
    phrases = ["Synthetic protected text retained in the original tree payload.",
               "Synthetic protected text retained in the replacement tree payload."]
    trees = []
    for phrase in phrases:
        blob = object_value("blob", phrase.encode(), algorithm)
        git(root, "hash-object", "-w", "--stdin", data=blob.data)
        oid = git(root, "mktree", data=f"100644 blob {blob.oid}\tnote.txt\n".encode()).strip().decode()
        trees.append(privacy._verified_git_object(oid, "tree", algorithm, git(root, "cat-file", "tree", oid)))
    child = commit_value(trees[0], (parent,))
    git(root, "hash-object", "-t", "commit", "-w", "--stdin", data=child.data)
    git(root, "update-ref", "refs/heads/main", child.oid)
    git(root, "replace", trees[0].oid, trees[1].oid)
    scanner = privacy.Scan({}, phrases)
    privacy._git_inventory(root, child.oid, scanner, [])
    assert all(found(scanner, phrase) for phrase in phrases)
