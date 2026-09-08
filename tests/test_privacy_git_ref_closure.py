"""Selected-object closure controls use generated local Git object databases."""
import hashlib

import pytest
from test_privacy_git_structural import found, git, object_value, repository

from talkcut import privacy_checks as privacy
from talkcut.project import TalkCutError


def write(root, obj):
    assert git(root, "hash-object", "-t", obj.kind, "-w", "--stdin", data=obj.data).strip().decode() == obj.oid
    return obj.oid


def tag(root, oid, kind, algorithm, body=b"Public synthetic tag\n"):
    return write(root, object_value("tag", (f"object {oid}\ntype {kind}\ntag fixture\ntagger Fixture <f@example.invalid> 1 +0000\n\n").encode() + body, algorithm))


@pytest.mark.parametrize("algorithm", ["sha1", "sha256"])
def test_nested_tags_retain_leaf_and_each_annotation(algorithm, tmp_path):
    root, _, _, child = repository(tmp_path, algorithm)
    leaf_phrase = "Synthetic selected leaf phrase beyond nested annotated tags."
    tag_phrase = "Synthetic protected annotation in an inner selected tag."
    leaf = write(root, object_value("blob", leaf_phrase.encode(), algorithm))
    inner = tag(root, leaf, "blob", algorithm, tag_phrase.encode())
    outer = tag(root, inner, "tag", algorithm)
    git(root, "update-ref", "refs/fixture/nested", outer)
    scanner = privacy.Scan({}, [leaf_phrase, tag_phrase])
    result = privacy._git_inventory(root, child.oid, scanner, [])
    assert found(scanner, leaf_phrase) and found(scanner, tag_phrase) and not scanner.unknown
    assert set(result["annotated_tags"]) == {inner, outer}
    assert {r["oid"] for r in result["selected_ref_objects"]} == {child.oid, leaf, inner, outer}
    assert len(result["selected_refs"]) == 2


@pytest.mark.parametrize("algorithm", ["sha1", "sha256"])
def test_tagged_tree_reads_all_nested_leaves_but_raw_tree_stays_unverified(algorithm, tmp_path):
    root, _, _, child = repository(tmp_path, algorithm)
    phrase = "Synthetic protected prose inside a deeply nested selected tree leaf."
    leaf = write(root, object_value("blob", phrase.encode(), algorithm))
    tree = git(root, "mktree", data=f"100644 blob {leaf}\tleaf.txt\n".encode()).strip().decode()
    for name in ("nested", "outer"):
        tree = git(root, "mktree", data=f"040000 tree {tree}\t{name}\n".encode()).strip().decode()
    top = tag(root, tree, "tree", algorithm)
    git(root, "update-ref", "refs/fixture/tree", top)
    scanner = privacy.Scan({}, [phrase])
    result = privacy._git_inventory(root, child.oid, scanner, [])
    assert found(scanner, phrase)
    assert any("tree metadata" in r["reason"] for r in scanner.unknown)
    assert {r["oid"] for r in result["selected_ref_objects"]}.issuperset({child.oid, top, tree, leaf})
    assert any(r["location"].endswith("outer/nested/leaf.txt") for r in scanner.findings)


def test_empty_selected_tree_cannot_claim_complete_text_inspection(tmp_path):
    root, tree, _, child = repository(tmp_path)
    git(root, "update-ref", "refs/fixture/empty", tree.oid)
    scanner = privacy.Scan({}, [])
    result = privacy._git_inventory(root, child.oid, scanner, [])
    assert scanner.unknown and not scanner.findings
    assert any(r["oid"] == tree.oid and r["bytes"] == 0 for r in result["selected_ref_objects"])


def test_symlink_leaf_retains_literal_bytes_and_is_not_followed(tmp_path):
    root, _, _, child = repository(tmp_path)
    phrase = "Synthetic protected symlink target literal text in a selected tree."
    leaf = write(root, object_value("blob", phrase.encode()))
    tree = git(root, "mktree", data=f"120000 blob {leaf}\tlink\n".encode()).strip().decode()
    git(root, "update-ref", "refs/fixture/link-tree", tree)
    scanner = privacy.Scan({}, [phrase])
    result = privacy._git_inventory(root, child.oid, scanner, [])
    assert found(scanner, phrase) and any("link was not followed" in r["reason"] for r in scanner.unknown)
    assert any(r["oid"] == leaf for r in result["selected_ref_objects"])


def test_submodule_tree_remains_explicitly_unverified(tmp_path):
    root, _, _, child = repository(tmp_path)
    tree = git(root, "mktree", data=f"160000 commit {child.oid}\tsubmodule\n".encode()).strip().decode()
    git(root, "update-ref", "refs/fixture/submodule-tree", tree)
    scanner = privacy.Scan({}, [])
    privacy._git_inventory(root, child.oid, scanner, [])
    assert any("submodule" in r["reason"] for r in scanner.unknown)


@pytest.mark.parametrize("kind", ["review", "credentials", "media", "transcript"])
def test_selected_private_blob_uses_original_digest_precedence(tmp_path, kind):
    root, _, _, child = repository(tmp_path)
    data = b"Synthetic private full artifact selected only by a direct ref."
    leaf = write(root, object_value("blob", data))
    git(root, "update-ref", "refs/fixture/private", leaf)
    scanner = privacy.Scan({hashlib.sha256(data).hexdigest(): kind}, [])
    result = privacy._git_inventory(root, child.oid, scanner, [])
    assert any(r["kind"] == "private_" + kind for r in scanner.findings)
    assert any(r["oid"] == leaf for r in result["selected_ref_objects"])


@pytest.mark.parametrize("case", ["wrong_type", "wrong_width", "unknown_type", "extra_field", "duplicate_name", "count_bound"])
def test_selected_ref_list_must_remain_closed_and_bounded(tmp_path, monkeypatch, case):
    root, _, _, child = repository(tmp_path)
    original = privacy._command
    fired = []

    def changed(argv, cwd, traces, **kwargs):
        result = original(argv, cwd, traces, **kwargs)
        if "for-each-ref" in argv:
            fired.append(True)
            if case == "wrong_type":
                return result.replace(b" commit\n", b" blob\n")
            if case == "wrong_width":
                return result.replace(child.oid.encode(), b"a" * 41)
            if case == "unknown_type":
                return result.replace(b" commit\n", b" unsupported\n")
            if case == "extra_field":
                return result.rstrip() + b" extra\n"
            if case == "duplicate_name":
                return result + result
            return result + result.replace(b"refs/heads/main", b"refs/fixture/other") * (privacy.MAX_UNITS + 1)
        return result

    monkeypatch.setattr(privacy, "_command", changed)
    with pytest.raises(TalkCutError):
        privacy._git_inventory(root, child.oid, privacy.Scan({}, []), [])
    assert fired
