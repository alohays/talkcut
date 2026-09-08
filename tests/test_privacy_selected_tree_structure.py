"""Generated selected trees exercise exact binary grammar and ordinary protection."""
import gzip
import hashlib

import pytest
from test_privacy_git_structural import found, git, object_value, repository

from talkcut import privacy_checks as privacy
from talkcut.project import TalkCutError


def entry(mode, name, oid):
    return mode + b" " + name + b"\0" + bytes.fromhex(oid)


def write(root, obj):
    assert git(root, "hash-object", "-t", obj.kind, "-w", "--stdin", data=obj.data).strip().decode() == obj.oid
    return obj.oid


def selected(root, child, obj, phrases=(), private=None):
    write(root, obj)
    git(root, "update-ref", "refs/fixture/tree", obj.oid)
    scan = privacy.Scan(private or {}, list(phrases))
    report = privacy._git_inventory(root, child.oid, scan, [])
    return scan, report


@pytest.mark.parametrize("algorithm", ["sha1", "sha256"])
def test_nested_tree_retains_all_raw_objects_names_paths_and_leaves(tmp_path, algorithm):
    root, _, _, child = repository(tmp_path, algorithm)
    phrase = "Synthetic protected selected leaf sentence."
    blob = object_value("blob", phrase.encode(), algorithm)
    write(root, blob)
    subtree = object_value("tree", entry(b"100755", b"leaf.txt", blob.oid), algorithm)
    write(root, subtree)
    tree = object_value("tree", entry(b"40000", b"folder", subtree.oid), algorithm)
    scan, report = selected(root, child, tree, [phrase])
    assert found(scan, phrase) and not scan.unknown
    assert {r["oid"] for r in report["selected_ref_objects"]}.issuperset({tree.oid, subtree.oid, blob.oid})
    assert {r["sha256"] for r in scan.units}.issuperset(hashlib.sha256(x.data).hexdigest() for x in (tree, subtree, blob))
    assert {r["oid"] for r in report["selected_tree_structures"]} == {tree.oid, subtree.oid}
    paths = {e["path"] for r in report["selected_tree_structures"] for e in r["entries"]}
    assert paths == {"folder", "folder/leaf.txt"}


@pytest.mark.parametrize("algorithm", ["sha1", "sha256"])
def test_empty_tree_has_zero_entries_and_retained_raw_unit(tmp_path, algorithm):
    root, tree, _, child = repository(tmp_path, algorithm)
    scan, report = selected(root, child, tree)
    assert not scan.unknown and not scan.findings
    assert len(report["selected_tree_structures"]) == 1
    assert report["selected_tree_structures"][0]["entries"] == []
    assert any(u["bytes"] == 0 and u["sha256"] == hashlib.sha256(b"").hexdigest() for u in scan.units)


@pytest.mark.parametrize("mutation", ["missing_space", "missing_nul", "short_oid", "extra_tail", "empty_name", "slash",
                                      "dot", "dotdot", "git_directory", "control", "non_utf8", "zero_oid", "bad_mode",
                                      "noncanonical_mode", "duplicate", "duplicate_file_directory", "wrong_order"])
@pytest.mark.parametrize("algorithm", ["sha1", "sha256"])
def test_bad_binary_records_never_gain_structural_context(mutation, algorithm):
    blob = object_value("blob", b"Public generated contents", algorithm)
    data = entry(b"100644", b"name", blob.oid)
    if mutation == "missing_space":
        data = data.replace(b" ", b"", 1)
    elif mutation == "missing_nul":
        data = data.replace(b"\0", b"", 1)
    elif mutation == "short_oid":
        data = data[:-1]
    elif mutation == "extra_tail":
        data += b"X"
    elif mutation in {"empty_name", "slash", "dot", "dotdot", "git_directory", "control", "non_utf8"}:
        name = {"empty_name": b"", "slash": b"a/b", "dot": b".", "dotdot": b"..", "git_directory": b".GiT",
                "control": b"a\nb", "non_utf8": b"bad\xff"}[mutation]
        data = entry(b"100644", name, blob.oid)
    elif mutation == "zero_oid":
        data = entry(b"100644", b"name", "0" * len(blob.oid))
    elif mutation in {"bad_mode", "noncanonical_mode"}:
        data = entry(b"100664" if mutation == "bad_mode" else b"040000", b"name", blob.oid)
    elif mutation == "duplicate":
        data += data
    elif mutation == "duplicate_file_directory":
        data += entry(b"40000", b"name", blob.oid)
    else:
        data += entry(b"100644", b"earlier", blob.oid)
    tree = object_value("tree", data, algorithm)
    with pytest.raises(TalkCutError):
        privacy._git_tree_entries(tree)
    scan = privacy.Scan({}, [])
    with pytest.raises(TalkCutError):
        scan._tree_payload(privacy._GitTreeContext(tree, tree.oid, (), ()))
    assert not scan.git_tree_structural


def test_git_directory_order_is_not_naive_name_order(tmp_path):
    root, _, _, child = repository(tmp_path)
    blob = object_value("blob", b"Public fixture\n")
    write(root, blob)
    subtree = object_value("tree", entry(b"100644", b"z", blob.oid))
    write(root, subtree)
    tree = object_value("tree", entry(b"100644", b"a.c", blob.oid) + entry(b"40000", b"a", subtree.oid))
    scan, _ = selected(root, child, tree)
    assert not scan.unknown
    wrong = object_value("tree", entry(b"40000", b"a", subtree.oid) + entry(b"100644", b"a.c", blob.oid))
    with pytest.raises(TalkCutError, match="order"):
        privacy._git_tree_entries(wrong)


@pytest.mark.parametrize("ordinary_first", [False, True])
@pytest.mark.parametrize("container", ["blob", "gzip"])
def test_identical_ordinary_tree_bytes_do_not_reuse_binary_context(tmp_path, ordinary_first, container):
    root, _, _, _child = repository(tmp_path)
    blob = object_value("blob", b"Public fixture\n")
    write(root, blob)
    tree = object_value("tree", entry(b"100644", b"leaf.txt", blob.oid))
    write(root, tree)
    scan = privacy.Scan({}, [])
    data = gzip.compress(tree.data) if container == "gzip" else tree.data
    if ordinary_first:
        scan.payload(data, "ordinary")
    privacy._selected_tree_inventory(tree, scan, lambda oid, kind: blob, lambda obj: None,
                                    f"100644 blob {blob.oid}\tleaf.txt\0".encode())
    if not ordinary_first:
        scan.payload(data, "ordinary")
    assert scan.unknown and all(r["location"].startswith("ordinary") for r in scan.unknown)
    assert len(scan.git_tree_structural) == 1
    assert sum(u["sha256"] == hashlib.sha256(tree.data).hexdigest() for u in scan.units) == 1


@pytest.mark.parametrize("kind", ["review", "transcript", "media", "credentials"])
def test_exact_private_tree_digest_precedes_structural_interpretation(tmp_path, kind):
    root, _, _, child = repository(tmp_path)
    tree = object_value("tree", b"")
    digest = hashlib.sha256(tree.data).hexdigest()
    scan, _ = selected(root, child, tree, private={digest: kind})
    assert any(f["kind"] == "private_" + kind and f["sha256"] == digest for f in scan.findings)
    assert not scan.git_tree_structural


def test_names_and_shared_subtree_prefixes_remain_protected(tmp_path):
    root, _, _, child = repository(tmp_path)
    token = "ghp_" + "A" * 36
    blob = object_value("blob", b"Public fixture\n")
    write(root, blob)
    subtree = object_value("tree", entry(b"100644", token.encode(), blob.oid))
    write(root, subtree)
    tree = object_value("tree", entry(b"40000", b"alpha", subtree.oid) + entry(b"40000", b"beta", subtree.oid))
    phrase = "beta/" + token
    scan, report = selected(root, child, tree, [phrase])
    assert found(scan, phrase) and scan.credentials and not scan.unknown
    assert {r["path"] for r in report["selected_tree_structures"]} == {"", "alpha", "beta"}
    assert len([f for f in scan.findings if f["kind"] == "github_token"]) == 2


@pytest.mark.parametrize("name", ["projects", ".env", ".env.secret"])
def test_existing_private_path_gate_also_applies_to_empty_directories(tmp_path, name):
    root, _, _, child = repository(tmp_path)
    empty = object_value("tree", b"")
    write(root, empty)
    tree = object_value("tree", entry(b"40000", name.encode(), empty.oid))
    scan, _ = selected(root, child, tree)
    assert any("Private project/environment" in r["reason"] for r in scan.unknown)


@pytest.mark.parametrize("mutation", ["wrong_kind", "wrong_oid", "wrong_bytes", "wrong_algorithm", "omitted_listing", "wrong_listing_path"])
def test_complete_child_identity_and_listing_must_match(mutation):
    blob = object_value("blob", b"Public fixture\n")
    tree = object_value("tree", entry(b"100644", b"file", blob.oid))
    returned = blob
    listing = f"100644 blob {blob.oid}\tfile\0".encode()
    if mutation == "wrong_kind":
        returned = privacy._GitObject(blob.oid, "tree", "sha1", blob.data)
    elif mutation == "wrong_oid":
        returned = object_value("blob", b"other")
    elif mutation == "wrong_bytes":
        returned = privacy._GitObject(blob.oid, "blob", "sha1", b"changed")
    elif mutation == "wrong_algorithm":
        returned = privacy._GitObject(blob.oid, "blob", "sha256", blob.data)
    elif mutation == "omitted_listing":
        listing = b""
    else:
        listing = listing.replace(b"file", b"other")
    scan = privacy.Scan({}, [])
    with pytest.raises(TalkCutError):
        privacy._selected_tree_inventory(tree, scan, lambda oid, kind: returned, lambda obj: None, listing)
    assert not scan.git_tree_structural


def test_external_marker_and_display_label_do_not_mint_context():
    scan = privacy.Scan({}, [])
    with pytest.raises(TalkCutError):
        scan._tree_payload({"tree": {}, "entries": []})
    with pytest.raises(TypeError):
        scan.payload(b"binary\0", "git-ref-tree:synthetic", tree_context={})
    scan.payload(b"binary\0", "git-ref-tree:synthetic")
    assert scan.unknown and not scan.git_tree_structural


@pytest.mark.parametrize("limit", ["unit", "entries", "paths"])
def test_finite_bounds_refuse_before_structural_promotion(monkeypatch, limit):
    blob = object_value("blob", b"Public fixture")
    tree = object_value("tree", entry(b"100644", b"file", blob.oid))
    if limit == "unit":
        monkeypatch.setattr(privacy, "MAX_UNIT_BYTES", len(tree.data)-1)
    elif limit == "entries":
        monkeypatch.setattr(privacy, "MAX_UNITS", 0)
    else:
        monkeypatch.setattr(privacy, "MAX_TOTAL_BYTES", 3)
    scan = privacy.Scan({}, [])
    with pytest.raises(TalkCutError):
        privacy._selected_tree_inventory(tree, scan, lambda oid, kind: blob, lambda obj: None,
                                        f"100644 blob {blob.oid}\tfile\0".encode())
    assert not scan.git_tree_structural


@pytest.mark.parametrize("case", ["truncated", "unsafe_name", "wrong_order", "unsupported_mode", "zero_oid"])
def test_actual_malformed_selected_root_remains_unknown(tmp_path, case):
    root, _, _, child = repository(tmp_path)
    blob = object_value("blob", b"Public fixture\n")
    write(root, blob)
    data = entry(b"100644", b"z", blob.oid)
    if case == "truncated":
        data = data[:-1]
    elif case == "unsafe_name":
        data = entry(b"100644", b"../file", blob.oid)
    elif case == "wrong_order":
        data += entry(b"100644", b"a", blob.oid)
    elif case == "unsupported_mode":
        data = entry(b"100664", b"file", blob.oid)
    else:
        data = entry(b"100644", b"file", "0" * 40)
    oid = git(root, "hash-object", "--literally", "-t", "tree", "-w", "--stdin", data=data).strip().decode()
    git(root, "update-ref", "refs/fixture/malformed", oid)
    scan = privacy.Scan({}, [])
    report = privacy._git_inventory(root, child.oid, scan, [])
    assert any("structural inspection failed" in r["reason"] for r in scan.unknown)
    assert not report["selected_tree_structures"]
    assert any(r["oid"] == oid and r["sha256"] == hashlib.sha256(data).hexdigest() for r in report["selected_ref_objects"])


@pytest.mark.parametrize("case", ["missing_child", "changed_listing"])
def test_actual_selected_tree_refuses_incomplete_current_readback(tmp_path, monkeypatch, case):
    root, _, _, child = repository(tmp_path)
    blob = object_value("blob", b"Public fixture\n")
    write(root, blob)
    tree = object_value("tree", entry(b"100644", b"file", blob.oid))
    write(root, tree)
    git(root, "update-ref", "refs/fixture/tree", tree.oid)
    command = privacy._command
    fired = []

    def changed(argv, cwd, traces, **kwargs):
        if case == "missing_child" and argv[-3:] == ["cat-file", "-t", blob.oid]:
            fired.append(True)
            (root / ".git" / "objects" / blob.oid[:2] / blob.oid[2:]).unlink()
        data = command(argv, cwd, traces, **kwargs)
        if case == "changed_listing" and argv[-5:] == ["ls-tree", "-r", "-z", "--full-tree", tree.oid]:
            fired.append(True)
            return b""
        return data

    monkeypatch.setattr(privacy, "_command", changed)
    scan = privacy.Scan({}, [])
    report = privacy._git_inventory(root, child.oid, scan, [])
    assert fired == [True]
    assert scan.unknown and not report["selected_tree_structures"]


def test_shared_subtree_counts_each_path_occurrence_before_context(monkeypatch):
    blob = object_value("blob", b"Public fixture")
    subtree = object_value("tree", entry(b"100644", b"file", blob.oid))
    tree = object_value("tree", entry(b"40000", b"a", subtree.oid) + entry(b"40000", b"b", subtree.oid))
    objects = {o.oid: o for o in (blob, subtree, tree)}
    monkeypatch.setattr(privacy, "MAX_UNITS", 3)
    scan = privacy.Scan({}, [])
    with pytest.raises(TalkCutError, match="path traversal"):
        privacy._selected_tree_inventory(tree, scan, lambda oid, kind: objects[oid], lambda obj: None, b"")
    assert not scan.git_tree_structural


def test_explicit_depth_limit_is_independent_of_unique_objects(monkeypatch):
    tree = object_value("tree", b"")
    objects = {tree.oid: tree}
    for _ in range(3):
        tree = object_value("tree", entry(b"40000", b"d", tree.oid))
        objects[tree.oid] = tree
    monkeypatch.setattr(privacy, "MAX_GIT_TREE_DEPTH", 2)
    scan = privacy.Scan({}, [])
    with pytest.raises(TalkCutError, match="depth"):
        privacy._selected_tree_inventory(tree, scan, lambda oid, kind: objects[oid], lambda obj: None, b"")
    assert not scan.git_tree_structural
