"""Synthetic local objects only; no real publication or private phrase is used."""

import gzip
import hashlib
import io
import json
import subprocess
import zipfile

import pytest

import talkcut.privacy_checks as privacy
from talkcut.project import TalkCutError

IDENTITY = b"Fixture <fixture@example.invalid> 1 +0000"


def object_value(kind, data, algorithm="sha1"):
    oid = hashlib.new(algorithm, kind.encode() + b" " + str(len(data)).encode() + b"\0" + data).hexdigest()
    return privacy._verified_git_object(oid, kind, algorithm, data)


def commit_value(tree, parents=(), *, message=b"Synthetic public fixture\n", extra=b"", identity=IDENTITY):
    data = b"tree " + tree.oid.encode() + b"\n"
    data += b"".join(b"parent " + p.oid.encode() + b"\n" for p in parents)
    data += b"author " + identity + b"\ncommitter " + IDENTITY + b"\n" + extra + b"\n" + message
    return object_value("commit", data, tree.algorithm)


def graph(algorithm="sha1"):
    tree = object_value("tree", b"", algorithm)
    parent = commit_value(tree)
    child = commit_value(tree, (parent,))
    return tree, parent, child


def context(tree, parent, child):
    objects = {obj.oid: obj for obj in (tree, parent, child)}
    return privacy._git_commit_context(child, frozenset((parent.oid, child.oid)), lambda oid, _: objects[oid])


def found(scanner, phrase):
    digest = hashlib.sha256(phrase.encode()).hexdigest()
    return [row for row in scanner.findings if row.get("matched_sha256") == digest]


@pytest.mark.parametrize("algorithm", ["sha1", "sha256"])
def test_complete_typed_tokens_preserve_unit_and_account_each_occurrence(algorithm):
    tree, parent, child = graph(algorithm)
    scanner = privacy.Scan({}, [tree.oid, parent.oid])
    scanner._commit_payload(context(tree, parent, child))
    assert not scanner.findings and not scanner.unknown
    assert scanner.units == [{"location": "git-commit:" + child.oid,
                              "sha256": hashlib.sha256(child.data).hexdigest(), "bytes": len(child.data)}]
    assert scanner.total_bytes == len(child.data)
    rows = scanner.git_structural_metadata
    assert len(rows) == 2 and {r["field"] for r in rows} == {"tree", "parent"}
    for row in rows:
        assert child.data[row["byte_start"]:row["byte_end"]] == row["target_oid"].encode()
        assert row["object_format"] == algorithm


@pytest.mark.parametrize("kind", ["blob", "body", "gzip", "zip"])
@pytest.mark.parametrize("ordinary_first", [False, True])
def test_identical_bytes_never_reuse_typed_exemption(kind, ordinary_first):
    tree, parent, child = graph()
    scanner = privacy.Scan({}, [parent.oid])

    def ordinary():
        if kind == "gzip":
            scanner.payload(gzip.compress(child.data), "asset.gz")
        elif kind == "zip":
            data = io.BytesIO()
            with zipfile.ZipFile(data, "w") as archive:
                archive.writestr("git-commit:" + child.oid, child.data)
            scanner.payload(data.getvalue(), "package.whl")
        else:
            scanner.payload(child.data, kind + ":" + child.oid)

    if ordinary_first:
        ordinary()
    scanner._commit_payload(context(tree, parent, child))
    if not ordinary_first:
        ordinary()
    assert len(found(scanner, parent.oid)) == 1
    assert len(scanner.git_structural_metadata) == 1
    assert len([r for r in scanner.units if r["sha256"] == hashlib.sha256(child.data).hexdigest()]) == 1
    assert not scanner.unknown


@pytest.mark.parametrize("label", ["git-commit:", "git-blob:", "release_body:", "verified_git_commit:"])
def test_display_label_never_mints_context(label):
    _, parent, child = graph()
    scanner = privacy.Scan({}, [parent.oid])
    scanner.payload(child.data, label + child.oid)
    assert found(scanner, parent.oid) and not scanner.git_structural_metadata


def test_json_marker_and_public_keyword_cannot_mint_context():
    _, parent, child = graph()
    scanner = privacy.Scan({}, [parent.oid])
    scanner.payload(json.dumps({"role": "verified_git_commit", "oid": child.oid,
                                "tokens": [[53, 93, "parent", parent.oid]], "data": child.data.decode()}).encode(), "body")
    assert found(scanner, parent.oid) and not scanner.git_structural_metadata
    with pytest.raises(TypeError):
        scanner.payload(child.data, "body", commit_context={"tokens": []})
    with pytest.raises(TalkCutError):
        scanner._commit_payload({"commit": child, "tokens": []})


@pytest.mark.parametrize("location", ["message", "author", "committer", "signature", "extra_header", "continuation", "repeated"])
def test_nonstructural_duplicate_is_still_protected(location):
    tree, parent, child = graph()
    phrase = parent.oid.encode()
    if location in {"message", "repeated"}:
        child = commit_value(tree, (parent,), message=(b"parent " + phrase + b"\n") * (3 if location == "repeated" else 1))
    elif location == "author":
        child = commit_value(tree, (parent,), identity=phrase + b" <fixture@example.invalid> 1 +0000")
    elif location == "committer":
        child = object_value("commit", child.data.replace(b"committer Fixture", b"committer " + phrase))
    elif location == "extra_header":
        child = commit_value(tree, (parent,), extra=b"encoding " + phrase + b"\n")
    else:
        child = commit_value(tree, (parent,), extra=b"gpgsig synthetic\n parent " + phrase + b"\n")
    scanner = privacy.Scan({}, [parent.oid])
    scanner._commit_payload(context(tree, parent, child))
    assert found(scanner, parent.oid) and len(scanner.git_structural_metadata) == 1


@pytest.mark.parametrize("phrase_kind", ["prefix", "header", "cross_field"])
def test_only_entire_oid_phrase_equality_can_be_metadata(phrase_kind):
    tree, parent, child = graph("sha256")
    phrase = {"prefix": parent.oid[:40], "header": "parent " + parent.oid,
              "cross_field": parent.oid + "\nauthor"}[phrase_kind]
    scanner = privacy.Scan({}, [phrase])
    scanner._commit_payload(context(tree, parent, child))
    assert found(scanner, phrase) and not scanner.git_structural_metadata


@pytest.mark.parametrize("kind", ["review", "transcript", "media", "credentials"])
def test_exact_private_digest_retains_precedence(kind):
    tree, parent, child = graph()
    digest = hashlib.sha256(child.data).hexdigest()
    scanner = privacy.Scan({digest: kind}, [parent.oid])
    scanner._commit_payload(context(tree, parent, child))
    assert scanner.findings == [{"kind": "private_" + kind, "location": "git-commit:" + child.oid, "sha256": digest}]
    assert not scanner.git_structural_metadata


@pytest.mark.parametrize("where", ["message", "header"])
def test_raw_credentials_still_detected(where):
    token = "ghp_" + "A" * 36
    tree, parent, _ = graph()
    child = commit_value(tree, (parent,), message=token.encode() if where == "message" else b"Public\n",
                         extra=b"x-token " + token.encode() + b"\n" if where == "header" else b"")
    scanner = privacy.Scan({}, [parent.oid])
    scanner._commit_payload(context(tree, parent, child))
    assert scanner.credentials == {hashlib.sha256(token.encode()).hexdigest()}
    assert len(scanner.git_structural_metadata) == 1


@pytest.mark.parametrize("mutation", ["missing_separator", "duplicate_tree", "parent_after_author", "cr", "nul",
                                      "missing_committer", "continuation_without_header", "duplicate_parent", "truncated"])
def test_malformed_header_cannot_receive_context(mutation):
    tree, parent, child = graph()
    data = child.data
    if mutation == "missing_separator":
        data = data.replace(b"\n\n", b"\n")
    elif mutation == "duplicate_tree":
        data = data.replace(b"\nauthor ", b"\ntree " + tree.oid.encode() + b"\nauthor ")
    elif mutation == "parent_after_author":
        data = data.replace(b"\n\n", b"\nparent " + parent.oid.encode() + b"\n\n")
    elif mutation in {"cr", "nul"}:
        data = data.replace(b"author Fixture", b"author Fix" + (b"\r" if mutation == "cr" else b"\0") + b"ture")
    elif mutation == "missing_committer":
        data = b"\n".join(line for line in data.split(b"\n") if not line.startswith(b"committer "))
    elif mutation == "continuation_without_header":
        data = data.replace(b"\n\n", b"\n parent " + parent.oid.encode() + b"\n\n")
    elif mutation == "duplicate_parent":
        data = data.replace(b"\nauthor", b"\nparent " + parent.oid.encode() + b"\nauthor")
    else:
        data = data[:100]
    child = object_value("commit", data)
    with pytest.raises(TalkCutError):
        context(tree, parent, child)
    scanner = privacy.Scan({}, [parent.oid])
    scanner.payload(data, "git-commit:" + child.oid)
    assert not scanner.git_structural_metadata
    assert found(scanner, parent.oid) or scanner.unknown


@pytest.mark.parametrize("length", [12, 39, 41, 48, 63, 64, 65])
def test_wrong_format_oid_length_refused(length):
    tree, parent, child = graph()
    child = object_value("commit", child.data.replace(parent.oid.encode(), ("a" * length).encode()))
    with pytest.raises(TalkCutError):
        context(tree, parent, child)


@pytest.mark.parametrize("mutation", ["uppercase", "nonhex", "wrong_hash", "wrong_kind", "unsupported_algorithm", "one_byte"])
def test_whole_typed_object_identity_must_verify(mutation):
    _, _, child = graph()
    oid, kind, algorithm, data = child.oid, child.kind, child.algorithm, child.data
    if mutation == "uppercase":
        oid = oid.upper()
    elif mutation == "nonhex":
        oid = "z" + oid[1:]
    elif mutation == "wrong_hash":
        oid = "0" * 40
    elif mutation == "wrong_kind":
        kind = "blob"
    elif mutation == "unsupported_algorithm":
        algorithm = "md5"
    else:
        data += b"X"
    with pytest.raises(TalkCutError):
        privacy._verified_git_object(oid, kind, algorithm, data)


@pytest.mark.parametrize("mutation", ["unselected_child", "missing_parent", "target_wrong_type", "target_wrong_oid", "target_changed_bytes", "target_wrong_algorithm"])
def test_context_requires_reachable_child_parent_and_exact_target_types(mutation):
    tree, parent, child = graph()
    reachable = frozenset((parent.oid, child.oid))
    objects = {x.oid: x for x in (tree, parent, child)}
    if mutation == "unselected_child":
        reachable = frozenset((parent.oid,))
    elif mutation == "missing_parent":
        reachable = frozenset((child.oid,))
    elif mutation == "target_wrong_type":
        objects[tree.oid] = privacy._GitObject(tree.oid, "blob", "sha1", tree.data)
    elif mutation == "target_wrong_oid":
        objects[tree.oid] = object_value("tree", b"different")
    elif mutation == "target_changed_bytes":
        objects[tree.oid] = privacy._GitObject(tree.oid, "tree", "sha1", b"different")
    else:
        objects[tree.oid] = privacy._GitObject(tree.oid, "tree", "sha256", tree.data)
    with pytest.raises(TalkCutError):
        privacy._git_commit_context(child, reachable, lambda oid, _: objects[oid])


def test_root_merge_and_extended_headers():
    tree, parent, _ = graph()
    other = commit_value(tree, message=b"Other synthetic branch\n")
    child = commit_value(tree, (parent, other), extra=b"encoding UTF-8\ngpgsig synthetic\n continuation\n")
    objects = {obj.oid: obj for obj in (tree, parent, other, child)}
    reachable = frozenset((parent.oid, other.oid, child.oid))
    scanner = privacy.Scan({}, [tree.oid, parent.oid, other.oid])
    for obj in (parent, child):
        scanner._commit_payload(privacy._git_commit_context(obj, reachable, lambda oid, _: objects[oid]))
    assert not scanner.findings and len(scanner.git_structural_metadata) == 4


@pytest.mark.parametrize("bound", ["MAX_UNIT_BYTES", "MAX_TOTAL_BYTES", "MAX_UNITS", "MAX_DEPTH"])
def test_original_scan_bounds_stay_failclosed(bound, monkeypatch):
    tree, parent, child = graph()
    authority = context(tree, parent, child)
    monkeypatch.setattr(privacy, bound, 0)
    scanner = privacy.Scan({}, [parent.oid])
    if bound == "MAX_DEPTH":
        scanner.payload(child.data, "body", depth=1)
    else:
        scanner._commit_payload(authority)
    assert scanner.unknown and scanner.exhausted and not scanner.git_structural_metadata


def git(root, *args, data=None):
    return subprocess.run(["git", "-C", str(root), *args], input=data, capture_output=True, check=True).stdout


def repository(tmp_path, algorithm="sha1"):
    root = tmp_path / "repo"
    root.mkdir()
    git(root, "init", "--initial-branch=main", "--object-format=" + algorithm)
    tree = git(root, "mktree", data=b"").strip().decode()
    tree_object = privacy._verified_git_object(tree, "tree", algorithm, b"")
    parent = commit_value(tree_object)
    child = commit_value(tree_object, (parent,))
    for obj in (parent, child):
        assert git(root, "hash-object", "-t", "commit", "-w", "--stdin", data=obj.data).strip().decode() == obj.oid
    git(root, "update-ref", "refs/heads/main", child.oid)
    return root, tree_object, parent, child


@pytest.mark.parametrize("algorithm", ["sha1", "sha256"])
def test_actual_local_reader_proves_storage_type_oid_and_reachability(tmp_path, algorithm):
    root, _, parent, child = repository(tmp_path, algorithm)
    scanner, traces = privacy.Scan({}, [parent.oid]), []
    result = privacy._git_inventory(root, child.oid, scanner, traces)
    assert result["object_format"] == algorithm and not scanner.findings and not scanner.unknown
    assert set(result["reachable_commits"]) == {parent.oid, child.oid}
    assert len(result["structural_oid_occurrences"]) == 1
    assert all(row["argv"][:2] == ["git", "--no-replace-objects"] for row in traces)


def test_replacements_do_not_substitute_original_bytes_or_hide_ref(tmp_path):
    root, tree, parent, child = repository(tmp_path)
    phrase = "Synthetic private phrase in replacement commit body."
    replacement = commit_value(tree, message=phrase.encode())
    git(root, "hash-object", "-t", "commit", "-w", "--stdin", data=replacement.data)
    git(root, "replace", child.oid, replacement.oid)
    assert git(root, "cat-file", "commit", child.oid) == replacement.data
    scanner = privacy.Scan({}, [parent.oid, phrase])
    result = privacy._git_inventory(root, child.oid, scanner, [])
    assert set(result["reachable_commits"]) == {parent.oid, child.oid, replacement.oid}
    assert found(scanner, phrase) and not found(scanner, parent.oid)
    assert len(scanner.git_structural_metadata) == 1 and not scanner.unknown


@pytest.mark.parametrize("ambiguity", ["shallow", "graft"])
def test_truncated_ancestry_never_gets_complete_graph_claim(tmp_path, ambiguity):
    root, _, parent, child = repository(tmp_path)
    if ambiguity == "shallow":
        (root / ".git" / "shallow").write_text(child.oid + "\n")
        with pytest.raises(TalkCutError, match="Shallow"):
            privacy._git_inventory(root, child.oid, privacy.Scan({}, [parent.oid]), [])
    else:
        (root / ".git" / "info" / "grafts").write_text(child.oid + "\n")
        scanner = privacy.Scan({}, [parent.oid])
        privacy._git_inventory(root, child.oid, scanner, [])
        assert scanner.unknown and found(scanner, parent.oid) and not scanner.git_structural_metadata


def test_tags_and_nested_tags_are_ordinary(tmp_path):
    root, _, parent, child = repository(tmp_path)
    target, target_type = child.oid, "commit"
    for name in ("inner", "outer"):
        raw = (f"object {target}\ntype {target_type}\ntag {name}\ntagger Fixture <f@example.invalid> 1 +0000\n\nparent {parent.oid}\n").encode()
        target = git(root, "hash-object", "-t", "tag", "-w", "--stdin", data=raw).strip().decode()
        target_type = "tag"
    git(root, "update-ref", "refs/tags/outer", target)
    scanner = privacy.Scan({}, [parent.oid])
    result = privacy._git_inventory(root, child.oid, scanner, [])
    assert len(result["annotated_tags"]) == 2 and len(found(scanner, parent.oid)) == 2
    assert len(scanner.git_structural_metadata) == 1


def test_changed_refs_rejected_after_scan(tmp_path, monkeypatch):
    root, _, parent, child = repository(tmp_path)
    original = privacy._command
    count = 0

    def changed(argv, cwd, traces, **kwargs):
        nonlocal count
        if "for-each-ref" in argv:
            count += 1
            if count == 2:
                git(root, "update-ref", "refs/heads/additional", parent.oid)
        return original(argv, cwd, traces, **kwargs)

    monkeypatch.setattr(privacy, "_command", changed)
    with pytest.raises(TalkCutError, match="refs changed"):
        privacy._git_inventory(root, child.oid, privacy.Scan({}, [parent.oid]), [])


@pytest.mark.parametrize("attack", ["reported_type", "reported_size", "returned_bytes", "storage_format", "commit_bound"])
def test_actual_reader_refuses_inconsistent_authority(tmp_path, monkeypatch, attack):
    root, _, parent, child = repository(tmp_path)
    original = privacy._command

    def changed(argv, cwd, traces, **kwargs):
        result = original(argv, cwd, traces, **kwargs)
        if attack == "reported_type" and argv[-3:] == ["cat-file", "-t", child.oid]:
            return b"tag\n"
        if attack == "reported_size" and argv[-3:] == ["cat-file", "-s", child.oid]:
            return b"1\n"
        if attack == "returned_bytes" and argv[-3:] == ["cat-file", "commit", child.oid]:
            return child.data[:-1] + b"X"
        if attack == "storage_format" and "--show-object-format=storage" in argv:
            return b"sha384\n"
        return result

    monkeypatch.setattr(privacy, "_command", changed)
    if attack == "commit_bound":
        monkeypatch.setattr(privacy, "MAX_COMMITS", 1)
    with pytest.raises(TalkCutError):
        privacy._git_inventory(root, child.oid, privacy.Scan({}, [parent.oid]), [])


def test_other_reachable_ref_and_exact_blob_copy_remain_scanned(tmp_path):
    root, tree, parent, child = repository(tmp_path)
    phrase = "Synthetic private review text on another reachable branch."
    other = commit_value(tree, message=phrase.encode())
    git(root, "hash-object", "-t", "commit", "-w", "--stdin", data=other.data)
    git(root, "update-ref", "refs/heads/other", other.oid)
    blob = git(root, "hash-object", "-w", "--stdin", data=child.data).strip().decode()
    new_tree_oid = git(root, "mktree", data=f"100644 blob {blob}\tREADME.md\n".encode()).strip().decode()
    new_tree = privacy._verified_git_object(new_tree_oid, "tree", "sha1", git(root, "cat-file", "tree", new_tree_oid))
    final = commit_value(new_tree, (child,))
    git(root, "hash-object", "-t", "commit", "-w", "--stdin", data=final.data)
    git(root, "update-ref", "refs/heads/main", final.oid)
    scanner = privacy.Scan({}, [parent.oid, phrase])
    result = privacy._git_inventory(root, final.oid, scanner, [])
    assert set(result["reachable_commits"]) == {parent.oid, child.oid, other.oid, final.oid}
    assert found(scanner, parent.oid)[0]["location"].startswith("git-blob:")
    assert found(scanner, phrase) and len(scanner.git_structural_metadata) == 1
    assert result["reachable_blob_count"] == 1 and not scanner.unknown


def test_missing_tree_and_wrong_type_parent_never_grant_metadata(tmp_path, monkeypatch):
    root, tree, parent, child = repository(tmp_path)
    original = privacy._command

    def missing(argv, cwd, traces, **kwargs):
        if argv[-3:] == ["cat-file", "-t", tree.oid]:
            raise TalkCutError("PUBLICATION_PRIVACY_UNVERIFIED", "synthetic missing exact tree")
        return original(argv, cwd, traces, **kwargs)

    monkeypatch.setattr(privacy, "_command", missing)
    scanner = privacy.Scan({}, [parent.oid])
    privacy._git_inventory(root, child.oid, scanner, [])
    assert found(scanner, parent.oid) and scanner.unknown and not scanner.git_structural_metadata


def test_object_validation_cache_bound_remains_unverified(tmp_path, monkeypatch):
    root, _, parent, child = repository(tmp_path)
    monkeypatch.setattr(privacy, "MAX_UNITS", 1)
    scanner = privacy.Scan({}, [parent.oid])
    with pytest.raises(TalkCutError, match="object bound"):
        privacy._git_inventory(root, child.oid, scanner, [])
    assert found(scanner, parent.oid) and scanner.unknown and not scanner.git_structural_metadata


def test_ordinary_copy_of_same_protected_phrase_remains_detected():
    tree, parent, child = graph()
    scanner = privacy.Scan({}, [parent.oid])
    scanner._commit_payload(context(tree, parent, child))
    # Classification remains tied to original whole-artifact bytes. The same
    # protected phrase in ordinary credentials/review text remains a match.
    scanner.payload(("synthetic private metadata " + parent.oid).encode(), "private-origin-copy")
    assert found(scanner, parent.oid) and len(scanner.git_structural_metadata) == 1
