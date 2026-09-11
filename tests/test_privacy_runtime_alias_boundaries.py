"""Independent byte-inventory controls. No inference or provider audit occurs."""

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from talkcut import privacy_checks as privacy
from talkcut.project import TalkCutError, artifact_ref, atomic_json, init_project

ROOT = Path.cwd()


@pytest.fixture(scope="module")
def compiled(tmp_path_factory):
    out = tmp_path_factory.mktemp("compiled-control")
    source = out / "source.c"
    source.write_text("int independent_alias_probe(void) { return 719; }\n")
    target = out / "actual.dylib"
    compiler = (
        "/Library/Developer/CommandLineTools/usr/bin/clang"
        if sys.platform == "darwin"
        else "cc"
    )
    cmd = [
        compiler,
        "-dynamiclib" if sys.platform == "darwin" else "-shared",
        "-fPIC",
        str(source),
        "-o",
        str(target),
    ]
    if sys.platform == "darwin":
        cmd += ["-isysroot", "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk"]
    result = subprocess.run(cmd, capture_output=True, timeout=30, check=False)
    (out / "stdout").write_bytes(result.stdout)
    (out / "stderr").write_bytes(result.stderr)
    atomic_json(
        out / "receipt.json",
        {
            "argv": cmd,
            "exit_code": result.returncode,
            "source": artifact_ref(source),
            "output": artifact_ref(target),
        },
    )
    assert result.returncode == 0
    return target


def fixture(tmp_path, compiled):
    src = tmp_path / "registered-original.bin"
    src.write_bytes(b"Independent hash-registration fixture; never real lecture media")
    task = tmp_path / "task"
    project = init_project(task, src, src)
    sources = {k: v["sha256"] for k, v in project["sources"].items()}
    runtime = task / "capability/runtime"
    runtime.mkdir(parents=True)
    target = runtime / "actual.dylib"
    shutil.copyfile(compiled, target)
    middle = runtime / "middle"
    middle.symlink_to(target.name)
    alias = runtime / "alias"
    alias.symlink_to(middle.name)
    request = runtime / "request.json"
    data = {
        "schema_version": "independent-runtime-metadata/v1",
        "runtime_libraries": [
            {"path": str(alias), "sha256": artifact_ref(target)["sha256"]}
        ],
        "note": "Synthetic private request bookkeeping only; no claimed native execution.",
    }
    atomic_json(request, data)
    atomic_json(
        task / "checkpoint.local.json",
        {"source_sha256": sources["screen"], "request": artifact_ref(request)},
    )
    return task, sources, request, alias, middle, target


def collect(parts):
    task, sources, request, *_ = parts
    return privacy.build_private_inventory(
        task, sources, ROOT, auxiliary_runtime_requests=[artifact_ref(request)]
    )


def test_positive_actual_chain_inventory_and_unverified_claims(tmp_path, compiled):
    parts = fixture(tmp_path, compiled)
    result = collect(parts)
    _task, _sources, request, alias, middle, target = parts
    rows = {r["path"]: r for r in result["entries"]}
    assert rows[str(request)]["classification"] == "review"
    assert {str(alias), str(middle), str(target)} <= rows.keys()
    assert rows[str(target)]["sha256"] == artifact_ref(target)["sha256"]
    assert (
        rows[str(alias)]["sha256"]
        == privacy.hashlib.sha256(os.fsencode(os.readlink(alias))).hexdigest()
    )
    assert result["classification_status"] == "UNVERIFIED"
    assert (
        result["known_graph"]["auxiliary_runtime_requests"][0]["claim_status"]
        == "UNVERIFIED"
    )


def test_nested_same_alias_does_not_borrow_top_level_locator(tmp_path, compiled):
    parts = fixture(tmp_path, compiled)
    task, _sources, request, *_ = parts
    data = json.loads(request.read_text())
    data["nested"] = {"runtime_libraries": data["runtime_libraries"]}
    atomic_json(request, data)
    atomic_json(task / "checkpoint.local.json", {"request": artifact_ref(request)})
    result = collect(parts)
    assert result["known_graph"]["auxiliary_runtime_reobservations"]
    assert result["classification_status"] == "UNVERIFIED"


def test_other_parent_cannot_borrow_identical_edge(tmp_path, compiled):
    parts = fixture(tmp_path, compiled)
    task, _sources, request, *_ = parts
    other = request.with_name("other.json")
    shutil.copyfile(request, other)
    atomic_json(
        task / "checkpoint.local.json",
        {"first": artifact_ref(request), "second": artifact_ref(other)},
    )
    result = collect(parts)
    assert result["known_graph"]["auxiliary_runtime_reobservations"]
    assert result["classification_status"] == "UNVERIFIED"


def test_directory_symlink_then_dotdot_cannot_relabel_actual_target(tmp_path, compiled):
    parts = fixture(tmp_path, compiled)
    _task, _sources, _request, alias, _middle, target = parts
    outside = tmp_path / "outside"
    (outside / "child").mkdir(parents=True)
    actual = outside / "actual.dylib"
    actual.write_bytes(
        compiled.read_bytes() + b"\nIndependent outside private payload sentinel.\n"
    )
    jump = target.parent / "jump"
    jump.symlink_to(outside / "child", target_is_directory=True)
    alias.unlink()
    alias.symlink_to("jump/../actual.dylib")
    # Actual OS open follows jump first, then ..; abspath lexical erasure differs.
    assert alias.read_bytes() == actual.read_bytes() and alias.resolve() == actual
    assert artifact_ref(actual)["sha256"] != artifact_ref(target)["sha256"]
    with pytest.raises(TalkCutError, match="directory|canonical|bytes changed"):
        collect(parts)


def test_private_symlink_classification_enters_exact_private_corpus(
    tmp_path, compiled, monkeypatch
):
    parts = fixture(tmp_path, compiled)
    task, sources, request, alias, _middle, _target = parts
    snapshot = collect(parts)
    snapshot_path = tmp_path / "inventory.json"
    atomic_json(snapshot_path, snapshot)
    # The audit transport boundary alone is isolated: assume a valid independently
    # checked classification has already been returned. No AI review is asserted.
    classifications = [
        {
            "path": r["path"],
            "sha256": r["sha256"],
            "classification": r["classification"]
            if r["classification"] != "UNCLASSIFIED"
            else "review",
            "reason": "Synthetic branch-control classification; no real independent AI execution.",
        }
        for r in snapshot["entries"]
    ]
    from talkcut import review

    monkeypatch.setattr(
        review,
        "verify_artifact_audit",
        lambda *a, **kw: {"response": {"private_classifications": classifications}},
    )
    audit_path = tmp_path / "audit-boundary.json"
    atomic_json(audit_path, {"scope": "parser boundary placeholder only"})
    private = {}
    result = privacy._audited_private_inventory(
        {
            "private_inventory_snapshot": artifact_ref(snapshot_path),
            "inventory_audit": artifact_ref(audit_path),
            "implementation_run_ids": ["independent-control-run"],
            "auxiliary_runtime_requests": [artifact_ref(request)],
        },
        task,
        sources,
        ROOT,
        private,
        [],
    )
    assert result["completeness"] == "PASS"
    row = next(r for r in snapshot["entries"] if r["path"] == str(alias))
    assert row["sha256"] in private, (
        "Audited private symlink bytes were omitted from exclusion corpus"
    )


def test_publication_still_rejects_symlink_after_runtime_inventory(tmp_path, compiled):
    parts = fixture(tmp_path, compiled)
    collect(parts)
    with pytest.raises(TalkCutError, match="symlink"):
        privacy._file(
            {"path": str(parts[3]), "sha256": artifact_ref(parts[5])["sha256"]}
        )
