"""Authored source-tree fixtures verify byte inventory; no build or AV approval."""

import json
import shutil
from pathlib import Path

import pytest
from _privacy_source_tree import ROOT, collect, fixture, privacy, rebind, refresh

from talkcut.project import TalkCutError, artifact_ref, atomic_json


def test_complete_tree_and_inline_copy_resolve_only_exact_context(tmp_path):
    parts = fixture(tmp_path)
    task, sources, base, source, build, manifest, copy, locator = parts
    result = collect(parts)
    entries = {r["path"]: r for r in result["entries"]}
    row = result["known_graph"]["auxiliary_source_trees"][0]
    assert (
        row["row_count"] == 3
        and row["source_directory"] == str(source)
        and row["claim_status"] == "UNVERIFIED"
    )
    assert {str(p) for p in source.rglob("*") if p.is_file()} <= entries.keys()
    assert all(
        entries[str(p)]["classification"] == "review"
        for p in [
            build,
            manifest,
            base / "build-execution-synthetic" / "source-before.local.json",
            base / "acquisition.json",
            copy,
        ]
    )
    assert (
        entries[str(source / ".gitmodules")]["sha256"]
        == artifact_ref(task / "transcripts" / "empty.stderr.txt")["sha256"]
    )
    assert result["classification_status"] == "UNVERIFIED" and not result["unresolved"]
    assert result["entries"] == collect(parts)["entries"]
    private, phrases, _ = privacy._known_private_inventory(
        task, sources, ROOT, auxiliary_source_trees=[locator]
    )
    assert artifact_ref(copy)["sha256"] in private and any(
        "invented confidential source-tree context" in x for x in phrases
    )


def test_without_explicit_locator_original_relative_failure_remains(tmp_path):
    parts = fixture(tmp_path)
    with pytest.raises(TalkCutError):
        privacy.build_private_inventory(parts[0], parts[1], ROOT)


@pytest.mark.parametrize(
    "damage",
    [
        "escape",
        "absolute",
        "dot",
        "duplicate",
        "missing",
        "changed_hash",
        "changed_bytes",
        "extra",
        "directory_target",
        "symlink_target",
        "symlink_directory",
        "missing_row",
        "invalid_digest",
        "malformed_row",
    ],
)
def test_tree_row_and_full_current_denominator_guards(tmp_path, damage):
    parts = fixture(tmp_path)
    _task, _sources, base, source, build, manifest, _copy, _locator = parts
    value = json.loads(manifest.read_text())
    if damage == "escape":
        value["files"][0]["path"] = "../outside"
    elif damage == "absolute":
        value["files"][0]["path"] = str(source / ".gitmodules")
    elif damage == "dot":
        value["files"][0]["path"] = "./.gitmodules"
    elif damage == "duplicate":
        value["files"].append(value["files"][0])
    elif damage == "missing":
        (source / "main.cpp").unlink()
    elif damage == "changed_hash":
        (source / "main.cpp").write_text(
            "Changed actual code bytes without rebinding the original tree.\n"
        )
    elif damage == "changed_bytes":
        value["files"][1]["bytes"] += 1
    elif damage == "extra":
        (source / "new.cpp").write_text("int unlisted_file;\n")
    elif damage == "directory_target":
        (source / "main.cpp").unlink()
        (source / "main.cpp").mkdir()
    elif damage == "symlink_target":
        (source / "main.cpp").unlink()
        (source / "main.cpp").symlink_to(source / ".gitmodules")
    elif damage == "symlink_directory":
        (source / "sub").rename(base / "outside")
        (source / "sub").symlink_to(base / "outside", target_is_directory=True)
    elif damage == "missing_row":
        value["files"].pop()
    elif damage == "invalid_digest":
        value["sha256"] = "f" * 64
    elif damage == "malformed_row":
        value["files"][0]["bytes"] = False
    if damage in {
        "escape",
        "absolute",
        "dot",
        "duplicate",
        "changed_bytes",
        "missing_row",
        "malformed_row",
    }:
        atomic_json(manifest, value)
        rebind(parts, manifest=True)
    elif damage == "invalid_digest":
        atomic_json(manifest, value)
        shutil.copyfile(
            manifest, base / "build-execution-synthetic" / "source-before.local.json"
        )
        data = json.loads(build.read_text())
        data["source_before"] = artifact_ref(
            base / "build-execution-synthetic" / "source-before.local.json"
        )
        data["source_after"] = artifact_ref(manifest)
        atomic_json(build, data)
        rebind(parts)
    with pytest.raises(TalkCutError):
        collect(parts)


@pytest.mark.parametrize(
    "damage",
    [
        "wrong_root",
        "wrong_cwd",
        "wrong_configured_root",
        "producer_relative_root",
        "producer_rebinding",
        "before_after_differ",
        "missing_origin",
        "formal_build",
        "caller_root",
        "registered_source",
        "protected_root",
        "outside_task_root",
    ],
)
def test_original_build_origin_guards(tmp_path, damage):
    parts = fixture(tmp_path)
    task, sources, base, source, build, manifest, copy, locator = parts
    if damage == "wrong_root":
        atomic_json(
            base / "acquisition.json", {"copied_source": str(base / "different")}
        )
        rebind(parts, origin=True)
    elif damage in {
        "wrong_cwd",
        "wrong_configured_root",
        "missing_origin",
        "formal_build",
    }:
        data = json.loads(build.read_text())
        if damage == "wrong_cwd":
            data["commands"][0]["cwd"] = str(ROOT)
        elif damage == "wrong_configured_root":
            data["commands"][0]["argv"][2] = str(ROOT)
        elif damage == "missing_origin":
            data.pop("source_acquisition")
        else:
            data["schema_version"] = "multimodal-review/v1"
        atomic_json(build, data)
        locator["build"] = artifact_ref(build)
        refresh(task, sources, build, copy)
    elif damage in {"producer_relative_root", "producer_rebinding"}:
        producer = base / "producer.py"
        body = producer.read_text()
        body = (
            body.replace("p.relative_to(source)", "p.relative_to(base)")
            if damage == "producer_relative_root"
            else body + "\nsource=base\n"
        )
        producer.write_text(body)
        rebind(parts, origin=True)
    elif damage == "before_after_differ":
        old = json.loads(
            (
                base / "build-execution-synthetic" / "source-before.local.json"
            ).read_text()
        )
        old["sha256"] = "e" * 64
        atomic_json(
            base / "build-execution-synthetic" / "source-before.local.json", old
        )
        data = json.loads(build.read_text())
        data["source_before"] = artifact_ref(
            base / "build-execution-synthetic" / "source-before.local.json"
        )
        atomic_json(build, data)
        locator["build"] = artifact_ref(build)
        refresh(task, sources, build, copy)
    elif damage == "caller_root":
        locator["source_root"] = str(source)
    elif damage == "registered_source":
        registered = Path(
            json.loads((task / "project.json").read_text())["sources"]["screen"]["path"]
        )
        (source / "main.cpp").write_bytes(registered.read_bytes())
        value = json.loads(manifest.read_text())
        row = next(r for r in value["files"] if r["path"] == "main.cpp")
        row["sha256"] = sources["screen"]
        row["bytes"] = registered.stat().st_size
        atomic_json(manifest, value)
        rebind(parts, manifest=True)
    elif damage in {"protected_root", "outside_task_root"}:
        if damage == "protected_root":
            new = task / "reviews" / "native"
        else:
            new = tmp_path / "outside-native"
        shutil.copytree(base, new)
        locator["build"] = artifact_ref(
            new / "build-execution-synthetic" / "result.local.json"
        )
    with pytest.raises(TalkCutError):
        collect(parts)


@pytest.mark.parametrize(
    "damage",
    [
        "different_value",
        "wrong_pointer",
        "missing_pointer",
        "different_build",
        "different_manifest",
        "formal_parent",
        "transcript_parent",
        "protected_parent",
        "duplicate_copy",
        "unregistered_copy",
    ],
)
def test_inline_copy_is_tied_to_exact_parent_pointer_value_and_origin(tmp_path, damage):
    parts = fixture(tmp_path)
    task, sources, _base, _source, build, manifest, copy, locator = parts
    data = json.loads(copy.read_text())
    if damage == "different_value":
        data["runtime"]["actual_build_source_tree"]["files"][0]["bytes"] = 1
    elif damage == "wrong_pointer":
        locator["copies"][0]["pointer"] = "/runtime"
    elif damage == "missing_pointer":
        locator["copies"][0]["pointer"] = "/absent/actual_build_source_tree"
    elif damage == "different_build":
        data["runtime"]["build_receipt"]["sha256"] = "f" * 64
    elif damage == "different_manifest":
        data["runtime"]["build_source_before"]["path"] = str(manifest)
    elif damage == "formal_parent":
        data["schema_version"] = "execution-receipt/v1"
    elif damage == "transcript_parent":
        data.update(schema_version="transcript/v1", source_sha256=sources["screen"])
    elif damage == "protected_parent":
        protected = task / "reviews"
        protected.mkdir()
        copy = protected / "binding.json"
        parts = (*parts[:6], copy, locator)
    elif damage == "unregistered_copy":
        locator["copies"] = []
    atomic_json(copy, data)
    if locator["copies"]:
        locator["copies"][0]["parent"] = artifact_ref(copy)
    if damage == "duplicate_copy":
        locator["copies"].append(locator["copies"][0])
    refresh(task, sources, build, copy)
    with pytest.raises(TalkCutError):
        collect(parts)


@pytest.mark.parametrize(
    "suffix",
    [
        "\nglobals()['source']=base\n",
        "\ntree.__globals__['source']=base\n",
        "\nPath=lambda *args: None\n",
        "\nimport os as hashlib\n",
        "\nPath.relative_to=lambda p: p\n",
    ],
)
def test_producer_cannot_rebind_root_or_relative_semantics_indirectly(tmp_path, suffix):
    parts = fixture(tmp_path)
    producer = parts[2] / "producer.py"
    producer.write_text(producer.read_text() + suffix)
    rebind(parts, origin=True)
    with pytest.raises(TalkCutError, match="construction|imports"):
        collect(parts)


def test_source_bound_private_transcript_in_tree_remains_private(tmp_path):
    parts = fixture(tmp_path)
    task, sources, _base, source, _build, manifest, _copy, locator = parts
    path = source / "sub" / "metadata.json"
    phrase = "This authored private transcript sentence must be protected even inside a source tree."
    atomic_json(
        path,
        {
            "schema_version": "transcript/v1",
            "source_sha256": sources["screen"],
            "segments": [{"text": phrase}],
        },
    )
    value = json.loads(manifest.read_text())
    row = next(v for v in value["files"] if v["path"] == "sub/metadata.json")
    row.update(sha256=artifact_ref(path)["sha256"], bytes=path.stat().st_size)
    atomic_json(manifest, value)
    rebind(parts, manifest=True)
    result = collect(parts)
    entry = next(v for v in result["entries"] if v["path"] == str(path))
    assert entry["classification"] == "transcript"
    private, phrases, _ = privacy._known_private_inventory(
        task, sources, ROOT, auxiliary_source_trees=[locator]
    )
    assert private[artifact_ref(path)["sha256"]] == "transcript" and phrase in phrases
    scanner = privacy.Scan(private, phrases)
    scanner.payload(phrase.encode(), "authored-publication-body")
    assert len(scanner.transcripts) >= 1
