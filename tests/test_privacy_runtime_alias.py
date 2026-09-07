"""Bounded byte-inventory tests, using an actually compiled authored library."""

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
    directory = tmp_path_factory.mktemp("actual-authored-library")
    source = directory / "fixture.c"
    source.write_text("int talkcut_privacy_fixture(void) { return 23; }\n")
    output = directory / "library.payload"
    compiler = (
        "/Library/Developer/CommandLineTools/usr/bin/clang"
        if sys.platform == "darwin"
        else "cc"
    )
    command = [
        compiler,
        "-dynamiclib" if sys.platform == "darwin" else "-shared",
        "-fPIC",
        str(source),
        "-o",
        str(output),
    ]
    if sys.platform == "darwin":
        command += ["-isysroot", "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk"]
    result = subprocess.run(command, capture_output=True, check=False, timeout=30)
    (directory / "stdout.bin").write_bytes(result.stdout)
    (directory / "stderr.bin").write_bytes(result.stderr)
    atomic_json(
        directory / "compile.json",
        {
            "argv": command,
            "cwd": str(ROOT),
            "exit_code": result.returncode,
            "source": artifact_ref(source),
            "output": artifact_ref(output) if output.exists() else None,
        },
    )
    assert result.returncode == 0
    return output


def fixture(tmp_path, compiled):
    source = tmp_path / "registered-source.mp4"
    source.write_bytes(b"authored registration identity, not real decoded media")
    directory = tmp_path / "task"
    project = init_project(directory, source, source)
    registered = {role: row["sha256"] for role, row in project["sources"].items()}
    runtime = directory / "capability" / "runtime"
    runtime.mkdir(parents=True)
    target = runtime / "actual-library.data"
    shutil.copyfile(compiled, target)
    middle = runtime / "middle"
    middle.symlink_to(target.name)
    first = runtime / "alias.dylib"
    first.symlink_to(middle.name)
    request = runtime / "request.data"
    ref = {
        "path": str(first),
        "sha256": artifact_ref(target)["sha256"],
        "bytes": target.stat().st_size,
    }
    atomic_json(
        request,
        {
            "schema_version": "authored-runtime-request-fixture/v1",
            "runtime_libraries": [ref],
            "private_note": "This invented private calibration note must stay inside the exact private task denominator.",
        },
    )
    atomic_json(
        directory / "checkpoint.local.json",
        {"source_sha256": registered["screen"], "request": artifact_ref(request)},
    )
    return directory, registered, request, first, middle, target


def collect(parts, **kwargs):
    directory, sources, request, *_ = parts
    return privacy.build_private_inventory(
        directory,
        sources,
        ROOT,
        auxiliary_runtime_requests=[artifact_ref(request)],
        **kwargs,
    )


def test_explicit_actual_request_collects_parent_every_link_and_external_target(
    tmp_path, compiled
):
    parts = fixture(tmp_path, compiled)
    _directory, _sources, request, first, middle, target = parts
    external = tmp_path / "outside-target"
    target.rename(external)
    middle.unlink()
    middle.symlink_to(str(external))
    result = collect(parts)
    entries = {r["path"]: r for r in result["entries"]}
    assert entries[str(request)]["classification"] == "review"
    for path in [first, middle]:
        row = entries[str(path)]
        assert (
            row["entry_type"] == "symlink" and row["classification"] == "UNCLASSIFIED"
        )
        assert (
            row["sha256"]
            == privacy.hashlib.sha256(os.fsencode(os.readlink(path))).hexdigest()
        )
        assert row["lstat"]["inode"] == path.lstat().st_ino
    assert entries[str(external)]["sha256"] == artifact_ref(external)["sha256"]
    assert entries[str(external)]["classification"] == "UNCLASSIFIED"
    observed = result["known_graph"]["auxiliary_runtime_requests"][0]
    assert (
        observed["claim_status"] == "UNVERIFIED"
        and len(observed["libraries"][0]["hops"]) == 2
    )
    assert not result["unresolved"] and result["classification_status"] == "UNVERIFIED"
    assert result["entries"] == collect(parts)["entries"]
    assert result["known_graph"]["derived_phrase_count"] > 0


def test_no_locator_retains_strict_reference_rejection(tmp_path, compiled):
    directory, sources, request, *_ = fixture(tmp_path, compiled)
    # Reproduce the actual normal JSON request path, whose body the old graph
    # already traversed. The opt-in API separately supports suffixless parents.
    actual = request.with_suffix(".json")
    shutil.copyfile(request, actual)
    atomic_json(
        directory / "checkpoint.local.json",
        {"source_sha256": sources["screen"], "request": artifact_ref(actual)},
    )
    with pytest.raises(TalkCutError, match="symlink"):
        privacy.build_private_inventory(directory, sources, ROOT)


@pytest.mark.parametrize(
    "damage",
    [
        "missing_target",
        "changed_target",
        "cycle",
        "directory_target",
        "directory_alias",
        "outside_parent_edge",
        "extension_only",
        "registered_hash",
        "protected_alias_path",
        "protected_target_path",
        "formal_parent",
        "nested_formal_parent",
        "transcript_parent",
        "nested_transcript_parent",
        "stale_request",
        "duplicate_request",
        "duplicate_edge",
    ],
)
def test_runtime_opt_in_cannot_relabel_private_or_unresolved_artifacts(
    tmp_path, compiled, damage
):
    parts = fixture(tmp_path, compiled)
    directory, sources, request, first, middle, target = parts
    original_request = artifact_ref(request)
    data = json.loads(request.read_text())
    if damage == "missing_target":
        target.unlink()
    elif damage == "changed_target":
        target.write_bytes(target.read_bytes() + b"changed bytes")
    elif damage == "cycle":
        middle.unlink()
        middle.symlink_to(first.name)
    elif damage == "directory_target":
        target.unlink()
        target.mkdir()
    elif damage == "directory_alias":
        alias = directory / "capability" / "alias-dir"
        alias.symlink_to(target.parent, target_is_directory=True)
        data["runtime_libraries"][0]["path"] = str(alias / first.name)
    elif damage == "outside_parent_edge":
        data["other_input"] = data["runtime_libraries"].pop()
        data["runtime_libraries"] = [artifact_ref(target)]
    elif damage == "extension_only":
        target.write_text(
            "This is text named as a runtime library, not binary library bytes."
        )
        data["runtime_libraries"][0]["sha256"] = artifact_ref(target)["sha256"]
        data["runtime_libraries"][0]["bytes"] = target.stat().st_size
    elif damage == "registered_hash":
        source = Path(
            json.loads((directory / "project.json").read_text())["sources"]["screen"][
                "path"
            ]
        )
        target.write_bytes(source.read_bytes())
        data["runtime_libraries"][0]["sha256"] = sources["screen"]
        data["runtime_libraries"][0]["bytes"] = target.stat().st_size
    elif damage == "protected_alias_path":
        protected = directory / "transcripts"
        protected.mkdir()
        alias = protected / "renamed.dylib"
        alias.symlink_to(first)
        data["runtime_libraries"][0]["path"] = str(alias)
    elif damage == "protected_target_path":
        protected = directory / "reviews"
        protected.mkdir()
        other = protected / "renamed.data"
        target.rename(other)
        middle.unlink()
        middle.symlink_to(other)
    elif damage in {
        "formal_parent",
        "nested_formal_parent",
        "transcript_parent",
        "nested_transcript_parent",
    }:
        marker = (
            {"schema_version": "execution-receipt/v1"}
            if "formal" in damage
            else {"schema_version": "transcript/v1", "source_sha256": sources["screen"]}
        )
        if damage.startswith("nested"):
            data["payload"] = marker
        else:
            data.update(marker)
    elif damage == "stale_request":
        data["extra"] = "actual subsequent metadata bytes"
    elif damage == "duplicate_edge":
        data["runtime_libraries"].append(data["runtime_libraries"][0])
    if damage not in {
        "missing_target",
        "changed_target",
        "cycle",
        "directory_target",
        "duplicate_request",
    }:
        atomic_json(request, data)
    # Normal current parent bookkeeping references the actual current request.
    atomic_json(
        directory / "checkpoint.local.json",
        {"source_sha256": sources["screen"], "request": artifact_ref(request)},
    )
    locators = (
        [original_request] if damage == "stale_request" else [artifact_ref(request)]
    )
    if damage == "duplicate_request":
        locators *= 2
    with pytest.raises(TalkCutError):
        privacy.build_private_inventory(
            directory, sources, ROOT, auxiliary_runtime_requests=locators
        )


@pytest.mark.parametrize(
    "namespace", ["reviews", "review", "transcripts", "sources", "renders"]
)
def test_private_parent_namespace_cannot_opt_in(tmp_path, compiled, namespace):
    directory, sources, request, *_ = fixture(tmp_path, compiled)
    private = directory / namespace
    private.mkdir(exist_ok=True)
    new = private / "request.json"
    shutil.copyfile(request, new)
    with pytest.raises(
        TalkCutError, match="Private source/transcript/render/review paths"
    ):
        privacy.build_private_inventory(
            directory, sources, ROOT, auxiliary_runtime_requests=[artifact_ref(new)]
        )


def test_link_text_changes_even_with_same_target_hash_require_fresh_snapshot(
    tmp_path, compiled
):
    parts = fixture(tmp_path, compiled)
    _, _, _, first, _middle, target = parts
    original = collect(parts)
    first.unlink()
    first.symlink_to(target.name)
    current = collect(parts)
    assert original["entries"] != current["entries"]
    before = {row["path"]: row for row in original["entries"]}
    after = {row["path"]: row for row in current["entries"]}
    assert before[str(first)]["sha256"] != after[str(first)]["sha256"]
    assert before[str(target)]["sha256"] == after[str(target)]["sha256"]


def test_publication_symlink_rule_remains_strict(tmp_path, compiled):
    parts = fixture(tmp_path, compiled)
    collect(parts)
    with pytest.raises(TalkCutError, match="symlink"):
        privacy._file(
            {"path": str(parts[3]), "sha256": artifact_ref(parts[5])["sha256"]}
        )


@pytest.mark.parametrize("kind", ["review", "transcript"])
def test_prior_private_digest_cannot_borrow_runtime_header(tmp_path, compiled, kind):
    parts = fixture(tmp_path, compiled)
    directory, sources, request, _first, _middle, target = parts
    protected = tmp_path / "private-body.txt"
    shutil.copyfile(target, protected)
    reference = artifact_ref(protected)
    if kind == "transcript":
        reference = {
            "schema_version": "transcript/v1",
            "source_sha256": sources["screen"],
            "actual": reference,
        }
    else:
        private = directory / "reviews"
        private.mkdir()
        local = private / "known-private.bin"
        shutil.copyfile(protected, local)
        reference = artifact_ref(local)
    atomic_json(
        directory / "checkpoint.local.json",
        {
            "source_sha256": sources["screen"],
            "private": reference,
            "request": artifact_ref(request),
        },
    )
    with pytest.raises(TalkCutError, match="Known private source/transcript/review"):
        collect(parts)


@pytest.mark.parametrize("link_count", [31, 32])
def test_runtime_link_walk_has_finite_complete_node_bound(
    tmp_path, compiled, link_count
):
    parts = fixture(tmp_path, compiled)
    directory, sources, request, _first, _middle, target = parts
    previous = target
    for index in range(link_count):
        link = target.parent / f"bounded-{index}"
        link.symlink_to(previous.name)
        previous = link
    data = json.loads(request.read_text())
    data["runtime_libraries"][0]["path"] = str(previous)
    atomic_json(request, data)
    atomic_json(
        directory / "checkpoint.local.json",
        {"source_sha256": sources["screen"], "request": artifact_ref(request)},
    )
    if link_count == 32:
        with pytest.raises(TalkCutError, match="hop bound"):
            collect(parts)
    else:
        result = collect(parts)
        entry_paths = {row["path"] for row in result["entries"]}
        chain = result["known_graph"]["auxiliary_runtime_requests"][0]["libraries"][0]
        assert len(chain["hops"]) == 31
        assert {row["path"] for row in chain["hops"]} < entry_paths


def repeated_fixture(tmp_path, compiled):
    parts = fixture(tmp_path, compiled)
    directory, sources, request, first, _middle, target = parts
    diagnostic = directory / "evidence" / "actual-diagnostic.json"
    diagnostic.parent.mkdir()
    phrase = "This authored private diagnostic sentence must remain protected in every repeated alias observation."
    reference = {"path": str(first), "sha256": artifact_ref(target)["sha256"]}
    atomic_json(
        diagnostic,
        {
            "scope": "Auxiliary actual byte observations only",
            "text": phrase,
            "frames": [{"ref": reference}],
        },
    )
    atomic_json(
        directory / "checkpoint.local.json",
        {
            "source_sha256": sources["screen"],
            "request": artifact_ref(request),
            "diagnostic": artifact_ref(diagnostic),
        },
    )
    return parts, diagnostic, phrase


def test_same_alias_diagnostic_keeps_parent_hops_target_and_phrase(tmp_path, compiled):
    parts, diagnostic, phrase = repeated_fixture(tmp_path, compiled)
    result = collect(parts)
    entries = {r["path"]: r for r in result["entries"]}
    assert entries[str(diagnostic)]["classification"] == "review"
    assert {str(p) for p in parts[3:]} <= entries.keys()
    private, phrases, known = privacy._known_private_inventory(
        parts[0], parts[1], ROOT, auxiliary_runtime_requests=[artifact_ref(parts[2])]
    )
    assert private[artifact_ref(diagnostic)["sha256"]] == "review" and phrase in phrases
    rows = known["auxiliary_runtime_reobservations"]
    assert len(rows) == 1
    assert rows[0]["parent"] == artifact_ref(diagnostic) and rows[0]["edge"] == [
        "frames",
        0,
        "ref",
    ]
    assert rows[0]["authority_request"] == artifact_ref(parts[2])
    assert (
        rows[0]["claim_status"] == "UNVERIFIED"
        and result["classification_status"] == "UNVERIFIED"
    )
    assert result["entries"] == collect(parts)["entries"]


@pytest.mark.parametrize(
    "damage",
    [
        "new_alias",
        "wrong_hash",
        "formal_parent",
        "nested_formal",
        "transcript_parent",
        "nested_transcript",
        "protected_parent",
        "extra_missing_ref",
        "no_authority",
        "wrong_bytes",
    ],
)
def test_reobserved_alias_has_no_new_authority_or_private_override(
    tmp_path, compiled, damage
):
    parts, diagnostic, _ = repeated_fixture(tmp_path, compiled)
    directory, sources, request, first, _middle, target = parts
    data = json.loads(diagnostic.read_text())
    if damage == "new_alias":
        new = first.with_name("unregistered-other-alias")
        new.symlink_to(target.name)
        data["frames"][0]["ref"]["path"] = str(new)
    elif damage == "wrong_hash":
        data["frames"][0]["ref"]["sha256"] = "f" * 64
    elif damage in {
        "formal_parent",
        "nested_formal",
        "transcript_parent",
        "nested_transcript",
    }:
        marker = (
            {"schema_version": "execution-receipt/v1"}
            if "formal" in damage
            else {"schema_version": "transcript/v1", "source_sha256": sources["screen"]}
        )
        if damage.startswith("nested"):
            data["payload"] = marker
        else:
            data.update(marker)
    elif damage == "protected_parent":
        protected = directory / "reviews"
        protected.mkdir()
        diagnostic = protected / "diagnostic.json"
    elif damage == "extra_missing_ref":
        data["missing"] = {
            "path": str(directory / "absent-private.json"),
            "sha256": "e" * 64,
        }
    elif damage == "wrong_bytes":
        data["frames"][0]["ref"]["bytes"] = 1
    atomic_json(diagnostic, data)
    atomic_json(
        directory / "checkpoint.local.json",
        {
            "source_sha256": sources["screen"],
            "request": artifact_ref(request),
            "diagnostic": artifact_ref(diagnostic),
        },
    )
    with pytest.raises(TalkCutError):
        if damage == "no_authority":
            privacy.build_private_inventory(directory, sources, ROOT)
        else:
            collect(parts)


def test_repeated_auxiliary_body_keeps_source_bound_plain_text_private(
    tmp_path, compiled
):
    parts, diagnostic, phrase = repeated_fixture(tmp_path, compiled)
    data = json.loads(diagnostic.read_text())
    data["source_sha256"] = parts[1]["screen"]
    atomic_json(diagnostic, data)
    atomic_json(
        parts[0] / "checkpoint.local.json",
        {"request": artifact_ref(parts[2]), "diagnostic": artifact_ref(diagnostic)},
    )
    private, phrases, known = privacy._known_private_inventory(
        parts[0], parts[1], ROOT, auxiliary_runtime_requests=[artifact_ref(parts[2])]
    )
    assert private[artifact_ref(diagnostic)["sha256"]] == "review" and phrase in phrases
    assert known["auxiliary_runtime_reobservations"][0]["claim_status"] == "UNVERIFIED"


def test_unknown_external_ref_beside_repeated_alias_stays_in_denominator(
    tmp_path, compiled
):
    parts, diagnostic, _ = repeated_fixture(tmp_path, compiled)
    external = tmp_path / "external-authored-review.txt"
    external.write_text(
        "This authored external private sentence is still part of the exact inspection denominator."
    )
    data = json.loads(diagnostic.read_text())
    data["extra"] = artifact_ref(external)
    atomic_json(diagnostic, data)
    atomic_json(
        parts[0] / "checkpoint.local.json",
        {"request": artifact_ref(parts[2]), "diagnostic": artifact_ref(diagnostic)},
    )
    result = collect(parts)
    entries = {r["path"]: r for r in result["entries"]}
    assert entries[str(external)]["sha256"] == artifact_ref(external)["sha256"]
    assert (
        entries[str(external)]["classification"] == "UNCLASSIFIED"
        and result["classification_status"] == "UNVERIFIED"
    )


def test_concurrent_hop_change_after_authority_observation_is_rejected(
    tmp_path, compiled, monkeypatch
):
    parts, _diagnostic, _ = repeated_fixture(tmp_path, compiled)
    original = privacy._auxiliary_runtime_inventory
    count = 0

    def observe(*args, **kwargs):
        nonlocal count
        result = original(*args, **kwargs)
        count += 1
        if count == 1:
            parts[3].unlink()
            parts[3].symlink_to(parts[5].name)
        return result

    monkeypatch.setattr(privacy, "_auxiliary_runtime_inventory", observe)
    with pytest.raises(TalkCutError, match="changed during inventory"):
        collect(parts)
