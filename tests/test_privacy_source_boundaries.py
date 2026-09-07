"""Actual synthetic Path/CMake/permission controls; no production review claim."""

import ast
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import _privacy_source_tree as setup
import pytest

from talkcut import privacy_checks as privacy
from talkcut.project import TalkCutError, artifact_ref, atomic_json

ROOT = Path.cwd()


def inventory(parts):
    return privacy._auxiliary_source_tree_inventory(
        [parts[-1]], parts[0], ROOT, set(parts[1].values())
    )


def test_actual_small_tree_current_paths_and_unverified_scope(tmp_path):
    parts = setup.fixture(tmp_path)
    row = inventory(parts)[0]
    assert (
        row["row_count"] == 3
        and row["source_directory"] == str(parts[3])
        and row["claim_status"] == "UNVERIFIED"
    )
    for item in row["files"]:
        assert artifact_ref(Path(item["actual"]["path"])) == item["actual"]
    assert len(row["bindings"]) == 3


@pytest.mark.parametrize("mutation", ["dunder_file", "path_function"])
def test_producer_origin_symbols_cannot_shadow_declared_root(tmp_path, mutation):
    parts = setup.fixture(tmp_path)
    producer = parts[2] / "producer.py"
    other = tmp_path / "other-native"
    (other / "source").mkdir(parents=True)
    body = producer.read_text()
    if mutation == "dunder_file":
        inserted = "__file__=" + repr(str(other / "producer.py")) + "\n"
    else:
        inserted = (
            "from pathlib import Path as OriginalPath\ndef Path(_arg):\n return OriginalPath("
            + repr(str(other / "producer.py"))
            + ")\n"
        )
    body = body.replace(
        "base=Path(__file__).resolve().parent",
        inserted + "base=Path(__file__).resolve().parent",
    )
    producer.write_text(body)
    setup.rebind(parts, origin=True)
    # Evaluate only the actual import/root declarations, without running the
    # producer's write/build code, to demonstrate this source resolves another root.
    syntax = ast.parse(body)
    prefix = []
    for node in syntax.body:
        prefix.append(node)
        if isinstance(node, ast.Assign) and any(
            isinstance(t, ast.Name) and t.id == "source" for t in node.targets
        ):
            break
    probe = parts[2] / "root-probe.py"
    probe.write_text(
        ast.unparse(ast.Module(body=prefix, type_ignores=[])) + "\nprint(source)\n"
    )
    result = subprocess.run(
        [sys.executable, str(probe)],
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    assert result.returncode == 0 and result.stdout.strip() == str(other / "source")
    atomic_json(
        parts[2] / "actual-root-probe.json",
        {
            "argv": [sys.executable, str(probe)],
            "exit_code": result.returncode,
            "actual_source": result.stdout.strip(),
            "scanner_candidate_source": str(parts[3]),
            "producer": artifact_ref(producer),
            "probe": artifact_ref(probe),
        },
    )
    with pytest.raises(TalkCutError, match="construction|imports|source"):
        inventory(parts)


@pytest.mark.parametrize("mutation", ["second_source_flag", "other_configure_command"])
def test_every_configured_source_root_must_match_actual_producer(tmp_path, mutation):
    cmake = shutil.which("cmake")
    assert cmake is not None, (
        "This independent actual CMake control requires installed cmake"
    )
    parts = setup.fixture(tmp_path)
    _task, _sources, base, source, build, _manifest, _copy, _locator = parts
    other = tmp_path / "other-cmake"
    other.mkdir()
    (other / "CMakeLists.txt").write_text(
        "cmake_minimum_required(VERSION 3.10)\nproject(OutsideControl NONE)\n"
    )
    output = tmp_path / "cmake-output"
    argv = (
        [cmake, "-S", str(source), "-S", str(other), "-B", str(output)]
        if mutation == "second_source_flag"
        else [cmake, "-S", str(other), "-B", str(output)]
    )
    process = subprocess.run(
        argv, cwd=source, capture_output=True, timeout=20, check=False
    )
    assert process.returncode == 0
    cache = (output / "CMakeCache.txt").read_text()
    actual_line = next(
        line
        for line in cache.splitlines()
        if line.startswith("CMAKE_HOME_DIRECTORY:INTERNAL=")
    )
    assert actual_line.split("=", 1)[1] == str(other)
    (base / "actual-configure.stdout").write_bytes(process.stdout)
    (base / "actual-configure.stderr").write_bytes(process.stderr)
    atomic_json(
        base / "actual-configure.json",
        {
            "argv": argv,
            "cwd": str(source),
            "exit_code": process.returncode,
            "cache": artifact_ref(output / "CMakeCache.txt"),
            "actual_cmake_source": str(other),
            "stdout": artifact_ref(base / "actual-configure.stdout"),
            "stderr": artifact_ref(base / "actual-configure.stderr"),
        },
    )
    value = json.loads(build.read_text())
    if mutation == "second_source_flag":
        arguments = [argv]
    else:
        arguments = [row["argv"] for row in value["commands"]] + [argv]
    setup.set_commands(parts, arguments)
    with pytest.raises(TalkCutError, match="source root|construction|configured"):
        inventory(parts)


@pytest.mark.parametrize(
    "mutation",
    [
        "copy_origin",
        "copy_pointer",
        "copy_namespace",
        "absolute_row",
        "dotdot_row",
        "source_alias",
    ],
)
def test_affected_origin_and_path_guards_remain_closed(tmp_path, mutation):
    parts = setup.fixture(tmp_path)
    _task, _sources, base, source, _build, manifest, copy, locator = parts
    if mutation in ("copy_origin", "copy_pointer", "copy_namespace"):
        value = json.loads(copy.read_text())
        if mutation == "copy_origin":
            value["runtime"]["source_acquisition"]["sha256"] = "f" * 64
        elif mutation == "copy_pointer":
            locator["copies"][0]["pointer"] = "/runtime/actual_build_source_tree/files"
        else:
            value["schema_version"] = "multimodal-review/v1"
        atomic_json(copy, value)
        locator["copies"][0]["parent"] = artifact_ref(copy)
    elif mutation == "source_alias":
        old = source / "main.cpp"
        other = base / "other.cpp"
        old.rename(other)
        old.symlink_to(other)
    else:
        value = json.loads(manifest.read_text())
        value["files"][0]["path"] = (
            str(source / ".gitmodules")
            if mutation == "absolute_row"
            else "../.gitmodules"
        )
        atomic_json(manifest, value)
        setup.rebind(parts, manifest=True)
    with pytest.raises(TalkCutError):
        inventory(parts)


def test_unlisted_unreadable_directory_cannot_be_omitted_from_current_tree(tmp_path):
    parts = setup.fixture(tmp_path)
    hidden = parts[3] / "unreadable-unlisted"
    hidden.mkdir()
    (hidden / "private-payload.txt").write_text(
        "Synthetic unseen file: no real lecture data."
    )
    hidden.chmod(0)
    try:
        try:
            list(os.scandir(hidden))
        except PermissionError:
            pass
        else:
            pytest.skip(
                "OS privilege permits this directory despite mode 000; no unreadable premise"
            )
        with pytest.raises(TalkCutError, match="source tree|current|permission|read"):
            inventory(parts)
    finally:
        hidden.chmod(0o700)


def test_aliased_path_object_cannot_change_actual_source_root(tmp_path):
    parts = setup.fixture(tmp_path)
    producer = parts[2] / "producer.py"
    other = tmp_path / "other-native" / "source"
    other.mkdir(parents=True)
    body = producer.read_text().replace(
        "source=base/'source'\n",
        "source=base/'source'\nalias=source\nalias.__init__("
        + repr(str(other))
        + ")\n",
    )
    producer.write_text(body)
    setup.rebind(parts, origin=True)
    prefix = []
    for node in ast.parse(body).body:
        prefix.append(node)
        if (
            isinstance(node, ast.Expr)
            and isinstance(node.value, ast.Call)
            and isinstance(node.value.func, ast.Attribute)
            and node.value.func.attr == "__init__"
        ):
            break
    probe = parts[2] / "actual-alias-root-probe.py"
    probe.write_text(
        ast.unparse(ast.Module(body=prefix, type_ignores=[])) + "\nprint(source)\n"
    )
    process = subprocess.run(
        [sys.executable, str(probe)],
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    assert process.returncode == 0 and process.stdout.strip() == str(other)
    atomic_json(
        parts[2] / "actual-alias-root-probe.json",
        {
            "argv": [sys.executable, str(probe)],
            "exit_code": process.returncode,
            "actual_source": process.stdout.strip(),
            "scanner_candidate_source": str(parts[3]),
            "producer": artifact_ref(producer),
            "probe": artifact_ref(probe),
        },
    )
    with pytest.raises(TalkCutError, match="source|construction"):
        inventory(parts)
