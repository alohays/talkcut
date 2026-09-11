"""Independent bounded root-slot controls; no producer or build is executed."""

import ast
import json

import pytest
from _privacy_source_tree import rebind
from test_privacy_current_native_source import native_parts, observe

from talkcut.project import TalkCutError, atomic_json


@pytest.mark.parametrize("legacy", [False, True])
@pytest.mark.parametrize("names", [("S", "B"), ("s" * 128, "b" * 128)])
def test_bounded_literal_names_are_general_and_keep_the_complete_tree(tmp_path, legacy, names):
    parts = native_parts(tmp_path, legacy=legacy)
    old_source = parts[3]
    source = parts[2] / names[0]
    old_build = parts[2] / "build-r4"
    build = parts[2] / names[1]
    replacements = {
        old_source.name: names[0], old_build.name: names[1],
        str(old_source): str(source), str(old_build): str(build),
    }
    old_source.rename(source)
    parts[3] = source
    producer = parts[2] / "producer.py"
    syntax = ast.parse(producer.read_text())
    for node in ast.walk(syntax):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            node.value = replacements.get(node.value, node.value)
    producer.write_text(ast.unparse(ast.fix_missing_locations(syntax)) + "\n")
    payload = json.loads(parts[4].read_text())
    for row in payload["commands"]:
        row["cwd"] = str(source)
        row["argv"] = [replacements.get(value, value) for value in row["argv"]]
    atomic_json(parts[4], payload)
    rebind(parts, origin=True)
    result = observe(parts)[0]
    assert result["row_count"] == 3
    assert {row["actual"]["path"] for row in result["files"]} == {
        str(path) for path in source.rglob("*") if path.is_file()
    }
    assert all(result[field] == "UNVERIFIED" for field in (
        "claim_status", "copy_history_status", "build_status", "runtime_status", "av_status"
    ))


@pytest.mark.parametrize("value", [
    "", ".", "..", "../build", "/absolute", "nested/build", "nested\\build",
    ".hidden", "b" * 129, True, 1, "llama.cpp-qwen3a-valid-mel-floor",
    "build-execution-synthetic",
])
def test_build_root_requires_its_own_distinct_bounded_literal_component(tmp_path, value):
    parts = native_parts(tmp_path)
    producer = parts[2] / "producer.py"
    syntax = ast.parse(producer.read_text())
    assignment = next(node for node in syntax.body if isinstance(node, ast.Assign)
                      and isinstance(node.targets[0], ast.Name) and node.targets[0].id == "build")
    assignment.value.right = ast.Constant(value)
    producer.write_text(ast.unparse(ast.fix_missing_locations(syntax)) + "\n")
    rebind(parts, origin=True)
    with pytest.raises(TalkCutError):
        observe(parts)


def test_recorded_build_success_never_promotes_current_byte_origin(tmp_path):
    parts = native_parts(tmp_path)
    payload = json.loads(parts[4].read_text())
    payload["status"] = "PASS"
    atomic_json(parts[4], payload)
    rebind(parts, origin=True)
    result = observe(parts)[0]
    assert result["origin_scope"] == "current_native_source_bytes/v1"
    assert all(result[field] == "UNVERIFIED" for field in (
        "claim_status", "copy_history_status", "build_status", "runtime_status", "av_status"
    ))
