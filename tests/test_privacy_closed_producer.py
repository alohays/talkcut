"""Closed recorder grammar controls; no synthetic execution claim is approved."""

import ast
import json
import subprocess
import sys

import pytest
from _privacy_source_tree import fixture, privacy, rebind, set_commands

from talkcut.project import TalkCutError, artifact_ref, atomic_json


def observe(parts):
    return privacy._auxiliary_source_tree_inventory(
        [parts[-1]], parts[0], privacy.Path.cwd(), set(parts[1].values())
    )


@pytest.mark.parametrize(
    "mutation",
    [
        "alias=source\nalias.__init__(OTHER)\n",
        "holder=[source]\nholder[0].__init__(OTHER)\n",
        "holder={'root':source}\nholder['root'].__init__(OTHER)\n",
        "class Holder: pass\nholder=Holder()\nholder.root=source\nholder.root.__init__(OTHER)\n",
        "def mutate(value): value.__init__(OTHER)\nmutate(source)\n",
        "[source.__init__][0](OTHER)\n",
        "alias=source\nalias._raw_paths=[OTHER]\n",
        "alias=base\nalias.__init__(OTHER)\n",
        "str=lambda value: OTHER\n",
        "import pathlib as foreign\nforeign.Path.__init__=lambda *args: None\n",
    ],
)
def test_indirect_root_mutations_cannot_extend_the_fixed_program(tmp_path, mutation):
    parts = fixture(tmp_path)
    producer = parts[2] / "producer.py"
    other = tmp_path / "other-source"
    other.mkdir()
    inserted = mutation.replace("OTHER", repr(str(other)))
    original = producer.read_text()
    producer.write_text(
        original.replace("source=base/'source'\n", "source=base/'source'\n" + inserted)
    )
    rebind(parts, origin=True)
    with pytest.raises(TalkCutError, match="closed supported source construction"):
        observe(parts)


def test_actual_alias_root_changes_but_closed_program_rejects_it(tmp_path):
    parts = fixture(tmp_path)
    producer = parts[2] / "producer.py"
    other = tmp_path / "other-source"
    other.mkdir()
    body = producer.read_text().replace(
        "source=base/'source'\n",
        "source=base/'source'\nalias=source\nalias.__init__("
        + repr(str(other))
        + ")\n",
    )
    producer.write_text(body)
    rebind(parts, origin=True)
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
    probe = parts[2] / "actual-root-probe.py"
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
    assert result.returncode == 0 and result.stdout.strip() == str(other)
    atomic_json(
        parts[2] / "actual-root-probe.json",
        {
            "argv": [sys.executable, str(probe)],
            "exit_code": result.returncode,
            "actual_source": result.stdout.strip(),
            "candidate_source": str(parts[3]),
            "probe": artifact_ref(probe),
            "producer": artifact_ref(producer),
        },
    )
    with pytest.raises(TalkCutError, match="closed supported source construction"):
        observe(parts)


@pytest.mark.parametrize(
    "mutation",
    [
        "extra_import",
        "changed_ref",
        "changed_tree",
        "changed_loop",
        "changed_result_path",
        "command_expression",
        "command_keyword",
        "run_directory",
        "patch_literal",
        "environment_literal",
        "record_environment",
        "record_argv",
        "record_name",
        "record_log",
    ],
)
def test_nonliteral_program_or_unbound_literal_changes_reject(tmp_path, mutation):
    parts = fixture(tmp_path)
    producer = parts[2] / "producer.py"
    text = producer.read_text()
    value = json.loads(parts[4].read_bytes())
    if mutation == "extra_import":
        text = "import invented_extension\n" + text
    elif mutation == "changed_ref":
        text = text.replace("hashlib.sha256(data).hexdigest()", "'f' * 64")
    elif mutation == "changed_tree":
        text = text.replace("p.relative_to(source)", "p.relative_to(base)")
    elif mutation == "changed_loop":
        text = text.replace("cwd=source", "cwd=base")
    elif mutation == "changed_result_path":
        text = text.replace("run / 'result.local.json'", "base / 'result.local.json'")
    elif mutation == "command_expression":
        text = text.replace("'cmake'", "''.join(['c','make'])", 1)
    elif mutation == "command_keyword":
        text = text.replace("'cmake'", "str(object='cmake')", 1)
    elif mutation == "run_directory":
        text = text.replace("'build-execution-synthetic'", "'other-execution'", 1)
    elif mutation == "patch_literal":
        text = text.replace("'change.patch'", "'patch.json'", 1)
    elif mutation == "environment_literal":
        text = text.replace("'/synthetic/sdk'", "'/different/sdk'", 1)
    elif mutation == "record_environment":
        value["commands"][0]["environment_overrides"]["SDKROOT"] = "/different/sdk"
    elif mutation == "record_argv":
        value["commands"][0]["argv"].append("-DOTHER=ON")
    elif mutation == "record_name":
        value["commands"][0]["name"] = "different"
    else:
        other = parts[2] / "other.stdout"
        other.write_text("Authored unrelated output")
        value["commands"][0]["stdout"] = artifact_ref(other)
    producer.write_text(text)
    atomic_json(parts[4], value)
    rebind(parts, origin=True)
    with pytest.raises(TalkCutError):
        observe(parts)


@pytest.mark.parametrize(
    "arguments",
    [
        lambda a, b: ["cmake", "-S", a, "-S", b],
        lambda a, b: ["cmake", "-S", a, "-S", a],
        lambda a, b: ["cmake", "-S", a, "-P", b],
        lambda a, b: ["cmake", "-S" + b],
    ],
)
def test_same_closed_producer_and_typed_records_cannot_hide_conflicting_roots(
    tmp_path, arguments
):
    parts = fixture(tmp_path)
    set_commands(parts, [arguments(str(parts[3]), str(tmp_path / "other"))])
    with pytest.raises(TalkCutError, match="configured source|configured root"):
        observe(parts)


def test_unexecuted_declared_suffix_cannot_hide_a_conflicting_source_root(tmp_path):
    parts = fixture(tmp_path)
    set_commands(
        parts,
        [
            ["cmake", "-S", str(parts[3]), "-B", str(parts[2] / "build")],
            ["cmake", "-S", str(tmp_path / "other")],
        ],
    )
    value = json.loads(parts[4].read_bytes())
    value["commands"] = value["commands"][:1]
    atomic_json(parts[4], value)
    rebind(parts)
    with pytest.raises(TalkCutError, match="configured source|configured root"):
        observe(parts)


def test_literal_environment_values_are_data_when_both_record_and_program_match(
    tmp_path,
):
    parts = fixture(tmp_path)
    value = json.loads(parts[4].read_bytes())
    producer = parts[2] / "producer.py"
    literal = "/synthetic/quotes' and import text; no code execution"
    value["commands"][0]["environment_overrides"]["SDKROOT"] = literal
    body = producer.read_text().replace(repr("/synthetic/sdk"), repr(literal))
    producer.write_text(body)
    atomic_json(parts[4], value)
    rebind(parts, origin=True)
    row = observe(parts)[0]
    assert row["claim_status"] == "UNVERIFIED" and row["row_count"] == 3
