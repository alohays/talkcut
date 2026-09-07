"""Source construction and every explicit CMake configure claim stay bound."""

import json

import pytest
from _privacy_source_tree import fixture, privacy, rebind, set_commands

from talkcut.project import TalkCutError, atomic_json


def observe(parts):
    return privacy._auxiliary_source_tree_inventory(
        [parts[-1]], parts[0], privacy.Path.cwd(), set(parts[1].values())
    )


@pytest.mark.parametrize(
    "body",
    [
        "__file__ = '/tmp/other.py'\n",
        "del __file__\n",
        "def Path(value):\n return value\n",
        "async def Path(value):\n return value\n",
        "class Path:\n pass\n",
        "def __file__():\n return 'other'\n",
        "def other(__file__):\n return __file__\n",
        "try:\n pass\nexcept Exception as __file__:\n pass\n",
        "match 'value':\n case __file__:\n  pass\n",
        "from pathlib import Path as __file__\n",
        "from pathlib import *\n",
    ],
)
def test_root_symbol_bindings_fail_closed_even_after_root_declarations(tmp_path, body):
    parts = fixture(tmp_path)
    producer = parts[2] / "producer.py"
    producer.write_text(producer.read_text() + "\n" + body)
    rebind(parts, origin=True)
    with pytest.raises(TalkCutError, match="source|construction|imports"):
        observe(parts)


@pytest.mark.parametrize(
    "arguments",
    [
        lambda a, b: ["-S", a, "-S", b],
        lambda a, b: ["-S", a, "-S", a],
        lambda a, b: ["-S", a, "-S" + b],
        lambda a, b: ["-S" + a],
        lambda a, b: ["-S", a, b],
        lambda a, b: ["-S", a, "--preset", "external"],
        lambda a, b: ["-S", a, "-P", b],
        lambda a, b: ["-S", a, "-B"],
    ],
)
def test_ambiguous_configure_command_cannot_hide_other_source(tmp_path, arguments):
    parts = fixture(tmp_path)
    value = json.loads(parts[4].read_text())
    value["commands"][0]["argv"] = [
        "cmake",
        *arguments(str(parts[3]), str(tmp_path / "other")),
    ]
    atomic_json(parts[4], value)
    rebind(parts)
    with pytest.raises(TalkCutError, match="source|configured"):
        observe(parts)


@pytest.mark.parametrize(
    "arguments",
    [
        lambda b: ["-S", b],
        lambda b: ["-S" + b],
        lambda b: [b],
        lambda b: ["--preset", "external"],
    ],
)
def test_later_configure_command_is_also_checked(tmp_path, arguments):
    parts = fixture(tmp_path)
    value = json.loads(parts[4].read_text())
    value["commands"].append(
        {"cwd": str(parts[3]), "argv": ["cmake", *arguments(str(tmp_path / "other"))]}
    )
    atomic_json(parts[4], value)
    rebind(parts)
    with pytest.raises(TalkCutError, match="source|configured"):
        observe(parts)


def test_repeated_matching_configure_and_supported_nonconfigure_commands_remain_observable(
    tmp_path,
):
    parts = fixture(tmp_path)
    value = json.loads(parts[4].read_text())
    value["commands"] = [
        {"cwd": str(parts[3]), "argv": ["cmake", "--version"]},
        *value["commands"],
        {
            "cwd": str(parts[3]),
            "argv": [
                "/usr/bin/cmake",
                "-S",
                str(parts[3]),
                "-B",
                str(parts[2] / "other-build"),
                "-G",
                "Ninja",
                "-DTEST=ON",
            ],
        },
        {
            "cwd": str(parts[3]),
            "argv": ["cmake", "--build", str(parts[2] / "other-build")],
        },
    ]
    set_commands(parts, [row["argv"] for row in value["commands"]])
    result = observe(parts)[0]
    assert result["row_count"] == 3 and result["claim_status"] == "UNVERIFIED"
