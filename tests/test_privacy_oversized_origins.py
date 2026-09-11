"""Bounded real-file consumer controls; no stored producer is executed."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from oversized_fixture import REASON, fixture, observe, refresh, write

from talkcut.project import TalkCutError

LEAVES = [
    ["known_graph", "public_work_candidates", 0, "reason"],
    ["known_graph", "unfollowed_refs", 0, "reason"],
    ["known_graph", "reason"], ["known_graph", "scope"], ["scope"],
    ["known_graph", "auxiliary_execution_sources", 0, "scope"],
    ["known_graph", "auxiliary_metadata_history", 0, "scope"],
    *[["known_graph", "synthetic_failure_fixtures", 0, "rows", index, "reason"] for index in range(3)],
    ["known_graph", "synthetic_failure_fixtures", 0, "current_reproduction", "scope"],
]


@pytest.mark.parametrize("edge", LEAVES)
def test_real_consumer_preserves_complete_parent_and_exact_leaf(tmp_path, edge):
    parts = fixture(tmp_path)
    original = Path(parts["parent"]["path"]).read_bytes()
    row = parts["body"]
    for key in edge[:-1]:
        row = row[key]
    result = observe(parts, edge)[0]
    assert result["selected_value"] == row[edge[-1]]
    assert result["associated_row"] == row
    assert result["extractions"] == [{"edge": edge, "value": row[edge[-1]]}]
    assert result["claim_status"] == "UNVERIFIED"
    assert result["classification"] == "review"
    assert result["parent"] == parts["parent"]
    assert Path(parts["parent"]["path"]).read_bytes() == original


@pytest.mark.parametrize(("file", "needle", "replacement"), [
    ("script", "result = privacy.build_private_inventory", "privacy = None\nresult = privacy.build_private_inventory"),
    ("script", "result = privacy.build_private_inventory", "raise RuntimeError('synthetic stop')\nresult = privacy.build_private_inventory"),
    ("script", "result = privacy.build_private_inventory", "privacy.build_private_inventory = None\nresult = privacy.build_private_inventory"),
    ("script", "atomic_json(HERE / 'oversized-stdout-inventory.json', result)", "result.clear()\natomic_json(HERE / 'oversized-stdout-inventory.json', result)"),
    ("script", "synthetic_negative_runs=[runref]", "synthetic_negative_runs=[]"),
    ("script", "ROOT / 'failure/result.json'", "ROOT / 'unused/result.json'"),
    ("helper", "privacy = importlib.util.module_from_spec(spec)", "privacy = None"),
    ("helper", "rows = []", "raise RuntimeError('synthetic stop')\nrows = []"),
    ("helper", "return (case, directory, sources", "return (HERE / 'unrelated', directory, sources"),
])
def test_called_writer_binding_and_paths_refuse_rebound_fault(tmp_path, file, needle, replacement):
    parts = fixture(tmp_path)
    assert observe(parts)
    path = Path(parts[file]["path"])
    before = path.read_text()
    assert needle in before
    path.write_text(before.replace(needle, replacement, 1))
    refresh(parts)
    with pytest.raises(TalkCutError):
        observe(parts)


@pytest.mark.parametrize("fault", [
    "_known_private_inventory = None\n", "verify_release_privacy = None\n",
    "raise RuntimeError('synthetic module stop')\n",
    "def dormant():\n    return 'unrelated unused producer'\n",
])
def test_complete_source_module_refuses_rebinding_and_unused_source(tmp_path, fault):
    parts = fixture(tmp_path)
    assert observe(parts)
    source = Path(parts["source"]["path"])
    source.write_text(source.read_text() + "\n" + fault)
    new_source = {"path": str(source), "sha256": hashlib.sha256(source.read_bytes()).hexdigest()}
    challenge = json.loads(Path(parts["challenge"]["path"]).read_bytes())
    challenge["source"] = new_source
    write(parts["challenge"]["path"], challenge)
    refresh(parts)
    with pytest.raises(TalkCutError, match="complete supported original invocation-scope grammar"):
        observe(parts)


@pytest.mark.parametrize("file", ["source", "script"])
@pytest.mark.parametrize("codec", ["talkcut_missing_codec", "utf-16"])
def test_actual_python_bytes_decoding_refuses(tmp_path, file, codec):
    parts = fixture(tmp_path)
    path = Path(parts[file]["path"])
    path.write_bytes(("# coding: " + codec + "\n").encode() + path.read_bytes())
    if file == "source":
        challenge = json.loads(Path(parts["challenge"]["path"]).read_bytes())
        challenge["source"] = {"path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
        write(parts["challenge"]["path"], challenge)
    refresh(parts)
    with pytest.raises(TalkCutError, match="Python|UTF|source"):
        observe(parts)


@pytest.mark.parametrize("fault", ["metadata_sha", "metadata_status", "row_sha", "row_case", "replay_artifacts", "replay_scope", "entry_count", "reported_presence"])
def test_complete_record_relationships_refuse(tmp_path, fault):
    parts = fixture(tmp_path)
    assert observe(parts)
    known = parts["body"]["known_graph"]
    if fault == "metadata_sha":
        known["auxiliary_metadata_history"][0]["original_reference"]["sha256"] = "1" * 64
    elif fault == "metadata_status":
        known["auxiliary_metadata_history"][0]["claim_status"] = "PASS"
    elif fault == "row_sha":
        known["synthetic_failure_fixtures"][0]["rows"][0]["declared_reference"]["sha256"] = "1" * 64
    elif fault == "row_case":
        known["synthetic_failure_fixtures"][0]["rows"][0]["case"] = "wrong_hashes.output_bytes"
    elif fault == "replay_artifacts":
        known["synthetic_failure_fixtures"][0]["current_reproduction"]["artifacts"] = []
    elif fault == "replay_scope":
        known["synthetic_failure_fixtures"][0]["current_reproduction"]["scope"] = "Unverified authored prose"
    elif fault == "entry_count":
        parts["body"]["entry_count"] += 1
    else:
        parts["result_body"]["binary_named_stdout_in_inventory"] = False
    refresh(parts)
    with pytest.raises(TalkCutError):
        observe(parts)


@pytest.mark.parametrize("place", ["root", "known", "row", "outside"])
def test_whole_parent_speech_refusal_remains(tmp_path, place):
    parts = fixture(tmp_path)
    descriptor = {"schema_version": "transcript/v1", "source_sha256": parts["registered"]["screen"], "text": REASON}
    if place == "root":
        parts["body"]["schema_version"] = "transcript/v1"
    elif place == "known":
        parts["body"]["known_graph"]["schema_version"] = "transcript/v1"
    elif place == "row":
        parts["body"]["known_graph"]["public_work_candidates"][0]["speech"] = descriptor
    else:
        parts["body"]["unresolved"].append(descriptor)
        parts["result_body"]["unresolved"] = parts["body"]["unresolved"]
    refresh(parts)
    with pytest.raises(TalkCutError):
        observe(parts)


def test_unselected_identical_prose_is_preserved_outside_leaf(tmp_path):
    parts = fixture(tmp_path)
    parts["body"]["unresolved"].append(REASON)
    parts["result_body"]["unresolved"] = parts["body"]["unresolved"]
    refresh(parts)
    result = observe(parts)[0]
    assert result["extractions"] == [{"edge": LEAVES[0], "value": REASON}]
    assert json.loads(Path(result["parent"]["path"]).read_bytes())["unresolved"] == [REASON]


@pytest.mark.parametrize("edge", [
    ["known_graph"], ["known_graph", "public_work_candidates", 0],
    ["known_graph", "synthetic_failure_fixtures", 0, "current_reproduction", "generator_argv_prefix", 0],
    ["unresolved", 0],
])
def test_only_closed_string_leaves_can_project(tmp_path, edge):
    parts = fixture(tmp_path)
    with pytest.raises(TalkCutError):
        observe(parts, edge)
