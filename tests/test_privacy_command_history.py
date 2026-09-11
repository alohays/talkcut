"""Actual tiny command bytes; their historical observation never certifies PASS."""
import json
import os
import shutil
import sys
from pathlib import Path

import pytest

from talkcut import privacy_checks as privacy
from talkcut.project import TalkCutError, artifact_ref, atomic_json, init_project
from talkcut.verification import _run_command


def fixture(tmp_path, exit_code=1):
    original = tmp_path / "authored-source.bin"
    original.write_bytes(b"Authored registration identity only; not decoded media")
    task = tmp_path / "task"
    project = init_project(task, original, original)
    registered = {role: value["sha256"] for role, value in project["sources"].items()}
    directory = task / "capability" / "tiny-command"
    directory.mkdir(parents=True)
    returned = _run_command("checks", [sys.executable, "-c", f"print('invented command log'); raise SystemExit({exit_code})"], Path.cwd(), directory, dict(os.environ), timeout=10)
    current = directory / "checks.command.json"
    snapshot = task / "audits" / "preserved-command.json"
    snapshot.parent.mkdir()
    shutil.copyfile(current, snapshot)
    original_ref = returned["receipt"]
    assert artifact_ref(snapshot)["sha256"] == original_ref["sha256"]
    atomic_json(current, returned)
    parent = snapshot.with_name("origin.json")
    atomic_json(parent, {"observations": [{"declared": original_ref}], "private_note": "This invented private diagnostic origin text must remain protected in its complete metadata body."})
    locator = {"original": original_ref, "snapshot": artifact_ref(snapshot), "current": artifact_ref(current), "parent": artifact_ref(parent), "pointer": "/observations/0/declared"}
    atomic_json(task / "checkpoint.local.json", {"origin": artifact_ref(parent), "current": artifact_ref(current)})
    return task, registered, current, snapshot, parent, locator


def collect(parts, locators=None):
    return privacy.build_private_inventory(parts[0], parts[1], Path.cwd(),
        historical_verification_command_observations=[parts[-1]] if locators is None else locators)


def rebind(parts, value, *, raw_nonfinite=False):
    task, _registered, current, snapshot, parent, locator = parts
    if raw_nonfinite:
        snapshot.write_text(json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n")
    else:
        atomic_json(snapshot, value)
    old = {"path": str(current), "sha256": artifact_ref(snapshot)["sha256"]}
    if raw_nonfinite:
        current.write_text(json.dumps({**value, "receipt": old}, sort_keys=True, separators=(",", ":")) + "\n")
    else:
        atomic_json(current, {**value, "receipt": old})
    payload = json.loads(parent.read_bytes())
    payload["observations"][0]["declared"] = old
    atomic_json(parent, payload)
    locator.update(original=old, snapshot=artifact_ref(snapshot), current=artifact_ref(current), parent=artifact_ref(parent))
    atomic_json(task / "checkpoint.local.json", {"origin": artifact_ref(parent), "current": artifact_ref(current)})


@pytest.mark.parametrize("exit_code", [0, 1])
def test_actual_command_versions_preserve_private_bytes_without_execution_approval(tmp_path, exit_code):
    parts = fixture(tmp_path, exit_code)
    result = collect(parts)
    row = result["known_graph"]["historical_verification_command_observations"][0]
    assert row["original"] == parts[-1]["original"]
    assert row["claimed_original_exit_code"] == exit_code
    assert row["claimed_original_status"] == ("PASS" if exit_code == 0 else "FAIL")
    assert row["claim_status"] == row["execution_status"] == row["validation_status"] == "UNVERIFIED"
    entries = {entry["path"]: entry for entry in result["entries"]}
    for ref in [row["current"], row["snapshot"], row["parent"], *row["log_refs"]]:
        assert entries[ref["path"]]["sha256"] == ref["sha256"]
        assert entries[ref["path"]]["classification"] == "review"
    assert result["classification_status"] == "UNVERIFIED"
    known, phrases, _ = privacy._known_private_inventory(parts[0], parts[1], Path.cwd(),
        historical_verification_command_observations=[parts[-1]])
    assert known[row["snapshot"]["sha256"]] == "review"
    assert json.loads(parts[4].read_bytes())["private_note"] in phrases
    assert result["entries"] == collect(parts)["entries"]
    for path in (parts[2], parts[3]):
        with pytest.raises(TalkCutError, match="Immutable"):
            privacy._auxiliary_json(path, Path.cwd(), set(parts[1].values()))
    with pytest.raises(TalkCutError, match="changed"):
        privacy._file(row["original"])
    with pytest.raises(TalkCutError): collect(parts, [])


@pytest.mark.parametrize("damage", [
    "old_hash", "current_hash", "snapshot_hash", "parent_hash", "original_path", "current_path", "snapshot_same", "parent_alias", "outside_parent",
    "protected_current", "protected_snapshot", "protected_parent", "parent_identity", "pointer_wrong", "pointer_scalar", "pointer_bad_escape", "pointer_index_bool",
    "nested_formal_parent", "source_transcript_parent", "origin_value", "duplicate", "extra_locator_key", "unknown_schema", "extra_field", "exit_bool", "timeout_bool", "interrupted_int",
    "numeric_nan", "numeric_infinite", "numeric_bool", "time_reversed", "time_naive", "time_wrong_type", "wrong_status", "log_hash", "log_path", "argv_type", "cwd", "selfref", "other_edit",
])
def test_historical_command_wrong_identity_structure_and_authority_refuse(tmp_path, damage):
    parts = fixture(tmp_path)
    task, registered, current, snapshot, parent, locator = parts
    old = json.loads(snapshot.read_bytes())
    locators = [locator]
    changed_old = False
    if damage == "old_hash": locator["original"]["sha256"] = "f" * 64
    elif damage == "current_hash": locator["current"]["sha256"] = "f" * 64
    elif damage == "snapshot_hash": locator["snapshot"]["sha256"] = "f" * 64
    elif damage == "parent_hash": locator["parent"]["sha256"] = "f" * 64
    elif damage == "original_path": locator["original"]["path"] = str(parent)
    elif damage == "current_path": locator["current"]["path"] = str(snapshot)
    elif damage == "snapshot_same": locator["snapshot"] = locator["current"]
    elif damage == "parent_alias":
        alias = parent.with_name("alias.json"); alias.symlink_to(parent.name); locator["parent"]["path"] = str(alias)
    elif damage == "outside_parent":
        other = tmp_path / "outside.json"; shutil.copyfile(parent, other); locator["parent"] = artifact_ref(other)
    elif damage.startswith("protected_"):
        target_key = damage.removeprefix("protected_"); original = Path(locator[target_key]["path"])
        other = task / "transcripts" / original.name; other.parent.mkdir(); shutil.copyfile(original, other); locator[target_key] = artifact_ref(other)
    elif damage == "parent_identity":
        with pytest.raises(TalkCutError):
            privacy._historical_verification_command_inventory([locator], task, Path.cwd(), {locator["parent"]["sha256"]})
        return
    elif damage == "pointer_wrong": locator["pointer"] = "/observations/1/declared"
    elif damage == "pointer_scalar": locator["pointer"] = "/private_note/path"
    elif damage == "pointer_bad_escape": locator["pointer"] = "/observations/~2/declared"
    elif damage == "pointer_index_bool": locator["pointer"] = "/observations/false/declared"
    elif damage in {"nested_formal_parent", "source_transcript_parent", "origin_value"}:
        payload = json.loads(parent.read_bytes())
        if damage == "nested_formal_parent": payload["nested"] = {"schema_version": "review-request/v1"}
        elif damage == "source_transcript_parent": payload["nested"] = {"schema_version": "transcript/v1", "source_sha256": registered["screen"], "text": "Invented private transcript data is protected."}
        else: payload["observations"][0]["declared"]["sha256"] = "f" * 64
        atomic_json(parent, payload); locator["parent"] = artifact_ref(parent)
    elif damage == "duplicate": locators *= 2
    elif damage == "extra_locator_key": locator["approved"] = True
    elif damage in {"selfref", "other_edit"}:
        payload = json.loads(current.read_bytes())
        if damage == "selfref": payload["receipt"]["sha256"] = "f" * 64
        else: payload["wall_seconds"] += 1
        atomic_json(current, payload); locator["current"] = artifact_ref(current)
    else:
        changed_old = True
        if damage == "unknown_schema": old["schema_version"] = "execution-receipt/v1"
        elif damage == "extra_field": old["text"] = "Private transcript content cannot become supported command metadata."
        elif damage == "exit_bool": old["exit_code"] = True
        elif damage == "timeout_bool": old["timed_out"] = 0
        elif damage == "interrupted_int": old["interrupted"] = 1
        elif damage == "numeric_nan": old["wall_seconds"] = float("nan")
        elif damage == "numeric_infinite": old["wall_seconds"] = float("inf")
        elif damage == "numeric_bool": old["timeout_seconds"] = True
        elif damage == "time_reversed": old["started_at"], old["finished_at"] = old["finished_at"], old["started_at"]
        elif damage == "time_naive": old["started_at"] = "2026-01-01T00:00:00"
        elif damage == "time_wrong_type": old["started_at"] = True
        elif damage == "wrong_status": old["status"] = "PASS"
        elif damage == "log_hash": old["stdout"]["sha256"] = "f" * 64
        elif damage == "log_path": old["stdout"] = old["stderr"]
        elif damage == "argv_type": old["argv"] = True
        elif damage == "cwd": old["cwd"] = str(tmp_path)
    if changed_old: rebind(parts, old, raw_nonfinite=damage in {"numeric_nan", "numeric_infinite"})
    with pytest.raises(TalkCutError): collect(parts, locators)


@pytest.mark.parametrize("role", ["current", "snapshot", "parent", "stdout"])
def test_real_same_byte_identity_replacement_between_observations_rejects(tmp_path, monkeypatch, role):
    parts = fixture(tmp_path)
    old = json.loads(parts[3].read_bytes())
    path = Path(old[role]["path"] if role == "stdout" else parts[-1][role]["path"])
    original = privacy._historical_verification_command_inventory
    calls = 0
    def replace(*args, **kwargs):
        nonlocal calls
        result = original(*args, **kwargs)
        calls += 1
        if calls == 1:
            other = path.with_name("replacement.bin"); other.write_bytes(path.read_bytes()); other.replace(path)
        return result
    monkeypatch.setattr(privacy, "_historical_verification_command_inventory", replace)
    with pytest.raises(TalkCutError, match="changed during inventory"):
        collect(parts)


def test_private_transcript_log_bytes_keep_stronger_private_classification(tmp_path):
    parts = fixture(tmp_path)
    old = json.loads(parts[3].read_bytes())
    log = Path(old["stdout"]["path"])
    transcript = parts[0] / "transcripts" / "captured-log.txt"
    transcript.parent.mkdir()
    shutil.copyfile(log, transcript)
    result = collect(parts)
    entries = {entry["path"]: entry for entry in result["entries"]}
    assert entries[str(log)]["classification"] == "transcript"
    assert entries[str(transcript)]["classification"] == "transcript"
    assert result["classification_status"] == "UNVERIFIED"
    assert result["known_graph"]["historical_verification_command_observations"][0]["execution_status"] == "UNVERIFIED"


@pytest.mark.parametrize("field, value", [("timed_out", 0), ("exit_code", True), ("timeout_seconds", 10.0)])
def test_current_command_json_field_types_cannot_change(tmp_path, field, value):
    parts = fixture(tmp_path)
    current = parts[2]
    payload = json.loads(current.read_bytes())
    assert type(payload[field]) is not type(value)
    payload[field] = value
    atomic_json(current, payload)
    parts[-1]["current"] = artifact_ref(current)
    atomic_json(parts[0] / "checkpoint.local.json", {"origin": artifact_ref(parts[4]), "current": artifact_ref(current)})
    with pytest.raises(TalkCutError, match="changes beyond"):
        collect(parts)
