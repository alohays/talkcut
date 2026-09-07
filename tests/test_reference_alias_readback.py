"""Extra physical alias/readback controls for the bounded R2 correction."""

import hashlib
import os

import pytest
from test_privacy_reference_alias import nested_collector
from test_reference_alias_independent import parent_alias

from talkcut.project import TalkCutError, artifact_ref, atomic_json


def verify_rows(rows):
    from pathlib import Path

    for row in rows.values():
        path = Path(row["path"])
        assert row["classification"] == "UNCLASSIFIED"
        if row["entry_type"] == "symlink":
            assert path.is_symlink()
            assert os.readlink(path) == row["target"]
            assert hashlib.sha256(os.fsencode(row["target"])).hexdigest() == row["sha256"]
        else:
            assert path.is_file() and not path.is_symlink()
            assert artifact_ref(path)["sha256"] == row["sha256"]


@pytest.mark.parametrize("form", ["leaf", "parent"])
def test_same_text_alias_inode_replacement_is_rejected(tmp_path, form):
    alias, target, requested = parent_alias(tmp_path)
    if form == "leaf":
        alias = tmp_path / "leaf-alias"
        alias.symlink_to(target)
        requested = alias
    ns = nested_collector(tmp_path)
    expected = artifact_ref(target)["sha256"]
    ns["collect"](requested, expected)
    text, inode = os.readlink(alias), alias.lstat().st_ino
    alias.rename(alias.with_name("preserved-original-link"))
    alias.symlink_to(text, target_is_directory=form == "parent")
    assert alias.lstat().st_ino != inode and os.readlink(alias) == text
    with pytest.raises(TalkCutError):
        ns["collect"](requested, expected)


@pytest.mark.parametrize("damage", ["text", "escape_same_bytes", "bytes", "cycle", "missing"])
def test_repeated_parent_alias_cannot_change_its_bound_chain_or_bytes(tmp_path, damage):
    alias, target, requested = parent_alias(tmp_path)
    ns = nested_collector(tmp_path)
    expected = artifact_ref(target)["sha256"]
    ns["collect"](requested, expected)
    if damage == "bytes":
        target.write_bytes(b"Different current target bytes")
    elif damage == "missing":
        target.rename(target.with_name("preserved-payload.bin"))
    else:
        alias.rename(alias.with_name("preserved-original-link"))
        if damage == "text":
            alias.symlink_to("./real", target_is_directory=True)
        elif damage == "cycle":
            alias.symlink_to(alias.name, target_is_directory=True)
        else:
            other = tmp_path / "different-target-directory"
            other.mkdir()
            (other / target.name).write_bytes(target.read_bytes())
            alias.symlink_to(other, target_is_directory=True)
    with pytest.raises(TalkCutError):
        ns["collect"](requested, expected)


@pytest.mark.parametrize("same_bytes", [True, False])
def test_target_inode_replacement_has_only_current_byte_authority(tmp_path, same_bytes):
    alias, target, requested = parent_alias(tmp_path)
    ns = nested_collector(tmp_path)
    expected = artifact_ref(target)["sha256"]
    ns["collect"](requested, expected)
    data, inode = target.read_bytes(), target.stat().st_ino
    target.rename(target.with_name("preserved-original-target.bin"))
    target.write_bytes(data if same_bytes else b"Replaced inode with changed content")
    assert target.stat().st_ino != inode
    if not same_bytes:
        with pytest.raises(TalkCutError):
            ns["collect"](requested, expected)
        return
    # Canonical path/SHA/bytes are the emitted target identity. No target inode
    # or historical execution claim is emitted or silently introduced here.
    ns["collect"](requested, expected)
    assert set(ns["entries"]) == {str(alias), str(target)}
    verify_rows(ns["entries"])
    atomic_json(tmp_path / "same-byte-inode-readback.json", {
        "target_inode_changed": True, "current_rows_verified": True,
        "claim_status": "UNVERIFIED", "entries": ns["entries"],
    })


def test_regular_target_cannot_acquire_literal_link_role(tmp_path):
    _, target, _ = parent_alias(tmp_path)
    with pytest.raises(TalkCutError):
        nested_collector(tmp_path)["collect"](target, artifact_ref(target)["sha256"], literal_link=True)
