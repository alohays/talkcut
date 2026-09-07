"""Actual permission and file-identity regressions for complete inventories."""

import os
import stat
from pathlib import Path

import pytest
from _privacy_source_tree import fixture
from test_privacy_historical_source_tree import snapshot

from talkcut import privacy_checks as privacy
from talkcut.project import TalkCutError, artifact_ref


def collect(parts):
    return privacy.build_private_inventory(
        parts[0], parts[1], Path.cwd(), auxiliary_source_trees=[parts[-1]]
    )


@pytest.mark.parametrize("pass_number", [1, 2])
def test_task_wide_unreadable_directory_is_rejected_on_either_pass(
    tmp_path, monkeypatch, pass_number
):
    parts = fixture(tmp_path)
    hidden = parts[0] / "ordinary-unreferenced"
    hidden.mkdir()
    payload = hidden / "private.txt"
    payload.write_text(
        "Authored unreferenced private content remains in the entire task denominator."
    )
    readable = collect(parts)
    assert any(row["path"] == str(payload) for row in readable["entries"])
    original_walk = privacy.os.walk
    calls = 0
    denied = []

    def walk(top, *args, **kwargs):
        nonlocal calls
        if Path(top) == parts[0]:
            calls += 1
            if calls == pass_number:
                hidden.chmod(0)
                with pytest.raises(PermissionError), os.scandir(hidden) as entries:
                    list(entries)
                denied.append(True)
        return original_walk(top, *args, **kwargs)

    monkeypatch.setattr(privacy.os, "walk", walk)
    try:
        with pytest.raises(
            TalkCutError, match="Task inventory traversal is unreadable"
        ):
            collect(parts)
    finally:
        hidden.chmod(0o700)
    monkeypatch.setattr(privacy.os, "walk", original_walk)
    assert denied == [True] and collect(parts)["entries"] == readable["entries"]


def source_observation(parts, role):
    if role == "current_manifest":
        return parts[3] / "main.cpp", lambda: privacy._auxiliary_source_tree_inventory(
            [parts[-1]], parts[0], Path.cwd(), set(parts[1].values())
        )
    locator, directory = snapshot(parts)
    target = (
        (directory / "source/main.cpp")
        if role == "historical_copy"
        else parts[3] / "main.cpp"
    )
    return target, lambda: privacy._auxiliary_historical_source_tree_inventory(
        [locator], parts[0], Path.cwd(), set(parts[1].values())
    )


@pytest.mark.parametrize(
    "role", ["current_manifest", "historical_copy", "historical_current"]
)
def test_actual_read_atime_does_not_change_source_identity(tmp_path, monkeypatch, role):
    parts = fixture(tmp_path)
    target, observe = source_observation(parts, role)
    before_ref = artifact_ref(target)
    old = target.stat()
    os.utime(target, ns=(1_000_000_000, old.st_mtime_ns))
    real = privacy.artifact_ref
    reads = []

    def measure(path):
        if Path(path) == target:
            before = target.stat()
            value = real(path)
            after = target.stat()
            reads.append((before, after))
            return value
        return real(path)

    monkeypatch.setattr(privacy, "artifact_ref", measure)
    result = observe()
    assert (
        result[0]["claim_status"] == "UNVERIFIED"
        and real(target) == before_ref
        and reads
    )
    for before, after in reads:
        assert (
            before.st_dev,
            before.st_ino,
            before.st_mode,
            before.st_nlink,
            before.st_uid,
            before.st_gid,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        ) == (
            after.st_dev,
            after.st_ino,
            after.st_mode,
            after.st_nlink,
            after.st_uid,
            after.st_gid,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
        assert after.st_atime_ns >= before.st_atime_ns


@pytest.mark.parametrize(
    "role", ["current_manifest", "historical_copy", "historical_current"]
)
@pytest.mark.parametrize("mutation", ["inode", "mode", "mtime"])
def test_non_access_identity_changes_still_reject_even_with_same_bytes(
    tmp_path, monkeypatch, role, mutation
):
    parts = fixture(tmp_path)
    target, observe = source_observation(parts, role)
    expected = artifact_ref(target)
    real = privacy.artifact_ref
    changed = []

    def mutate(path):
        value = real(path)
        if Path(path) == target and not changed:
            old = target.stat()
            if mutation == "inode":
                replacement = target.with_name("replacement")
                replacement.write_bytes(target.read_bytes())
                os.replace(replacement, target)
            elif mutation == "mode":
                target.chmod(stat.S_IMODE(old.st_mode) ^ 0o100)
            else:
                os.utime(target, ns=(old.st_atime_ns, old.st_mtime_ns + 1_000_000))
            changed.append(True)
        return value

    monkeypatch.setattr(privacy, "artifact_ref", mutate)
    with pytest.raises(TalkCutError, match="changed|private source"):
        observe()
    assert changed == [True] and real(target)["sha256"] == expected["sha256"]
