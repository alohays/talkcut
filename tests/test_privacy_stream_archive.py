"""Opaque private byte-preservation controls; no provider or content approval."""
import errno
import hashlib
import os
from pathlib import Path

import pytest

from talkcut import privacy_checks as privacy
from talkcut.project import TalkCutError, artifact_ref


def entries(tmp_path, bodies=(b"first source",), kinds=None):
    task = tmp_path / "task"
    task.mkdir()
    rows = {}
    for index, body in enumerate(bodies):
        path = task / f"input-{index}"
        path.write_bytes(body)
        rows[str(path)] = {**artifact_ref(path), "entry_type": "file",
                           "classification": kinds[index] if kinds else "review"}
    return task, rows


def preserve(tmp_path, rows, task):
    return privacy._preserve_private_inputs(rows, task, tmp_path / "archive")


def test_actual_oversized_opaque_bytes_preserved_without_parser_or_scan_expansion(tmp_path, monkeypatch):
    body = b"\xff\x00not JSON, no line boundary " * 700000
    assert len(body) > privacy.MAX_UNIT_BYTES
    task, rows = entries(tmp_path, (body,))
    read = os.read
    requests = []

    def bounded(fd, size):
        requests.append(size)
        return read(fd, size)

    monkeypatch.setattr(privacy.os, "read", bounded)
    saved, report = preserve(tmp_path, rows, task)
    ref = saved[next(iter(rows))]
    assert Path(ref["path"]).read_bytes() == body
    assert ref["sha256"] == hashlib.sha256(body).hexdigest()
    assert max(requests) == privacy.PRIVATE_ARCHIVE_CHUNK_BYTES == 1024 * 1024
    assert privacy.MAX_UNIT_BYTES == 16 * 1024 * 1024
    assert privacy.MAX_TOTAL_BYTES == 256 * 1024 * 1024
    assert report["status"] == "UNVERIFIED"
    observation = report["observations"][0]
    assert observation["source_identity_before"] == observation["source_identity_after"]
    assert observation["source_digest_before"] == observation["source_digest_after"]
    assert observation["source"]["sha256"] == observation["target"]["sha256"]
    assert not list((tmp_path / "archive").glob(".partial-*"))
    scanner = privacy.Scan({}, [])
    scanner.payload(body, "authored-oversized-private-archive-control")
    assert scanner.unknown and not scanner.units


@pytest.mark.parametrize("kind", ["review", "transcript"])
def test_exact_per_file_and_total_bounds_include_equal_byte_paths(tmp_path, monkeypatch, kind):
    task, rows = entries(tmp_path, (b"abcd", b"abcd"), (kind, kind))
    monkeypatch.setattr(privacy, "MAX_PRIVATE_ARCHIVE_FILE_BYTES", 4)
    monkeypatch.setattr(privacy, "MAX_PRIVATE_ARCHIVE_TOTAL_BYTES", 8)
    saved, report = preserve(tmp_path, rows, task)
    assert len(saved) == report["selected_path_count"] == 2
    assert len({ref["path"] for ref in saved.values()}) == report["unique_target_count"] == 1
    assert report["selected_path_bytes"] == 8
    assert {row["classification"] for row in rows.values()} == {kind}
    assert [row["created"] for row in report["observations"]] == [True, False]


@pytest.mark.parametrize("limit,value", [("MAX_PRIVATE_ARCHIVE_FILE_BYTES", 3),
                                         ("MAX_PRIVATE_ARCHIVE_TOTAL_BYTES", 7)])
def test_bound_overflow_fails_before_any_copy(tmp_path, monkeypatch, limit, value):
    task, rows = entries(tmp_path, (b"abcd", b"abcd"))
    monkeypatch.setattr(privacy, limit, value)
    with pytest.raises(TalkCutError, match="bound"):
        preserve(tmp_path, rows, task)
    assert not (tmp_path / "archive").exists()


@pytest.mark.parametrize("kind", ["UNCLASSIFIED", "media", "credentials"])
def test_archive_never_reclassifies_or_selects_other_roles(tmp_path, kind):
    task, rows = entries(tmp_path, (b"preserve", b"unselected"), ("review", kind))
    original = {name: dict(row) for name, row in rows.items()}
    saved, report = preserve(tmp_path, rows, task)
    assert rows == original
    assert set(saved) == {str(task / "input-0")}
    assert report["selected_path_count"] == 1


def test_empty_selected_set_and_empty_file_are_supported(tmp_path):
    task, rows = entries(tmp_path, (b"",))
    saved, report = preserve(tmp_path, rows, task)
    assert report["selected_path_bytes"] == 0 and len(saved) == 1
    empty, empty_report = preserve(tmp_path, {}, task)
    assert not empty and empty_report["selected_path_count"] == 0


@pytest.mark.parametrize("mutation", ["wrong_digest", "source_symlink", "source_directory", "malformed_digest"])
def test_invalid_sources_refuse_without_success(tmp_path, mutation):
    task, rows = entries(tmp_path)
    source = task / "input-0"
    if mutation == "wrong_digest":
        rows[str(source)]["sha256"] = "0" * 64
    elif mutation == "malformed_digest":
        rows[str(source)]["sha256"] = "../target"
    else:
        source.unlink()
        if mutation == "source_symlink":
            source.symlink_to(tmp_path / "elsewhere")
        else:
            source.mkdir()
    with pytest.raises((TalkCutError, OSError)):
        preserve(tmp_path, rows, task)


@pytest.mark.parametrize("target_kind", ["symlink", "dangling_symlink", "hardlink_source", "directory", "corrupt"])
def test_existing_target_must_be_separate_unchanged_regular_bytes(tmp_path, target_kind):
    task, rows = entries(tmp_path)
    source = task / "input-0"
    archive = tmp_path / "archive"
    archive.mkdir()
    target = archive / rows[str(source)]["sha256"]
    if target_kind == "symlink":
        target.symlink_to(source)
    elif target_kind == "dangling_symlink":
        target.symlink_to(tmp_path / "absent")
    elif target_kind == "hardlink_source":
        os.link(source, target)
    elif target_kind == "directory":
        target.mkdir()
    else:
        target.write_bytes(b"corrupt retained original")
    before = target.lstat()
    with pytest.raises((TalkCutError, OSError)):
        preserve(tmp_path, rows, task)
    assert target.lstat() == before
    assert source.read_bytes() == b"first source"


@pytest.mark.parametrize("mutation", ["same_bytes_replace", "append", "truncate", "changed_bytes", "symlink"])
def test_source_change_during_copy_is_refused(tmp_path, monkeypatch, mutation):
    task, rows = entries(tmp_path, (b"abcdefghijkl",))
    source = task / "input-0"
    read = os.read
    done = False
    monkeypatch.setattr(privacy, "PRIVATE_ARCHIVE_CHUNK_BYTES", 4)

    def mutate(fd, size):
        nonlocal done
        block = read(fd, size)
        if not done:
            done = True
            if mutation == "same_bytes_replace":
                source.rename(task / "original")
                source.write_bytes(b"abcdefghijkl")
            elif mutation == "append":
                with source.open("ab") as output:
                    output.write(b"extra")
            elif mutation == "truncate":
                source.write_bytes(b"abcd")
            elif mutation == "changed_bytes":
                source.write_bytes(b"ABCDEFGHIJKL")
            else:
                source.rename(task / "original")
                source.symlink_to(task / "original")
        return block

    monkeypatch.setattr(privacy.os, "read", mutate)
    with pytest.raises((TalkCutError, OSError)):
        preserve(tmp_path, rows, task)
    assert list((tmp_path / "archive").glob(".partial-*"))
    assert not (tmp_path / "archive" / rows[str(source)]["sha256"]).exists()


@pytest.mark.parametrize("fault", ["enospc", "cancel", "zero_write"])
def test_partial_failures_retained_and_retry_does_not_promote_them(tmp_path, monkeypatch, fault):
    task, rows = entries(tmp_path, (b"abcdefghijkl",))
    write = os.write
    calls = 0
    monkeypatch.setattr(privacy, "PRIVATE_ARCHIVE_CHUNK_BYTES", 4)

    def fail(fd, body):
        nonlocal calls
        calls += 1
        if calls > 1:
            if fault == "enospc":
                raise OSError(errno.ENOSPC, "authored disk-full control")
            if fault == "cancel":
                raise KeyboardInterrupt
            return 0
        return write(fd, body)

    monkeypatch.setattr(privacy.os, "write", fail)
    with pytest.raises((TalkCutError, OSError, KeyboardInterrupt)):
        preserve(tmp_path, rows, task)
    partials = {path: path.read_bytes() for path in (tmp_path / "archive").glob(".partial-*")}
    assert len(partials) == 1 and next(iter(partials.values())) == b"abcd"
    assert not (tmp_path / "archive" / next(iter(rows.values()))["sha256"]).exists()
    monkeypatch.setattr(privacy.os, "write", write)
    saved, report = preserve(tmp_path, rows, task)
    assert len(saved) == 1 and report["observations"][0]["created"]
    assert all(path.read_bytes() == body for path, body in partials.items())


def test_short_writes_complete_all_bytes(tmp_path, monkeypatch):
    task, rows = entries(tmp_path, (b"abcdefghijkl",))
    write = os.write
    monkeypatch.setattr(privacy.os, "write", lambda fd, block: write(fd, block[:2]))
    saved, _ = preserve(tmp_path, rows, task)
    assert Path(next(iter(saved.values()))["path"]).read_bytes() == b"abcdefghijkl"


@pytest.mark.parametrize("target", ["source", "archive"])
def test_ancestor_replacement_during_copy_refuses(tmp_path, monkeypatch, target):
    task, rows = entries(tmp_path)
    read = os.read
    done = False

    def replace(fd, size):
        nonlocal done
        block = read(fd, size)
        if not done:
            done = True
            selected = task if target == "source" else tmp_path / "archive"
            selected.rename(tmp_path / "retained-original-directory")
            selected.mkdir()
            if target == "source":
                (selected / "input-0").write_bytes(b"first source")
        return block

    monkeypatch.setattr(privacy.os, "read", replace)
    with pytest.raises((TalkCutError, OSError)):
        preserve(tmp_path, rows, task)


@pytest.mark.parametrize("prior_target", [False, True])
def test_later_copy_cannot_invalidate_prior_success(tmp_path, monkeypatch, prior_target):
    task, rows = entries(tmp_path, (b"first source", b"second source"))
    stream = privacy._private_archive_stream
    second_digest = rows[str(task / "input-1")]["sha256"]
    done = False

    def mutate(fd, size, output_fd=None):
        nonlocal done
        digest = stream(fd, size, output_fd)
        if not done and digest == second_digest and output_fd is not None:
            done = True
            selected = (tmp_path / "archive" / rows[str(task / "input-0")]["sha256"]
                        if prior_target else task / "input-0")
            selected.rename(tmp_path / "retained-prior")
            selected.write_bytes(b"first source")
        return digest

    monkeypatch.setattr(privacy, "_private_archive_stream", mutate)
    with pytest.raises(TalkCutError, match="identity changed|changed before completion"):
        preserve(tmp_path, rows, task)
    assert (tmp_path / "retained-prior").read_bytes() == b"first source"


def test_archive_inside_project_is_refused(tmp_path):
    task, rows = entries(tmp_path)
    with pytest.raises(TalkCutError, match="outside"):
        privacy._preserve_private_inputs(rows, task, task / "archive")


@pytest.mark.parametrize("alias_role", ["source", "archive"])
def test_initial_ancestor_aliases_do_not_create_archive_authority(tmp_path, alias_role):
    task, rows = entries(tmp_path)
    alias = tmp_path / "alias"
    if alias_role == "source":
        alias.symlink_to(task, target_is_directory=True)
        row = dict(next(iter(rows.values())))
        row["path"] = str(alias / "input-0")
        rows = {row["path"]: row}
        archive = tmp_path / "archive"
    else:
        actual = tmp_path / "actual-archive-parent"
        actual.mkdir()
        alias.symlink_to(actual, target_is_directory=True)
        archive = alias / "archive"
    with pytest.raises(TalkCutError, match="canonical"):
        privacy._preserve_private_inputs(rows, task, archive)


@pytest.mark.parametrize("fault", ["enospc", "cancel"])
def test_later_write_failure_keeps_all_prior_success_bytes(tmp_path, monkeypatch, fault):
    task, rows = entries(tmp_path, (b"prior success", b"new source"))
    first = {str(task / "input-0"): rows[str(task / "input-0")]}
    saved, _ = preserve(tmp_path, first, task)
    target = Path(next(iter(saved.values()))["path"])
    identity = privacy._source_file_identity(target.lstat())

    def fail(*_args):
        if fault == "enospc":
            raise OSError(errno.ENOSPC, "authored later write failure")
        raise KeyboardInterrupt

    monkeypatch.setattr(privacy.os, "write", fail)
    with pytest.raises((OSError, KeyboardInterrupt)):
        preserve(tmp_path, rows, task)
    assert target.read_bytes() == b"prior success"
    assert privacy._source_file_identity(target.lstat()) == identity
    assert list((tmp_path / "archive").glob(".partial-*"))


def test_build_snapshot_schema_and_every_entry_remain_unchanged(tmp_path, monkeypatch):
    from test_privacy_replay import ROOT, project

    task, sources = project(tmp_path)
    before = privacy.build_private_inventory(task, sources, ROOT)
    reports = []
    implementation = privacy._preserve_private_inputs

    def capture(*args, **kwargs):
        saved, report = implementation(*args, **kwargs)
        reports.append(report)
        return saved, report

    monkeypatch.setattr(privacy, "_preserve_private_inputs", capture)
    after = privacy.build_private_inventory(task, sources, ROOT, archive_dir=tmp_path / "archive")
    assert set(before) == set(after)
    assert {key: value for key, value in before.items() if key != "preserved_private_inputs"} == {
        key: value for key, value in after.items() if key != "preserved_private_inputs"}
    eligible = {row["path"] for row in after["entries"]
                if row["entry_type"] == "file" and row["classification"] in {"review", "transcript"}}
    assert set(after["preserved_private_inputs"]) == eligible
    assert reports[0]["selected_path_count"] == len(eligible)
    assert "private_byte_preservation" not in after
