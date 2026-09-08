"""Independent generated selected-ref context, read refusal and bound controls."""

import gzip
import hashlib

import pytest
from test_privacy_git_structural import found, git, repository

from talkcut import privacy_checks as privacy
from talkcut.project import TalkCutError


@pytest.mark.parametrize("algorithm", ["sha1", "sha256"])
@pytest.mark.parametrize("container", ["blob", "tag", "gzip"])
def test_same_commit_bytes_in_selected_ordinary_payload_stay_protected(tmp_path, algorithm, container):
    root, _, parent, child = repository(tmp_path, algorithm)
    data = gzip.compress(child.data, mtime=0) if container == "gzip" else child.data
    blob = git(root, "hash-object", "-w", "--stdin", data=data).strip().decode()
    selected = blob
    if container == "tag":
        raw = f"object {blob}\ntype blob\ntag ordinary\ntagger Fixture <f@example.invalid> 1 +0000\n\nPublic tag\n".encode()
        selected = git(root, "hash-object", "-t", "tag", "-w", "--stdin", data=raw).strip().decode()
    git(root, "update-ref", "refs/fixture/ordinary", selected)
    scan = privacy.Scan({}, [parent.oid])
    result = privacy._git_inventory(root, child.oid, scan, [])
    assert found(scan, parent.oid) and not scan.unknown
    assert len(scan.git_structural_metadata) == 1
    assert any(row["oid"] == blob for row in result["selected_ref_objects"])
    digest = hashlib.sha256(child.data).hexdigest()
    assert sum(row["sha256"] == digest for row in scan.units) == 1


@pytest.mark.parametrize("algorithm", ["sha1", "sha256"])
def test_unreadable_selected_blob_refuses_at_actual_object_read(tmp_path, monkeypatch, algorithm):
    root, _, _, child = repository(tmp_path, algorithm)
    blob = git(root, "hash-object", "-w", "--stdin", data=b"Selected generated object\n").strip().decode()
    git(root, "update-ref", "refs/fixture/unreadable", blob)
    command = privacy._command
    fired = []

    def missing(argv, cwd, traces, **kwargs):
        if argv[-3:] == ["cat-file", "-t", blob]:
            fired.append(True)
            (root / ".git" / "objects" / blob[:2] / blob[2:]).unlink()
        return command(argv, cwd, traces, **kwargs)

    monkeypatch.setattr(privacy, "_command", missing)
    with pytest.raises(TalkCutError):
        privacy._git_inventory(root, child.oid, privacy.Scan({}, []), [])
    assert fired == [True]


@pytest.mark.parametrize("algorithm", ["sha1", "sha256"])
def test_selected_blob_bound_refuses_before_payload_read(tmp_path, monkeypatch, algorithm):
    root, _, _, child = repository(tmp_path, algorithm)
    blob = git(root, "hash-object", "-w", "--stdin", data=b"x" * 4097).strip().decode()
    git(root, "update-ref", "refs/fixture/oversized", blob)
    command = privacy._command
    payload_reads = []

    def bounded(argv, cwd, traces, **kwargs):
        if argv[-3:] == ["cat-file", "blob", blob]:
            payload_reads.append(True)
        return command(argv, cwd, traces, **kwargs)

    monkeypatch.setattr(privacy, "MAX_UNIT_BYTES", 4096)
    monkeypatch.setattr(privacy, "_command", bounded)
    with pytest.raises(TalkCutError, match="byte bound"):
        privacy._git_inventory(root, child.oid, privacy.Scan({}, []), [])
    assert payload_reads == []
