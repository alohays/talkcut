"""Synthetic exclusive-creation boundary; the same test covers both APIs."""
import os

import pytest

from talkcut import privacy_checks as privacy
from talkcut.project import TalkCutError, artifact_ref


def test_exclusive_creation_uses_the_original_directory_descriptor(tmp_path, monkeypatch):
    task = tmp_path / "task"
    task.mkdir()
    source = task / "opaque.bin"
    payload = b"SYNTHETIC_PRIVATE_BYTES_OUTSIDE_AUTHORIZED_ARCHIVE"
    source.write_bytes(payload)
    rows = {str(source): {**artifact_ref(source), "entry_type": "file", "classification": "review"}}
    archive = tmp_path / "archive"
    original = tmp_path / "retained-original-archive"
    redirected = tmp_path / "outside-authorized-archive"
    redirected.mkdir()
    open_file = os.open
    fired = False

    def redirect_at_exclusive_creation(path, flags, mode=0o777, *, dir_fd=None):
        nonlocal fired
        if flags & os.O_CREAT and flags & os.O_EXCL:
            assert not fired
            fired = True
            archive.rename(original)
            archive.symlink_to(redirected, target_is_directory=True)
        return open_file(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(privacy.os, "open", redirect_at_exclusive_creation)
    with pytest.raises(TalkCutError):
        privacy._preserve_private_inputs(rows, task, archive)
    assert fired and source.read_bytes() == payload
    assert not any(payload in path.read_bytes() for path in redirected.iterdir() if path.is_file())
