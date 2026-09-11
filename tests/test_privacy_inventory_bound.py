"""The finite file cap preserves all entries and fails rather than truncating."""
import pytest
from test_privacy_replay import ROOT, privacy, project

from talkcut.project import TalkCutError


def test_actual_finite_inventory_boundary_never_truncates(tmp_path,monkeypatch):
    directory,sources=project(tmp_path)
    for i in range(30):
        (directory/f'preserved-frame-{i}.txt').write_text(f'Public synthetic file count fixture {i}')
    measured=privacy.build_private_inventory(directory,sources,ROOT)
    count=measured['entry_count']
    assert count>=30 and not measured['unresolved']
    monkeypatch.setattr(privacy,'MAX_TASK_FILES',count)
    at_bound=privacy.build_private_inventory(directory,sources,ROOT)
    assert at_bound['entries']==measured['entries']
    (directory/'one-additional-preserved-artifact.txt').write_text('This file must never silently disappear')
    with pytest.raises(TalkCutError,match='file-count bound'):
        privacy.build_private_inventory(directory,sources,ROOT)
