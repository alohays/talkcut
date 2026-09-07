"""Explicit synthetic provider gate for local filesystem race controls only."""
import copy
import hashlib
import json
import os
from pathlib import Path

import pytest

from talkcut import native_provenance as native
from talkcut import privacy_checks as privacy
from talkcut.project import TalkCutError, artifact_ref, atomic_json


def local_case(tmp_path, monkeypatch):
    target = tmp_path / 'tool-bytes'
    target.write_bytes(b'local synthetic tool bytes')
    link = tmp_path / 'arbitrary-local-alias'
    link.symlink_to(target.name)
    snapshot = native.alias_snapshot(str(link))
    hop = snapshot['hops'][0]
    typed = {'path': str(link), 'sha256': hop['link_bytes_sha256'], 'entry_type': 'symlink', 'target': hop['link_text'], 'classification': 'UNCLASSIFIED'}
    rows = [typed, {'path': str(target), 'sha256': artifact_ref(target)['sha256'], 'entry_type': 'file', 'classification': 'UNCLASSIFIED'}]
    origin = {'schema_version': 'private-task-inventory/v1', 'project': str(tmp_path), 'scope': 'Synthetic unit fixture only', 'dependencies': {}, 'entries': rows, 'entry_count': 2, 'mandatory_private_count': 0, 'unresolved': [], 'known_graph': {}, 'classification_status': 'UNVERIFIED', 'preserved_private_inputs': [], 'limits': {}, 'excluded_directories': []}
    parent = tmp_path / 'origin.json'
    atomic_json(parent, origin)
    authority = {'actual_target': artifact_ref(target), 'link_path': str(link), 'link_target': hop['link_text'], 'link_bytes_sha256': hop['link_bytes_sha256']}
    # Explicit provider unit gate. Real replay verification is covered separately.
    monkeypatch.setattr(privacy, '_verified_synthetic_replay', lambda *_: {'bundle': artifact_ref(parent), 'external_tool_links': [copy.deepcopy(authority)]})
    request = {'parent': artifact_ref(parent), 'pointer': '/entries/0', 'typed_origin': {'parent': artifact_ref(parent), 'pointer': '/entries/0'}, 'tool_alias_index': 0}
    return target, link, parent, request, origin


@pytest.mark.parametrize('mutation', ['target_bytes', 'target_inode', 'link_inode', 'link_literal', 'retarget_same_bytes', 'cycle', 'escape', 'parent_bytes'])
def test_during_observation_changes_reject(tmp_path, monkeypatch, mutation):
    target, link, parent, request, _ = local_case(tmp_path, monkeypatch)
    actual = native.alias_snapshot
    calls = 0

    def changing(raw):
        nonlocal calls
        before = actual(raw)
        calls += 1
        if calls == 1:
            if mutation == 'target_bytes':
                target.write_bytes(b'changed bytes')
            elif mutation == 'target_inode':
                other = tmp_path / 'replacement'
                other.write_bytes(target.read_bytes())
                os.replace(other, target)
            elif mutation in {'link_inode', 'link_literal'}:
                link.unlink()
                link.symlink_to(target.name if mutation == 'link_inode' else './' + target.name)
            elif mutation == 'retarget_same_bytes':
                other = tmp_path / 'other'
                other.write_bytes(target.read_bytes())
                link.unlink()
                link.symlink_to(other.name)
            elif mutation in {'cycle', 'escape'}:
                link.unlink()
                link.symlink_to(link.name if mutation == 'cycle' else '../missing-outside-tool')
            else:
                parent.write_text(parent.read_text() + '\n')
        return before

    monkeypatch.setattr(native, 'alias_snapshot', changing)
    with pytest.raises((TalkCutError, OSError)):
        privacy._inventory_alias_row_inventory([request], tmp_path, Path.cwd(), set(), artifact_ref(parent))


def test_literal_changed_after_replay_before_first_snapshot_rejects(tmp_path, monkeypatch):
    target, link, parent, request, origin = local_case(tmp_path, monkeypatch)
    link.unlink()
    text = './' + target.name
    link.symlink_to(text)
    origin['entries'][0].update(target=text, sha256=hashlib.sha256(os.fsencode(text)).hexdigest())
    atomic_json(parent, origin)
    request['parent'] = request['typed_origin']['parent'] = artifact_ref(parent)
    with pytest.raises(TalkCutError, match='literal differs from verified replay'):
        privacy._inventory_alias_row_inventory([request], tmp_path, Path.cwd(), set(), artifact_ref(parent))


def test_local_arbitrary_alias_positive_preserves_truth(tmp_path, monkeypatch):
    _, _, parent, request, _ = local_case(tmp_path, monkeypatch)
    rows = privacy._inventory_alias_row_inventory([request], tmp_path, Path.cwd(), set(), artifact_ref(parent))
    assert len(rows) == 1
    assert rows[0]['execution_status'] == rows[0]['claim_status'] == 'UNVERIFIED'
    assert rows[0]['history_supported'] is False
    assert json.loads(parent.read_bytes())['entry_count'] == 2
