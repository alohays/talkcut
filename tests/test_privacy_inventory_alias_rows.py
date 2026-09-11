"""Historical inventory rows need exact typed origins and current tool authority."""
import copy
import json
import os
import shutil
from pathlib import Path

import pytest

from talkcut import privacy_checks as privacy
from talkcut.project import TalkCutError, artifact_ref, atomic_json, init_project

ROOT = Path.cwd()


@pytest.fixture(scope='module')
def replay(tmp_path_factory):
    # Exercise real tools through controlled aliases on every supported host,
    # including distributions whose system executable paths are regular files.
    tool_bin = tmp_path_factory.mktemp('tool-aliases')
    for name in ('ffmpeg', 'ffprobe'):
        executable = shutil.which(name)
        assert executable is not None
        (tool_bin / name).symlink_to(Path(executable).resolve())
    with pytest.MonkeyPatch.context() as environment:
        environment.setenv('PATH', str(tool_bin) + os.pathsep + os.environ['PATH'])
        yield privacy.prepare_synthetic_failure_replay(ROOT, tmp_path_factory.mktemp('fixed-replay') / 'archive')


def case(tmp_path, replay):
    first, second = tmp_path / 'screen.bin', tmp_path / 'speaker.bin'
    first.write_bytes(b'bounded private registration screen')
    second.write_bytes(b'bounded private registration speaker')
    task = tmp_path / 'task'
    project = init_project(task, first, second)
    sources = {key: value['sha256'] for key, value in project['sources'].items()}
    tools = privacy._verified_synthetic_replay(replay, ROOT)['external_tool_links']
    atomic_json(task / 'checkpoint.local.json', {'tools': [{'path': tool['link_path'], 'sha256': tool['actual_target']['sha256']} for tool in tools]})
    origin = privacy.build_private_inventory(task, sources, ROOT)
    origin_path, copied_path = task / 'audits/origin.json', task / 'audits/copied.json'
    origin_path.parent.mkdir()
    indexes, bare_indexes, typed_rows = [], [], []
    for tool in tools:
        index = next(i for i, row in enumerate(origin['entries']) if row['path'] == tool['link_path'])
        row = origin['entries'][index]
        indexes.append(index)
        typed_rows.append(copy.deepcopy(row))
        bare_indexes.append(len(origin['known_graph']['unfollowed_refs']))
        origin['known_graph']['unfollowed_refs'].append({'path': row['path'], 'sha256': row['sha256'], 'reason': 'Historical copied observation text'})
    atomic_json(origin_path, origin)
    atomic_json(copied_path, {'copied': typed_rows})
    atomic_json(task / 'goal-handoff.local.json', {'historical_inventory': artifact_ref(origin_path), 'copied_review': artifact_ref(copied_path)})
    requests = []
    for i, entry_index in enumerate(indexes):
        authority = {'parent': artifact_ref(origin_path), 'pointer': f'/entries/{entry_index}'}
        for parent, pointer in [(origin_path, f'/entries/{entry_index}'), (origin_path, f'/known_graph/unfollowed_refs/{bare_indexes[i]}'), (copied_path, f'/copied/{i}')]:
            requests.append({'parent': artifact_ref(parent), 'pointer': pointer, 'typed_origin': copy.deepcopy(authority), 'tool_alias_index': i})
    return {'task': task, 'sources': sources, 'origin': origin, 'origin_path': origin_path, 'copied_path': copied_path,
            'requests': requests, 'indexes': indexes, 'bare_indexes': bare_indexes}


def observe(value, requests, replay):
    return privacy._inventory_alias_row_inventory(requests, value['task'], ROOT, set(value['sources'].values()), replay)


def replace_origin(value, body):
    atomic_json(value['origin_path'], body)
    for request in value['requests']:
        request['typed_origin']['parent'] = artifact_ref(value['origin_path'])
        if request['parent']['path'] == str(value['origin_path']):
            request['parent'] = artifact_ref(value['origin_path'])


def test_exact_typed_and_bare_rows_preserve_full_inventory(tmp_path, replay):
    value = case(tmp_path, replay)
    with pytest.raises(TalkCutError, match='alias target bytes changed'):
        privacy.build_private_inventory(value['task'], value['sources'], ROOT)
    before = {p: p.read_bytes() for p in (value['origin_path'], value['copied_path'])}
    observed = observe(value, value['requests'], replay)
    assert len(observed) == 6
    result = privacy.build_private_inventory(value['task'], value['sources'], ROOT,
                                            synthetic_replay=replay, inventory_alias_row_reobservations=value['requests'])
    assert result['classification_status'] == result['known_graph']['completeness'] == 'UNVERIFIED'
    assert result['excluded_directories'] == result['unresolved'] == []
    assert len(result['known_graph']['inventory_alias_row_reobservations']) == 6
    rows = {row['path']: row for row in result['entries']}
    authority = privacy._verified_synthetic_replay(replay, ROOT)
    for ref in [authority['bundle'], *authority['artifacts'], *authority['external_inputs']]:
        assert rows[ref['path']]['sha256'] == ref['sha256']
    assert len(authority['artifacts']) > 0
    for observation in observed:
        assert observation['claim_status'] == observation['execution_status'] == 'UNVERIFIED'
        assert observation['history_supported'] is False
        identity = observation['alias_identity']
        for hop in identity['hops']:
            assert rows[hop['path']]['sha256'] == hop['link_bytes_sha256']
            assert rows[hop['path']]['classification'] == 'UNCLASSIFIED'
        assert rows[identity['target']['path']]['sha256'] == identity['target']['sha256']
        assert rows[identity['target']['path']]['classification'] == 'UNCLASSIFIED'
    assert before == {p: p.read_bytes() for p in before}


@pytest.mark.parametrize('mutation', [
    'missing_origin', 'unknown_field', 'index_bool', 'index_negative', 'index_large', 'cross_tool',
    'pointer_missing', 'pointer_escape', 'pointer_leading_zero', 'origin_wrong_pointer', 'origin_wrong_parent',
    'duplicate', 'unscoped_bare', 'parent_hash', 'origin_hash', 'typed_missing_target', 'typed_extra_field',
    'typed_wrong_target', 'typed_public_classification', 'typed_wrong_digest', 'origin_public_classification',
    'origin_count', 'origin_duplicate_path', 'origin_target_digest', 'origin_link_digest', 'origin_schema',
    'origin_nested_formal', 'protected_parent', 'json_duplicate', 'bare_wrong_digest',
])
def test_explicit_row_boundary_rejects_forgery(tmp_path, replay, mutation):
    value = case(tmp_path, replay)
    requests = value['requests']
    if mutation == 'missing_origin':
        requests[0].pop('typed_origin')
    elif mutation == 'unknown_field':
        requests[0]['trust'] = True
    elif mutation in {'index_bool', 'index_negative', 'index_large', 'cross_tool'}:
        requests[0]['tool_alias_index'] = {'index_bool': True, 'index_negative': -1, 'index_large': 99, 'cross_tool': 1}[mutation]
    elif mutation.startswith('pointer_'):
        requests[0]['pointer'] = {'pointer_missing': '/absent', 'pointer_escape': '/~2', 'pointer_leading_zero': '/entries/00'}[mutation]
    elif mutation == 'origin_wrong_pointer':
        requests[0]['typed_origin']['pointer'] = '/known_graph/unfollowed_refs/0'
    elif mutation == 'origin_wrong_parent':
        requests[0]['typed_origin']['parent'] = artifact_ref(value['copied_path'])
    elif mutation == 'duplicate':
        requests.append(copy.deepcopy(requests[0]))
    elif mutation == 'unscoped_bare':
        atomic_json(value['copied_path'], {'copied': [value['origin']['known_graph']['unfollowed_refs'][value['bare_indexes'][0]]]})
        requests = [dict(requests[2], parent=artifact_ref(value['copied_path']))]
    elif mutation in {'parent_hash', 'origin_hash'}:
        target = requests[0]['parent'] if mutation == 'parent_hash' else requests[0]['typed_origin']['parent']
        target['sha256'] = '0' * 64
    elif mutation.startswith('typed_'):
        body = json.loads(value['copied_path'].read_bytes())
        row = body['copied'][0]
        if mutation == 'typed_missing_target':
            row.pop('target')
        else:
            key, replacement = {'typed_extra_field': ('approved', True), 'typed_wrong_target': ('target', 'different'),
                                'typed_public_classification': ('classification', 'PUBLIC'), 'typed_wrong_digest': ('sha256', '0' * 64)}[mutation]
            row[key] = replacement
        atomic_json(value['copied_path'], body)
        requests = [dict(requests[2], parent=artifact_ref(value['copied_path']))]
    elif mutation.startswith('origin_') or mutation == 'bare_wrong_digest':
        body = copy.deepcopy(value['origin'])
        if mutation == 'origin_public_classification':
            body['classification_status'] = 'PASS'
        elif mutation == 'origin_count':
            body['entry_count'] -= 1
        elif mutation == 'origin_duplicate_path':
            body['entries'][-1] = copy.deepcopy(body['entries'][0])
        elif mutation == 'origin_target_digest':
            link = body['entries'][value['indexes'][0]]
            target = str((Path(link['path']).parent / link['target']).resolve())
            next(row for row in body['entries'] if row['path'] == target)['sha256'] = '0' * 64
        elif mutation == 'origin_link_digest':
            body['entries'][value['indexes'][0]]['sha256'] = '0' * 64
        elif mutation == 'origin_schema':
            body['schema_version'] = 'untyped-copy/v1'
        elif mutation == 'origin_nested_formal':
            body['known_graph']['forged'] = {'schema_version': 'transcript/v1'}
        elif mutation == 'bare_wrong_digest':
            body['known_graph']['unfollowed_refs'][value['bare_indexes'][0]]['sha256'] = '0' * 64
        replace_origin(value, body)
    elif mutation == 'protected_parent':
        target = value['task'] / 'reviews/copied.json'
        target.parent.mkdir()
        target.write_bytes(value['copied_path'].read_bytes())
        requests = [dict(requests[2], parent=artifact_ref(target))]
    elif mutation == 'json_duplicate':
        original = value['origin_path'].read_text()
        value['origin_path'].write_text('{"classification_status":"UNVERIFIED",' + original[1:])
        for request in requests:
            request['typed_origin']['parent'] = artifact_ref(value['origin_path'])
            if request['parent']['path'] == str(value['origin_path']):
                request['parent'] = artifact_ref(value['origin_path'])
    with pytest.raises(TalkCutError):
        observe(value, requests, replay)


def test_bare_reason_text_never_grants_a_role(tmp_path, replay):
    value = case(tmp_path, replay)
    body = copy.deepcopy(value['origin'])
    body['known_graph']['unfollowed_refs'][value['bare_indexes'][0]]['reason'] = 'An arbitrary changed narrative has no authority.'
    replace_origin(value, body)
    assert len(observe(value, value['requests'], replay)) == 6
    body['known_graph']['unfollowed_refs'][value['bare_indexes'][0]]['reference_type'] = 'symlink_literal'
    replace_origin(value, body)
    with pytest.raises(TalkCutError):
        observe(value, value['requests'], replay)


def test_missing_replay_authority_rejects_even_exact_rows(tmp_path, replay):
    value = case(tmp_path, replay)
    with pytest.raises(TalkCutError, match='current verified tool replay'):
        observe(value, value['requests'], None)
