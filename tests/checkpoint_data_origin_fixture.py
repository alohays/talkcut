"""Portable checkpoint/report data; no historical producer is run."""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

from acceptance_origin_fixture import fixture as cli_fixture
from acceptance_origin_fixture import write
from report_data_origin_fixture import fixture as data_fixture

from talkcut import privacy_checks as privacy
from talkcut.project import artifact_ref

PHRASE = 'Execution contract and identified tools/reviewers'
MODES = ('evidence_summary', 'command_summary', 'preserved_report_summary')
SUMMARY_FIELDS = ('status', 'release_ready', 'goal_achieved', 'criteria', 'owner_acceptance')
COMMAND_FIELDS = ('code_revision', 'code_tree_hash', 'criteria', 'status', 'release_ready', 'goal_achieved',
                  'media_state', 'owner_acceptance', 'output_hash', 'open_findings', 'uncovered_intervals')


def get(value, selector):
    for part in selector:
        value = value[part]
    return value


def fixture(tmp_path, mode='evidence_summary', archived=True, native=False):
    upstream = cli_fixture(tmp_path) if mode == 'command_summary' else data_fixture(
        tmp_path, serialization='canonical_json_lf' if mode == 'preserved_report_summary' else 'pretty_json_lf')
    parts = {'upstream': upstream, 'root': upstream['root'], 'directory': upstream['directory'],
             'registered': upstream['registered'], 'folder': upstream['folder'], 'temporary': tmp_path,
             'mode': mode, 'archived': archived, 'native': native}
    refresh(parts)
    return parts


def refresh(parts):
    up = parts['upstream'];mode = parts['mode'];folder = parts['folder']
    source = up['stdout'] if mode == 'command_summary' else up['parents'][0]['original']
    report = up['report'] if mode == 'command_summary' else up['reports'][0]
    upstream_authority = up['authority'] if mode == 'command_summary' else up['data_authority_ref']
    source_with_size = {**source, 'bytes': Path(source['path']).stat().st_size}
    if mode == 'evidence_summary':
        parent = {'schema_version': 'goal-stage-checkpoint/v1',
                  'acceptance': {key: copy.deepcopy(report[key]) for key in SUMMARY_FIELDS},
                  'evidence': [None] * 5 + [source_with_size]}
        prefix = ['acceptance']
        edge = {'kind': 'original_checkpoint_explicit_evidence', 'pointer': '/evidence/5'}
    elif mode == 'command_summary':
        command = {**up['command'], 'bytes': Path(up['command']['path']).stat().st_size}
        parent = {'schema_version': 'talkcut-append-only-checkpoint/v1',
                  'actual_latest_acceptance': {key: copy.deepcopy(report[key]) for key in COMMAND_FIELDS},
                  'evidence': {'actual_acceptance_command': command, 'actual_acceptance_stdout': source_with_size}}
        prefix = ['actual_latest_acceptance']
        edge = {'kind': 'original_checkpoint_command_stdout', 'command': command}
    else:
        historical_path = parts['directory'] / 'reports/overwritten-latest.json'
        write(historical_path, {'schema_version': 'private-review/v1', 'note': 'Different current report bytes.'})
        historical = {**source_with_size, 'path': str(historical_path)}
        parent = {'schema_version': 'goal-checkpoint/v1' if parts['native'] else 'goal-stage-checkpoint/v1',
                  'criteria': copy.deepcopy(report['criteria']), 'acceptance_status': report['status'],
                  **{key: copy.deepcopy(report[key]) for key in ('release_ready', 'goal_achieved', 'owner_acceptance')},
                  'actual_latest_acceptance': historical}
        prefix = []
        edge = {'kind': 'original_explicit_report_ref_with_exact_preserved_bytes',
                'original_reference': historical, 'preserved_reference': source}
    parent['private_notes'] = parts.get('private_notes', 'Unselected synthetic checkpoint prose stays private.')
    if 'parent_mutator' in parts:
        parts['parent_mutator'](parent)
    raw = (json.dumps(parent, ensure_ascii=False, allow_nan=False, indent=2) + '\n').encode()
    original = write(parts.get('original_path', folder / 'checkpoint-original.json'), raw)
    snapshot = write(parts['temporary'] / 'checkpoint-preserved.json', raw) if parts['archived'] else original
    selectors = [['criteria', i, 'description'] for i in range(13) if i not in (2, 8)]
    selectors += [['criteria', i, 'checks', j, 'reason'] for i, j in
                  ((0, 1), (2, 0), (3, 0), (3, 1), (3, 2), (4, 0), (5, 0), (5, 1), (6, 0),
                   (7, 0), (8, 0), (9, 0), (9, 1), (10, 0), (11, 0), (12, 0))]
    rows = []
    for i, selector in enumerate(selectors):
        value = get(report, selector)
        rows.append({'original_origin_index': i, 'pointer': '/' + '/'.join(map(str, prefix + selector)),
                     'source_pointer': '/' + '/'.join(map(str, selector)), 'criterion_id': report['criteria'][selector[1]]['id'],
                     'value': value, 'phrase_sha256': hashlib.sha256(value.encode()).hexdigest(),
                     'status': 'EXACT_ORIGINAL_REPORT_COPY_FIELD'})
    case = {'parent': {'kind': 'review', **original}, 'source_report': source_with_size, 'copy_edges': [edge],
            'source_code_revision': report['code_revision'], 'rows': rows, 'original_goal_status': report['status'],
            'original_goal_achieved': report['goal_achieved'], 'original_owner_acceptance': report['owner_acceptance']}
    retained = {'schema': 'root-original-checkpoint-copy-fields/v1', 'cases': [case],
                'scope': 'Synthetic separately retained relation; no historical checkpoint writer claim'}
    if 'retained_mutator' in parts:
        parts['retained_mutator'](retained)
    retained_ref = write(folder / 'retained-checkpoint-cases.json', retained)
    authority = {'schema_version': 'review-machine-field-authority/v1', 'family': 'acceptance_checkpoint_data',
                 'retained_copies': retained_ref, 'upstream_authority': upstream_authority,
                 'parents': [{'original': original, 'snapshot': snapshot, 'retained_case': 0,
                              'upstream_parent': source, 'projection': mode}]}
    if 'checkpoint_authority_mutator' in parts:
        parts['checkpoint_authority_mutator'](authority)
    authority_ref = write(folder / 'checkpoint-authority.json', authority)
    parts.update(parent=parent, original=original, snapshot=snapshot, retained=retained, case=case, authority=authority,
                 authority_ref=authority_ref, upstream_authority=upstream_authority, prefix=prefix, source=source)
    write(parts['directory'] / 'checkpoint.local.json', {'original_checkpoint': original, 'archive': snapshot,
                                                      'original_report': source})


def locator(parts, selector=None, snapshot=False):
    return {'schema_version': 'review-text-origin/v1', 'kind': 'machine_inventory_field',
            'parent': parts['snapshot'] if snapshot else parts['original'],
            'selector': parts['prefix'] + ['criteria', 0, 'description'] if selector is None else selector,
            'authority': parts['authority_ref']}


def observe(parts, selected=None, registered=None, approved=None):
    return privacy._review_text_origin_inventory([locator(parts)] if selected is None else selected,
        parts['directory'], parts['root'], set(parts['registered'].values()) if registered is None else registered,
        [parts['authority_ref'], parts['upstream_authority']] if approved is None else approved)


def inventory(parts, selected=None):
    return privacy._known_private_inventory(parts['directory'], parts['registered'], parts['root'],
        review_text_origins=[locator(parts)] if selected is None else selected,
        review_text_origin_authorities=[parts['authority_ref'], parts['upstream_authority']])


def rebind_authority(parts):
    parts['authority_ref'] = write(parts['folder'] / 'checkpoint-authority.json', parts['authority'])


def current_ref(path):
    return artifact_ref(path)
