"""Real synthetic files and exact public source fixtures; no evaluator execution."""
from __future__ import annotations

import ast
import hashlib
import json
from pathlib import Path

from test_privacy_checks import commit, git
from test_privacy_replay import project

from talkcut import privacy_checks as privacy
from talkcut.project import artifact_ref, atomic_json

ROLES = {
    'src/talkcut/__main__.py': 'acceptance-cli.py.txt',
    'src/talkcut/project.py': 'acceptance-project.py.txt',
    'src/talkcut/contracts.py': 'acceptance-contracts.py.txt',
    'src/talkcut/__init__.py': 'acceptance-package.py.txt',
    'pyproject.toml': 'acceptance-pyproject.toml.txt',
}
PHRASE = 'Execution contract and identified tools/reviewers'
SELECTOR = ['criteria', 0, 'description']


def write(path, value):
    path = Path(path);path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(value, bytes):
        path.write_bytes(value)
    else:
        atomic_json(path, value)
    return artifact_ref(path)


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode()


def fixture(tmp_path, mode='checkpoint'):
    root = tmp_path / 'repository';root.mkdir()
    git(root, 'init', '--initial-branch=main')
    roles = {**ROLES, 'src/talkcut/acceptance.py': 'acceptance-evaluator-' + ('a' if mode == 'checkpoint' else 'b') + '.py.txt'}
    sources = {}
    for role, name in roles.items():
        sources[role] = write(root / role, (Path(__file__).parent / 'fixtures' / name).read_bytes())
    commit(root)
    directory, registered = project(root)
    folder = directory / 'evidence' / 'acceptance-origin';folder.mkdir(parents=True)
    tree = ast.parse(Path(sources['src/talkcut/contracts.py']['path']).read_bytes())
    table = ast.literal_eval(next(node.value for node in tree.body if isinstance(node, ast.Assign)
                                 and any(isinstance(t, ast.Name) and t.id == 'CRITERIA' for t in node.targets)))
    criteria = [{'id': key, 'description': value, 'status': 'UNVERIFIED', 'checks': [], 'evidence_refs': []}
                for key, value in table.items()]
    checks = {
        'AC01': [('frozen_contract', 'UNVERIFIED', 'Invalid or incomplete evidence: synthetic missing contract', None),
                 ('executed_reviewer_capability', 'UNVERIFIED', 'No valid audio/video reviewer capability demonstration', None)],
        'AC02': [('registered_originals', 'UNVERIFIED', 'Invalid or incomplete evidence: synthetic source metadata', None),
                 ('full_decode_pts', 'UNVERIFIED', 'Invalid or incomplete evidence: synthetic source metadata', None)],
        'AC03': [('workflow_e2e', 'UNVERIFIED', 'Required hashed artifact reference is missing', None),
                 ('baseline', 'UNVERIFIED', 'Required hashed artifact reference is missing', None)],
        'AC04': [('source_conservation_and_final_mapping', 'FAIL', 'Preview/sample/test-only output cannot be final master', None),
                 ('sync', 'UNVERIFIED', 'Required hashed artifact reference is missing', None),
                 ('boundaries', 'UNVERIFIED', 'Required hashed artifact reference is missing', None)],
        'AC05': [('geometry_audio', 'UNVERIFIED', 'Required hashed artifact reference is missing', None)],
        'AC06': [('real_source_editorial_analysis', 'UNVERIFIED', 'Required hashed artifact reference is missing', None),
                 ('editorial_fixture', 'UNVERIFIED', 'Required hashed artifact reference is missing', None)],
        'AC07': [('recovery', 'UNVERIFIED', 'Required hashed artifact reference is missing', None)],
        'AC08': [('multimodal_union_coverage', 'UNVERIFIED', 'Actual source/output domains unavailable', None)],
        'AC09': [('output_technical', 'UNVERIFIED', 'Required hashed artifact reference is missing', None),
                 ('open_P0_P1', 'PASS', 'Unresolved P0/P1 must be zero', {'count': 0})],
        'AC10': [('failure_injection', 'UNVERIFIED', 'Required hashed artifact reference is missing', None),
                 ('evaluator_negative', 'UNVERIFIED', 'Required hashed artifact reference is missing', None)],
        'AC11': [('reproducibility', 'UNVERIFIED', 'Required hashed artifact reference is missing', None)],
        'AC12': [('independent_audit_and_handoff', 'UNVERIFIED', 'Required hashed artifact reference is missing', None)],
        'AC13': [('verified_public_release', 'UNVERIFIED', 'Required hashed artifact reference is missing', None)],
    }
    for row in criteria:
        row['checks'] = [dict(zip(('check_id', 'status', 'reason', 'measurements'), values, strict=True)) for values in checks[row['id']]]
        row['status'] = 'FAIL' if row['id'] == 'AC04' else 'UNVERIFIED'
    report = {'schema_version': 'goal-acceptance/v1', 'status': 'FAIL', 'release_ready': False, 'goal_achieved': False,
              'media_state': 'BLOCKED', 'goal_contract_hash': None, 'evaluator_version': 'goal-acceptance/v1',
              'source_hashes': {}, 'output_hash': None, 'edit_disposition': None, 'criteria': criteria,
              'coverage': {}, 'uncovered_intervals': [], 'invalid_evidence': [], 'open_findings': [],
              'independent_audit_ref': None, 'code_release_evidence': None, 'owner_acceptance': 'pending',
              'provenance_limitations': 'Hashes prove byte identity, not semantic truth or provider authenticity; a separate audit of actual media, provider execution records and evaluator is mandatory.'}
    parts = {'root': root, 'directory': directory, 'registered': registered, 'folder': folder, 'sources': sources,
             'report': report, 'mode': mode, 'revision': git(root, 'rev-parse', 'HEAD').strip(),
             'saved_path': tmp_path / 'preserved-saved-report.json'}
    refresh(parts)
    write(directory / 'checkpoint.local.json', {'report': parts['stdout']})
    return parts


def refresh(parts, *, rebuild_source_map=True):
    root, directory, folder = parts['root'], parts['directory'], parts['folder']
    if rebuild_source_map:
        parts['sources'] = {name: artifact_ref(ref['path']) for name, ref in parts['sources'].items()}
    files = {name: ref['sha256'] for name, ref in parts['sources'].items()}
    identity = {'files': files, 'code_tree_hash': hashlib.sha256(encoded(files)).hexdigest(), 'code_revision': parts['revision']}
    report = parts['report'];report.update(identity)
    stdout = write(folder / 'stdout.json', (json.dumps(report, indent=2, ensure_ascii=False, allow_nan=False) + '\n').encode())
    stderr = write(folder / 'stderr.txt', b'')
    tail = [str(directory), '--render', 'a' * 64, '--contract', str(directory / 'frozen-contract.json'), '--json']
    prefix = [str(root / '.venv/bin/python3'), '-m', 'talkcut', 'acceptance', 'evaluate'] if parts['mode'] == 'python' else ['uv', 'run', '--locked', 'talkcut', 'acceptance', 'evaluate']
    command = {'argv': prefix + tail, 'cwd': str(root), 'exit_code': 1, 'started_at': '2000-01-01T00:00:00Z',
               'finished_at': '2000-01-01T00:00:01Z', 'stdout': stdout, 'stderr': stderr}
    copies = []
    if parts['mode'] == 'checkpoint':
        snapshot = write(parts['saved_path'], encoded(report) + b'\n')
        original = {'path': str(directory / 'reports/acceptance-latest.local.json'), 'sha256': snapshot['sha256']}
        copies = [{'original': original, 'snapshot': snapshot}]
        previous = write(folder / 'previous.json', {'schema_version': 'private-review/v1', 'scope': 'Synthetic previous file observation.'})
        command.update(schema_version='actual-cli-checkpoint/v1', code_before=identity, code_after=identity,
                       current_report=original, previous_report=previous, source_project_modified=False)
    else:
        command.update(schema_version='verification-command/v1', error=None, interrupted=False, name='synthetic-acceptance',
                       status='FAIL', timed_out=False, timeout_seconds=2, wall_seconds=1)
    if 'command_mutator' in parts:
        parts['command_mutator'](command)
    command_ref = write(folder / 'command.json', command)
    selected = {'schema_version': 'review-machine-field-authority/v1', 'family': 'acceptance_cli_report',
                'command': command_ref, 'stdout': stdout, 'sources': parts['sources'], 'saved_copies': copies}
    if 'authority_mutator' in parts:
        parts['authority_mutator'](selected)
    authority = write(folder / 'authority.json', selected)
    parts.update(stdout=stdout, command=command_ref, authority=authority, selected=selected)
    if (directory / 'checkpoint.local.json').exists():
        write(directory / 'checkpoint.local.json', {'report': stdout})


def locator(parts, selector=None, saved=False):
    return {'schema_version': 'review-text-origin/v1', 'kind': 'machine_inventory_field',
            'parent': artifact_ref(parts['saved_path']) if saved else parts['stdout'],
            'authority': parts['authority'], 'selector': SELECTOR.copy() if selector is None else selector}


def observe(parts, selector=None, saved=False):
    return privacy._review_text_origin_inventory([locator(parts, selector, saved)], parts['directory'], parts['root'],
                                                set(parts['registered'].values()), [parts['authority']])


def inventory(parts, locators=None):
    selected = [locator(parts)] if locators is None else locators
    return privacy._known_private_inventory(parts['directory'], parts['registered'], parts['root'],
                                            review_text_origins=selected, review_text_origin_authorities=[parts['authority']] if selected else [])
