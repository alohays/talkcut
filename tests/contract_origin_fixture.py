"""Real synthetic files; recorded construction metadata never claims execution."""
from __future__ import annotations

import copy
import json
from pathlib import Path

from test_privacy_checks import commit, git
from test_privacy_replay import project

from talkcut import privacy_checks as privacy
from talkcut.contracts import code_identity, expected_contract
from talkcut.project import artifact_ref, atomic_json

FILES = {'contracts': ('src/talkcut/contracts.py', 'contract-writer.py.txt'),
         'project': ('src/talkcut/project.py', 'contract-serializer.py.txt'),
         'negative': ('src/talkcut/evaluator_negative.py', 'contract-negative-writer.py.txt'),
         'caller': ('tests/constructor-caller.py', 'contract-caller.py.txt')}
PHRASE = 'Execution contract and identified tools/reviewers'


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(value, bytes):
        path.write_bytes(value)
    else:
        atomic_json(path, value)
    return artifact_ref(path)


def encoded(value, pretty=False):
    if pretty:
        return (json.dumps(value, indent=2, ensure_ascii=False, allow_nan=False) + '\n').encode()
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False) + '\n').encode()


def fixture(tmp_path, recipe='canonical', embedded=False):
    root = tmp_path / 'repository'
    root.mkdir()
    git(root, 'init', '--initial-branch=main')
    snapshots = {}
    for role, (relative, name) in FILES.items():
        snapshots[role] = write(root / relative, (Path(__file__).parent / 'fixtures' / name).read_bytes())
    commit(root)
    directory, registered = project(root)
    folder = directory / 'evidence' / 'contract-construction'
    folder.mkdir(parents=True)
    base = expected_contract()  # Current trusted fixture data factory; no preserved source is imported.
    variants = [copy.deepcopy(base) for _ in range({'canonical': 1, 'native_fixture': 2, 'negative_run': 4}[recipe])]
    if recipe == 'negative_run':
        variants[1]['checks']['sync']['max_lip_residual_with_uncertainty_ms']['max'] = 800
        variants[2]['criteria'][0]['required'] = False
        variants[3]['unresolved_P0_P1'] = 1
    parts = {'root': root, 'directory': directory, 'registered': registered, 'folder': folder,
             'recipe': recipe, 'embedded': embedded, 'values': variants, 'snapshots': snapshots}
    refresh(parts)
    return parts


def refresh(parts):
    root, folder, recipe = parts['root'], parts['folder'], parts['recipe']
    roles = {'contracts'} | ({'caller'} if recipe == 'native_fixture' else {'project', 'negative'} if recipe == 'negative_run' else set())
    sources = {}
    for role in roles:
        snapshot = artifact_ref(parts['snapshots'][role]['path'])
        original = {'path': str(folder / 'test_native_audio.py'), 'sha256': snapshot['sha256']} if role == 'caller' else snapshot
        sources[role] = {'original': original, 'snapshot': snapshot}
    names = ['control', 'numeric_limit', 'required_flag', 'blocker_limit'] if recipe == 'negative_run' else list(range(len(parts['values'])))
    parents = []
    for index, (name, value) in enumerate(zip(names, parts['values'], strict=True)):
        path = folder / ('contract-' + str(name) + '.json') if recipe == 'negative_run' else folder / ('case-' + str(index)) / 'contract.json'
        ref = write(path, encoded(value, recipe != 'negative_run'))
        parents.append({'original': ref, 'snapshot': ref})
    identity = code_identity(root)
    records = None
    if recipe == 'native_fixture':
        xml = b'<testsuites><testsuite tests="2" failures="0" errors="0" skipped="0"><testcase name="test_actual_tiny_child_transport_case_and_summary_binding[False]"/><testcase name="test_actual_tiny_child_transport_case_and_summary_binding[True]"/></testsuite></testsuites>'
        junit = write(folder / 'junit.xml', xml)
        record = {'test_sources': [sources['caller']['snapshot']], 'junit': junit, 'scope': 'Synthetic recorded data relationship; not execution'}
        if not parts['embedded']:
            record['command'] = [str(root / '.venv/bin/python3'), '-I', '-B', '-m', 'pytest', '-q',
                                 sources['caller']['original']['path'], '--basetemp', str(folder / 'cases'), '--junitxml', junit['path']]
            record_ref = write(folder / 'test-record.json', record)
        handoff = {'tests': record if parts['embedded'] else record_ref, 'public_code_identity': identity}
        handoff_ref = write(folder / 'handoff.json', handoff)
        launches = []
        for pair in parents:
            ref = pair['original']
            case = Path(ref['path']).parent
            audio = write(case / 'audio.wav', b'not played; binding-only fixture')
            screen = write(case / 'source.bin', b'authored source fixture')
            launches.append(write(Path(ref['path']).parent / 'launch.json', {
                'schema_version': 'private-native-audio-launch/v1', 'purpose': 'binding test only',
                'audio': audio, 'source_artifacts': {'screen': screen}, 'contract': ref,
                'dependencies': {'source_hashes': {'screen': screen['sha256']},
                                 'contract_hash': ref['sha256'], 'code_tree_hash': identity['code_tree_hash']}}))
        if 'launch_mutator' in parts:
            for ref in launches:
                value = json.loads(Path(ref['path']).read_bytes())
                parts['launch_mutator'](value)
                ref.update(write(Path(ref['path']), value))
        records = {'handoff': handoff_ref, 'test_record': {'parent': handoff_ref if parts['embedded'] else record_ref,
                   'selector': ['tests'] if parts['embedded'] else []}, 'junit': junit,
                   'launches': launches, 'identity_record': handoff_ref}
    elif recipe == 'negative_run':
        harness = sources['negative']['original']
        request = {'schema_version': 'evaluator-negative-request/v1', 'harness': harness, 'code_identity': identity,
                   'actual_dgist_acceptance': False, 'final_ac12_audit': False}
        request_ref = write(folder / 'request.json', request)
        artifacts = [request_ref, *[pair['original'] for pair in parents]]
        pairs = []
        for index, name in enumerate(names[1:], 1):
            pair = {'name': name, 'mutation': {}}
            for input_name, process_name, parent_index in [('control_input', 'control', 0), ('mutation_input', 'attack', index)]:
                case = folder / 'cases/threshold_tamper' / name
                input_ref = write(case / ('control.input.json' if process_name == 'control' else 'mutation.input.json'),
                                  {'contract': parents[parent_index]['original']})
                stdout = write(case / (process_name + '.stdout'), b'{}\n')
                stderr = write(case / (process_name + '.stderr'), b'')
                pair[input_name] = input_ref
                pair[process_name] = {'schema_version': 'negative-process/v1', 'cwd': str(root),
                    'argv': [str(root / '.venv/bin/python3'), harness['path'], 'probe', '--repo', str(root),
                             '--case', 'threshold_tamper', '--input', input_ref['path']],
                    'exit_code': 0 if process_name == 'control' else 1, 'timed_out': False,
                    'started_at': '2000-01-01T00:00:00Z', 'finished_at': '2000-01-01T00:00:01Z',
                    'timeout_seconds': 1200, 'wall_seconds': 1, 'stdout': stdout, 'stderr': stderr}
                artifacts.extend([input_ref, stdout, stderr])
            pairs.append(pair)
        result = {'schema_version': 'evaluator-negative-run/v1', 'request': request_ref, 'harness': harness,
                  'actual_dgist_acceptance': False, 'final_ac12_audit': False, 'test_only': True,
                  'artifacts': artifacts, 'cases': {'threshold_tamper': {'pairs': pairs}}}
        if 'result_mutator' in parts:
            parts['result_mutator'](result)
        result_ref = write(folder / 'result.json', result)
        receipt = {'schema_version': 'evaluator-negative-receipt/v1', 'request': request_ref, 'result': result_ref,
                   'harness': harness, 'final_ac12_audit': False, 'test_only': True}
        records = {'request': request_ref, 'result': result_ref, 'receipt': write(folder / 'receipt.json', receipt)}
    authority = {'schema_version': 'review-machine-field-authority/v1', 'family': 'contract_template',
                 'recipe': recipe, 'sources': sources, 'parents': parents, 'records': records}
    if 'authority_mutator' in parts:
        parts['authority_mutator'](authority)
    authority_ref = write(folder / 'authority.json', authority)
    parts.update(authority=authority, authority_ref=authority_ref, parents=parents)
    write(parts['directory'] / 'checkpoint.local.json', {'contract_parents': [pair['original'] for pair in parents]})


def locator(parts, index=0, selector=None):
    return {'schema_version': 'review-text-origin/v1', 'kind': 'machine_inventory_field',
            'parent': parts['parents'][index]['snapshot'], 'authority': parts['authority_ref'],
            'selector': ['criteria', 0, 'description'] if selector is None else selector}


def observe(parts, locators=None, registered=None):
    return privacy._review_text_origin_inventory([locator(parts)] if locators is None else locators,
        parts['directory'], parts['root'], set(parts['registered'].values()) if registered is None else registered,
        [parts['authority_ref']])


def inventory(parts, locators=None):
    chosen = [locator(parts)] if locators is None else locators
    return privacy._known_private_inventory(parts['directory'], parts['registered'], parts['root'],
        review_text_origins=chosen, review_text_origin_authorities=[parts['authority_ref']] if chosen else [])
