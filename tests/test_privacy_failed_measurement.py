"""Observe failed worker bytes without promoting failure to acceptance evidence."""

import hashlib
import json
from pathlib import Path

import pytest
from test_privacy_checks import repository as repository_fixture
from test_privacy_companion_phrases import publication

from talkcut import privacy_checks as privacy
from talkcut.measurements import run_measurement
from talkcut.project import TalkCutError, artifact_ref, atomic_json, init_project

repository = repository_fixture
NAMES = ('stdout.json', 'stderr.log', 'execution.json', 'receipt.json', 'run.json')
PRIVATE = 'Invented private failure detail about the synthetic task must never appear in a public release.'


def read(folder, name):
    return json.loads((folder / name).read_bytes())


def rewrite(folder, name, value):
    """Preserve every original; bind changed descendants to otherwise unchanged parents."""
    atomic_json(folder / name, value)
    if name in {'stdout.json', 'stderr.log'}:
        log = read(folder, 'execution.json')
        log['stdout' if name == 'stdout.json' else 'stderr'] = artifact_ref(folder / name)
        rewrite(folder, 'execution.json', log)
        receipt = read(folder, 'receipt.json')
        receipt['stdout' if name == 'stdout.json' else 'stderr'] = artifact_ref(folder / name)
        if name == 'stdout.json':
            receipt['result'] = artifact_ref(folder / name)
        rewrite(folder, 'receipt.json', receipt)
    elif name == 'execution.json':
        receipt = read(folder, 'receipt.json')
        receipt['log'] = artifact_ref(folder / name)
        rewrite(folder, 'receipt.json', receipt)
    elif name == 'receipt.json':
        run = read(folder, 'run.json')
        run['receipt'] = artifact_ref(folder / name)
        atomic_json(folder / 'run.json', run)


@pytest.fixture
def failed(tmp_path, repository, monkeypatch):
    monkeypatch.setenv('PYTHONPATH', str(Path(__file__).resolve().parents[1] / 'src'))
    source = tmp_path / 'synthetic-source.bin'
    source.write_bytes(b'Generated synthetic source identity; never used as real media')
    task = tmp_path / 'task'
    project = init_project(task, source, source)
    inputs = tmp_path / 'input.json'
    atomic_json(inputs, {'schema_version': 'baseline-input/v1'})
    run = run_measurement(task, 'baseline', inputs, tmp_path / 'missing-contract.json', repository)
    assert run['status'] == 'FAIL' and run['evidence'] is None and run['measurements'] is None
    folder = task / 'measurements' / run['run_id']
    receipt = read(folder, 'receipt.json')
    log = read(folder, 'execution.json')
    assert receipt['completed'] is False and receipt['exit_code'] == log['exit_code'] == 2
    assert log['failure'] is None and read(folder, 'stdout.json')['status'] == 'FAIL'
    originals = tmp_path / 'preserved-originals'
    originals.mkdir()
    for name in NAMES:
        (originals / name).write_bytes((folder / name).read_bytes())
    return task, {role: row['sha256'] for role, row in project['sources'].items()}, folder


def observe(failed):
    return privacy._bookkeeping(failed[2] / 'stdout.json', failed[0])


def test_actual_worker_failure_preserves_all_bytes_and_references(failed, repository, monkeypatch):
    before = {str(path): artifact_ref(path) for path in failed[0].rglob('*') if path.is_file()}
    observation = observe(failed)
    assert observation['state'] == 'private_failed_cli_measurement'
    assert observation['claim_status'] == 'UNVERIFIED' and observation['reported_exit_code'] == 2
    assert set(observation['artifacts']) == set(NAMES)
    # This verifier only reads the existing subprocess evidence.
    monkeypatch.setattr('talkcut.measurements.subprocess.Popen', lambda *a, **kw: pytest.fail('unexpected execution'))
    assert observe(failed) == observation
    monkeypatch.undo()
    inventory = privacy.build_private_inventory(failed[0], failed[1], repository)
    rows = {row['path']: row for row in inventory['entries']}
    assert before.keys() <= rows.keys()
    assert all(rows[path]['sha256'] == ref['sha256'] for path, ref in before.items())
    assert all(rows[str(failed[2] / name)]['classification'] == 'review' for name in NAMES)
    assert observation['input_artifacts'][0]['path'] in rows
    assert inventory['classification_status'] == inventory['known_graph']['completeness'] == 'UNVERIFIED'
    assert all(artifact_ref(Path(path)) == ref for path, ref in before.items())


@pytest.mark.parametrize('destination', ['pr_body', 'release_body', 'wheel', 'sdist'])
def test_actual_private_error_message_copy_is_detected(failed, repository, tmp_path, destination):
    message = read(failed[2], 'stdout.json')['message']
    assert len(message) >= 40
    result = publication(failed, repository, tmp_path, destination, message)
    assert result['status'] == 'FAIL' and result['user_ready'] is False
    assert any(row['kind'] == 'protected_transcript_phrase'
               and row['matched_sha256'] == hashlib.sha256(message.encode()).hexdigest() for row in result['findings'])
    assert message not in json.dumps(result['findings'])


def test_exact_public_boilerplate_does_not_become_a_private_phrase(failed, repository, tmp_path):
    reason = read(failed[2], 'run.json')['reason']
    known, phrases, graph = privacy._known_private_inventory(failed[0], failed[1], repository)
    assert reason not in phrases
    assert read(failed[2], 'stdout.json')['message'] in phrases
    assert known[artifact_ref(failed[2] / 'run.json')['sha256']] == 'review'
    assert graph['failed_cli_measurement_observations'] == [observe(failed)]
    result = publication(failed, repository, tmp_path, 'pr_body', reason)
    assert not result['findings'] and result['status'] == 'UNVERIFIED'


@pytest.mark.parametrize(('name', 'key', 'value'), [
    ('stdout.json', 'status', 'PASS'), ('stdout.json', 'retryable', 0),
    ('stdout.json', 'message', {'schema_version': 'measurement-result/v1'}),
    ('stdout.json', 'manifest_path', '/invented/manifest.json'),
    ('stdout.json', 'unexpected', {'schema_version': 'measurement-check/v1'}),
    ('stdout.json', 'code', False),
    ('run.json', 'status', 'MEASURED'), ('run.json', 'interrupted', True),
    ('run.json', 'evidence', {}), ('run.json', 'measurements', {'lip_sync': True}),
    ('run.json', 'acceptance_status', 'PASS'), ('run.json', 'owner_acceptance', 'approved'),
    ('run.json', 'reason', PRIVATE), ('run.json', 'run_id', 'measurement-' + 'f' * 32),
    ('receipt.json', 'completed', True), ('receipt.json', 'completed', 0),
    ('receipt.json', 'exit_code', 0), ('receipt.json', 'exit_code', 2.0),
    ('receipt.json', 'dependencies', {'lip_sync': True}), ('receipt.json', 'operation', 'render'),
    ('receipt.json', 'result', {'path': '/invented/result.json', 'sha256': '0' * 64}),
    ('receipt.json', 'owner_acceptance', 'approved'), ('receipt.json', 'input_artifacts', []),
    ('execution.json', 'exit_code', 0), ('execution.json', 'failure', {'type': 'TimeoutExpired'}),
    ('execution.json', 'wall_seconds', True), ('execution.json', 'wall_seconds', -1),
    ('execution.json', 'after', {'schema_version': 'measurement-result/v1'}),
    ('execution.json', 'stdout', {'path': '/invented/stdout.json', 'sha256': '0' * 64}),
    ('execution.json', 'finished_at', 'rebound'),
])
def test_fake_success_nested_formal_and_rebound_records_refuse(failed, name, key, value):
    body = read(failed[2], name)
    body[key] = value
    rewrite(failed[2], name, body)
    with pytest.raises(TalkCutError):
        observe(failed)


@pytest.mark.parametrize('name', ['stdout.json', 'run.json', 'receipt.json', 'execution.json'])
def test_duplicate_keys_refuse_even_when_hashes_are_rebound(failed, name):
    body = read(failed[2], name)
    key = next(iter(body))
    data = json.dumps(body)
    (failed[2] / name).write_text('{' + json.dumps(key) + ':' + json.dumps(body[key]) + ',' + data[1:])
    # Bind ancestors without rewriting the deliberately duplicated bytes.
    if name == 'stdout.json':
        log = read(failed[2], 'execution.json')
        log['stdout'] = artifact_ref(failed[2] / name)
        rewrite(failed[2], 'execution.json', log)
        receipt = read(failed[2], 'receipt.json')
        receipt['stdout'] = receipt['result'] = artifact_ref(failed[2] / name)
        rewrite(failed[2], 'receipt.json', receipt)
    elif name == 'execution.json':
        receipt = read(failed[2], 'receipt.json')
        receipt['log'] = artifact_ref(failed[2] / name)
        rewrite(failed[2], 'receipt.json', receipt)
    elif name == 'receipt.json':
        run = read(failed[2], 'run.json')
        run['receipt'] = artifact_ref(failed[2] / name)
        rewrite(failed[2], 'run.json', run)
    with pytest.raises(TalkCutError, match='duplicate'):
        observe(failed)


@pytest.mark.parametrize('name', NAMES)
def test_oversize_sidecar_is_refused_before_read(failed, monkeypatch, name):
    selected = failed[2] / name
    with selected.open('wb') as stream:
        stream.truncate(privacy.MAX_UNIT_BYTES + 1)
    original = Path.read_bytes
    def guarded(path):
        assert path != selected, 'oversized sidecar was opened'
        return original(path)
    monkeypatch.setattr(Path, 'read_bytes', guarded)
    with pytest.raises(TalkCutError, match='oversized'):
        observe(failed)


@pytest.mark.parametrize('name', NAMES)
def test_same_byte_symlink_sidecar_is_refused(failed, tmp_path, name):
    selected = failed[2] / name
    copy = tmp_path / ('copy-' + name)
    copy.write_bytes(selected.read_bytes())
    selected.unlink()
    selected.symlink_to(copy)
    with pytest.raises(TalkCutError, match='linked'):
        observe(failed)


def test_stale_stdout_hash_refuses(failed):
    output = read(failed[2], 'stdout.json')
    output['message'] = PRIVATE
    atomic_json(failed[2] / 'stdout.json', output)
    with pytest.raises(TalkCutError, match='rebound|scope'):
        observe(failed)


def test_exact_cancelled_cli_shape_is_only_unverified_bytes(failed):
    rewrite(failed[2], 'stdout.json', {'schema_version': 'talkcut-error/v1', 'status': 'FAIL', 'code': 'CANCELLED'})
    log = read(failed[2], 'execution.json')
    log['exit_code'] = 130
    rewrite(failed[2], 'execution.json', log)
    receipt = read(failed[2], 'receipt.json')
    receipt['exit_code'] = 130
    rewrite(failed[2], 'receipt.json', receipt)
    observed = observe(failed)
    assert observed['reported_exit_code'] == 130 and observed['claim_status'] == 'UNVERIFIED'
    # This is a constructed cancellation record, not a claim that a cancel ran.


def test_unknown_check_actual_subprocess_failure_is_supported(failed, tmp_path, repository, monkeypatch):
    monkeypatch.setenv('PYTHONPATH', str(Path(__file__).resolve().parents[1] / 'src'))
    raw = tmp_path / 'unknown-input.json'
    atomic_json(raw, {})
    run = run_measurement(failed[0], 'unknown-contract-check', raw, tmp_path / 'missing.json', repository)
    folder = failed[0] / 'measurements' / run['run_id']
    assert privacy._bookkeeping(folder / 'stdout.json', failed[0])['reported_exit_code'] == 2


def test_failed_record_cannot_carry_evidence(failed):
    atomic_json(failed[2] / 'evidence.json', {'schema_version': 'measurement-check/v1'})
    with pytest.raises(TalkCutError, match='evidence'):
        observe(failed)


def test_nonfinite_record_refuses(failed):
    log = read(failed[2], 'execution.json')
    log['wall_seconds'] = float('nan')
    (failed[2] / 'execution.json').write_text(json.dumps(log))
    with pytest.raises(TalkCutError, match='nonfinite'):
        observe(failed)


def test_run_directory_alias_cannot_claim_canonical_scope(failed, tmp_path):
    alias = tmp_path / 'alias'
    alias.symlink_to(failed[2], target_is_directory=True)
    with pytest.raises(TalkCutError, match='scope'):
        privacy._failed_cli_measurement(alias / 'stdout.json', failed[0])


def test_identical_stdout_outside_measurement_namespace_is_not_a_new_role(failed, tmp_path):
    outside = tmp_path / 'stdout.json'
    outside.write_bytes((failed[2] / 'stdout.json').read_bytes())
    assert privacy._bookkeeping(outside, failed[0]) is None


def test_input_hash_change_refuses_without_rebinding_original_record(failed):
    receipt = read(failed[2], 'receipt.json')
    Path(receipt['input_artifacts'][0]['path']).write_bytes(b'changed raw input')
    with pytest.raises(TalkCutError, match='changed'):
        observe(failed)


@pytest.mark.parametrize('field', ['stdout', 'log', 'result', 'input_artifacts'])
def test_receipt_ref_shapes_do_not_admit_nested_formal_authority(failed, field):
    receipt = read(failed[2], 'receipt.json')
    target = receipt[field][0] if field == 'input_artifacts' else receipt[field]
    target['authority'] = {'schema_version': 'execution-receipt/v1', 'completed': True}
    rewrite(failed[2], 'receipt.json', receipt)
    with pytest.raises(TalkCutError):
        observe(failed)


def test_cancelled_stdout_with_exit_two_is_rejected(failed):
    rewrite(failed[2], 'stdout.json', {'schema_version': 'talkcut-error/v1', 'status': 'FAIL', 'code': 'CANCELLED'})
    with pytest.raises(TalkCutError):
        observe(failed)


def test_short_generic_error_retains_exact_hash_without_invented_phrase_coverage(failed, repository):
    output = read(failed[2], 'stdout.json')
    output['message'] = 'Unknown contract measurement'
    rewrite(failed[2], 'stdout.json', output)
    known, phrases, _ = privacy._known_private_inventory(failed[0], failed[1], repository)
    assert known[artifact_ref(failed[2] / 'stdout.json')['sha256']] == 'review'
    assert output['message'] not in phrases  # Existing 40-character policy is unchanged.


def test_failed_error_namespace_cannot_hide_a_missing_sidecar(failed):
    (failed[2] / 'run.json').unlink()
    with pytest.raises(TalkCutError, match='missing'):
        observe(failed)


def test_during_observation_mutation_is_detected(failed, monkeypatch):
    selected = failed[2] / 'stdout.json'
    trigger = failed[2] / 'run.json'
    original = Path.read_bytes
    def guarded(path):
        data = original(path)
        if path == trigger:
            selected.write_bytes(selected.read_text().replace('FAIL', 'PASS').encode())
        return data
    monkeypatch.setattr(Path, 'read_bytes', guarded)
    with pytest.raises(TalkCutError, match='changed'):
        observe(failed)
