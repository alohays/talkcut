"""Synthetic byte-bound verifier fixtures; no actual provider/media approval."""
import copy
import json

import pytest

from talkcut.acceptance import Evaluator
from talkcut.project import artifact_ref

MISSING = object()


def save(path, value):
    path.write_text(json.dumps(value, sort_keys=True) + '\n')
    return artifact_ref(path)


def finding_case(tmp_path, change, identity='issue:explicit-positive', mutate=None):
    """Exercise actual artifact/dependency/receipt verifier, without mocks."""
    repo = tmp_path / 'synthetic-repo'
    repo.mkdir()
    evaluator = Evaluator(tmp_path, 'synthetic-render', tmp_path / 'contract.json', repo)
    deps = dict(evaluator.deps)
    prompt = tmp_path / 'prompt.txt'
    prompt.write_text('Synthetic identity validation fixture; no provider was called.\n')
    log = tmp_path / 'log.txt'
    log.write_text('Synthetic test data, not an execution observation.\n')
    original = tmp_path / 'original-evidence.txt'
    original.write_text('Synthetic original/repair evidence used only by a unit test.\n')
    request = {'dependencies': deps, 'scope': 'finding_' + change,
               'evidence_refs': [artifact_ref(original)],
               'from_severity': 'P1', 'to_severity': 'P2'}
    response = {'verdict': 'PASS', 'change_approved': True,
                'reason': 'Synthetic positive verifier control only; no real finding approval.',
                'resolved': True, 'to_severity': 'P2'}
    finding = {'severity': 'P2' if change == 'severity' else 'P1',
               'original_severity': 'P1', 'reporter_run_id': 'synthetic-reporter'}
    if identity is not MISSING:
        finding['id'] = identity
        request['finding_id'] = identity
        response['finding_id'] = identity
    receipt = {'schema_version': 'execution-receipt/v1', 'run_id': 'synthetic-independent-auditor',
               'started_at': '2026-01-01T00:00:00+00:00', 'finished_at': '2026-01-01T00:00:01+00:00',
               'completed': True, 'exit_code': 0, 'executor': 'synthetic-test-fixture',
               'tool_version': 'synthetic-fixture/v1', 'command': ['synthetic-fixture-not-executed'],
               'log': artifact_ref(log), 'dependencies': deps,
               'provider_request_id': 'synthetic-provider-id', 'model_revision': 'synthetic-model-label',
               'prompt_sha256': artifact_ref(prompt)['sha256'], 'prompt': artifact_ref(prompt)}
    evidence = {'dependencies': deps, 'reviewer_role': 'independent_auditor',
                'reviewer_run_id': 'synthetic-independent-auditor'}
    if mutate:
        mutate(finding, request, response, receipt, evidence)
    receipt['request'] = save(tmp_path / 'request.json', request)
    receipt['response'] = save(tmp_path / 'response.json', response)
    evidence['receipt'] = save(tmp_path / 'receipt.json', receipt)
    key = 'independent_review_ref' if change == 'severity' else 'resolution_ref'
    finding[key] = save(tmp_path / 'review.json', evidence)
    save(tmp_path / 'finding.json', finding)
    return evaluator, finding


@pytest.mark.parametrize('change', ['resolution', 'severity'])
def test_omitted_identity_cannot_approve_unidentified_issue(tmp_path, change):
    evaluator, finding = finding_case(tmp_path, change, MISSING)
    before = copy.deepcopy(finding)
    assert evaluator.verify_finding_change(finding, change) is False
    assert finding == before


@pytest.mark.parametrize('change', ['resolution', 'severity'])
def test_idless_receipt_cannot_close_two_unrelated_findings(tmp_path, change):
    evaluator, first = finding_case(tmp_path, change, MISSING)
    first['description'] = 'Synthetic clipping observation on source A at ten seconds.'
    second = {**first, 'description': 'Unrelated synthetic clipping observation on source B at twenty seconds.'}
    observed = (evaluator.verify_finding_change(first, change),
                evaluator.verify_finding_change(second, change))
    assert observed == (False, False)


@pytest.mark.parametrize('change', ['resolution', 'severity'])
@pytest.mark.parametrize('identity', [None, '', '   \t', 0, 7, True, [], {}])
def test_shared_invalid_identity_is_rejected(tmp_path, change, identity):
    evaluator, finding = finding_case(tmp_path, change, identity)
    before = copy.deepcopy(finding)
    assert evaluator.verify_finding_change(finding, change) is False
    assert finding == before


@pytest.mark.parametrize('change', ['resolution', 'severity'])
@pytest.mark.parametrize('identity', ['issue:explicit-positive', '7', '확인할 항목'])
def test_matching_explicit_string_identity_remains_valid(tmp_path, change, identity):
    evaluator, finding = finding_case(tmp_path, change, identity)
    assert evaluator.verify_finding_change(finding, change) is True


@pytest.mark.parametrize('change', ['resolution', 'severity'])
@pytest.mark.parametrize('mutation', [
    lambda f, q, r, c, e: q.__setitem__('finding_id', 'unrelated-issue'),
    lambda f, q, r, c, e: r.__setitem__('finding_id', 'unrelated-issue'),
    lambda f, q, r, c, e: q.pop('finding_id'),
    lambda f, q, r, c, e: r.pop('finding_id'),
    lambda f, q, r, c, e: q.__setitem__('scope', 'independent_audit'),
    lambda f, q, r, c, e: f.__setitem__('reporter_run_id', 'synthetic-independent-auditor'),
    lambda f, q, r, c, e: r.__setitem__('verdict', 'UNVERIFIED'),
    lambda f, q, r, c, e: r.__setitem__('change_approved', False),
    lambda f, q, r, c, e: r.__setitem__('reason', ''),
    lambda f, q, r, c, e: c.__setitem__('completed', False),
    lambda f, q, r, c, e: e.__setitem__('dependencies', {'code_tree_hash': 'wrong'}),
    lambda f, q, r, c, e: q.__setitem__('evidence_refs', []),
])
def test_other_existing_bindings_remain_required(tmp_path, change, mutation):
    evaluator, finding = finding_case(tmp_path, change, mutate=mutation)
    assert evaluator.verify_finding_change(finding, change) is False


def test_resolution_still_requires_resolved(tmp_path):
    evaluator, finding = finding_case(tmp_path, 'resolution', mutate=lambda f,q,r,c,e: r.__setitem__('resolved', False))
    assert evaluator.verify_finding_change(finding, 'resolution') is False


def test_severity_still_requires_exact_transition(tmp_path):
    evaluator, finding = finding_case(tmp_path, 'severity', mutate=lambda f,q,r,c,e: q.__setitem__('to_severity', 'P3'))
    assert evaluator.verify_finding_change(finding, 'severity') is False
