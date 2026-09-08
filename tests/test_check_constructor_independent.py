"""Independent constructor-only controls; synthetic metadata runs no callback."""
import pytest
from acceptance_origin_fixture import fixture, observe, refresh
from test_privacy_acceptance_relations import dependency_fixture

from talkcut.project import TalkCutError


@pytest.mark.parametrize('mode', ['checkpoint', 'python'])
@pytest.mark.parametrize('value', [None, False, 0, '', [], {}, {'private_detail': 'opaque retained callback data'}, [1, None]])
def test_success_result_is_opaque_and_never_grants_callback_approval(tmp_path, mode, value):
    parts = fixture(tmp_path, mode)
    assert observe(parts)
    check = parts['report']['criteria'][1]['checks'][0]
    check.update(status='PASS', reason='Verified from current artifacts', measurements=value)
    refresh(parts)
    result = observe(parts)[0]
    assert result['claim_status'] == 'UNVERIFIED' and result['commands'] == []
    assert parts['report']['status'] == 'FAIL'
    assert check['measurements'] == value
    if mode == 'checkpoint':
        assert observe(parts, saved=True)[0]['claim_status'] == 'UNVERIFIED'


@pytest.mark.parametrize('mode', ['checkpoint', 'python'])
@pytest.mark.parametrize('status', ['FAIL', 'UNVERIFIED'])
@pytest.mark.parametrize('value', [False, 0, [], {}])
def test_all_falsey_nonnull_exception_results_refuse(tmp_path, mode, status, value):
    parts = fixture(tmp_path, mode)
    assert observe(parts)
    criterion = parts['report']['criteria'][1]
    check = criterion['checks'][0]
    check.update(status=status, reason='Synthetic EvidenceError reason', measurements=None)
    criterion['status'] = 'FAIL' if status == 'FAIL' else 'UNVERIFIED'
    refresh(parts)
    assert observe(parts)
    check['measurements'] = value
    refresh(parts)
    with pytest.raises(TalkCutError, match='exception check carries measurements'):
        observe(parts)


@pytest.mark.parametrize('mode', ['checkpoint', 'python'])
def test_direct_no_capability_fallback_retains_exact_non_success_reason(tmp_path, mode):
    parts = fixture(tmp_path, mode)
    result = observe(parts)[0]
    check = parts['report']['criteria'][0]['checks'][-1]
    assert check == {'check_id': 'executed_reviewer_capability', 'status': 'UNVERIFIED',
        'reason': 'No valid audio/video reviewer capability demonstration', 'measurements': None}
    assert result['claim_status'] == 'UNVERIFIED'
    check['measurements'] = False
    refresh(parts)
    with pytest.raises(TalkCutError, match='exception check carries measurements'):
        observe(parts)


@pytest.mark.parametrize('mode', ['checkpoint', 'python'])
def test_successful_capability_callback_has_success_constructor_without_fallback(tmp_path, mode):
    parts = fixture(tmp_path, mode)
    assert observe(parts)
    check = parts['report']['criteria'][0]['checks'][-1]
    check.update(status='PASS', reason='Verified from current artifacts', measurements={'scope': 'synthetic callback return only'})
    refresh(parts)
    result = observe(parts)[0]
    assert len(parts['report']['criteria'][0]['checks']) == 2
    assert result['claim_status'] == 'UNVERIFIED' and result['commands'] == []
    check['reason'] = 'No valid audio/video reviewer capability demonstration'
    refresh(parts)
    with pytest.raises(TalkCutError, match='successful check reason'):
        observe(parts)


@pytest.mark.parametrize('mode', ['checkpoint', 'python'])
def test_direct_open_findings_keeps_its_own_reason_and_count(tmp_path, mode):
    parts = fixture(tmp_path, mode)
    assert observe(parts)
    parts['report']['open_findings'] = [{'severity': 'P1', 'resolved': False, 'reason': 'Retained private finding'}]
    criterion = parts['report']['criteria'][8]
    criterion['checks'][-1].update(status='FAIL', measurements={'count': 1})
    criterion['status'] = 'FAIL'
    refresh(parts)
    assert observe(parts)[0]['claim_status'] == 'UNVERIFIED'
    criterion['checks'][-1]['reason'] = 'Verified from current artifacts'
    refresh(parts)
    with pytest.raises(TalkCutError, match='original count relation'):
        observe(parts)


def test_late_dependency_keeps_its_distinct_constructor_and_original_aggregation(tmp_path):
    parts = dependency_fixture(tmp_path)
    checks = parts['report']['criteria'][8]['checks']
    assert checks[-1] == {'check_id': 'G0_G5_dependencies', 'status': 'UNVERIFIED',
        'reason': 'Final master requires all preceding media gates', 'measurements': None}
    result = observe(parts)[0]
    assert result['claim_status'] == 'UNVERIFIED' and result['commands'] == []
    checks[-1]['measurements'] = {}
    refresh(parts)
    with pytest.raises(TalkCutError, match='complete original constructor'):
        observe(parts)
