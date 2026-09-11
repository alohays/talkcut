"""Retained selector normalization; exact constructor-positive fixture first."""
import pytest
from checkpoint_data_origin_fixture import fixture, observe, refresh

from talkcut.project import TalkCutError


def test_valid_original_retained_selection(tmp_path):
    p = fixture(tmp_path)
    assert len(observe(p)) == 1


@pytest.mark.parametrize('which', ['pointer', 'source_pointer'])
def test_overlong_retained_decimal_refuses_as_typed_unverified(tmp_path, which):
    p = fixture(tmp_path)
    assert len(observe(p)) == 1
    def mutate(record):
        row = record['cases'][0]['rows'][0]
        prefix = '/acceptance' if which == 'pointer' else ''
        row[which] = prefix + '/criteria/' + '9' * 5000 + '/description'
    p['retained_mutator'] = mutate
    refresh(p)
    with pytest.raises(TalkCutError):
        observe(p)
