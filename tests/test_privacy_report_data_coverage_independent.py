"""Source-owned container shapes without callback truth or count thresholds."""
from __future__ import annotations

import copy
from pathlib import Path

import pytest
from report_data_origin_fixture import fixture, locator, observe, refresh

from talkcut.project import TalkCutError

ORDER = ['output_audio', 'output_video', 'deleted_source', 'source_analysis',
         'observed_frame_count', 'observed_frame_count_unknown_runs', 'deletion_count', 'seams']


def complete_metrics():
    values = {key: {'denominator_seconds': '2', 'numerator_seconds': '2', 'fraction': 1.0,
                    'not_applicable': False, 'uncovered_intervals': []} for key in ORDER[:4]}
    values.update(observed_frame_count=0, observed_frame_count_unknown_runs=0,
                  deletion_count={'denominator': 0, 'numerator': 0, 'not_applicable': True},
                  seams={'denominator': 0, 'numerator': 0, 'not_applicable': True, 'uncovered_times': []})
    return values


@pytest.mark.parametrize('length', range(9))
def test_exact_constructed_metric_prefixes(tmp_path, length):
    parts = fixture(tmp_path)
    parts['reports'][0]['coverage'] = dict(list(complete_metrics().items())[:length])
    refresh(parts)
    assert observe(parts)


@pytest.mark.parametrize('fault', ['first_bool', 'first_list', 'unknown_bool', 'frame_float', 'deletion_list',
                                  'seam_tuple_string', 'partial_row', 'added_row_field'])
def test_unselected_source_owned_shape_must_still_match(tmp_path, fault):
    parts = fixture(tmp_path)
    metrics = complete_metrics()
    parts['reports'][0]['coverage'] = metrics
    refresh(parts)
    assert observe(parts)
    if fault == 'first_bool':
        metrics['output_audio'] = False
    elif fault == 'first_list':
        metrics['output_audio'] = []
    elif fault == 'unknown_bool':
        metrics['observed_frame_count_unknown_runs'] = False
    elif fault == 'frame_float':
        metrics['observed_frame_count'] = 1.0
    elif fault == 'deletion_list':
        metrics['deletion_count'] = []
    elif fault == 'seam_tuple_string':
        metrics['seams']['uncovered_times'] = ['0', 1]
    elif fault == 'partial_row':
        metrics['output_video'].pop('fraction')
    else:
        metrics['source_analysis']['unverified_prose'] = 'extra source-unwritten field'
    refresh(parts)
    with pytest.raises(TalkCutError):
        observe(parts)


def test_negative_observed_count_is_not_a_new_acceptance_threshold(tmp_path):
    parts = fixture(tmp_path)
    metrics = complete_metrics()
    metrics['observed_frame_count'] = -3
    parts['reports'][0]['coverage'] = metrics
    refresh(parts)
    assert observe(parts)


@pytest.mark.parametrize('delta', [0, 1])
def test_outer_locator_never_accepts_optional_size(tmp_path, delta):
    parts = fixture(tmp_path, archived=True)
    assert observe(parts)
    selected = locator(parts)
    selected['parent'] = copy.deepcopy(selected['parent'])
    selected['parent']['bytes'] = Path(selected['parent']['path']).stat().st_size + delta
    with pytest.raises(TalkCutError, match='exact artifact reference'):
        observe(parts, [selected])
