from __future__ import annotations

from pathlib import Path

import pytest
from retention_consumer_fixture import PRIVATE_PROSE, consumer_fixture, observe
from retention_fixture import ref, write


@pytest.mark.parametrize('variant', [0, 1])
def test_full_real_file_consumer_preserves_private_rows_and_unselected_text(tmp_path: Path, variant: int) -> None:
    context = consumer_fixture(tmp_path, variant)
    parent_before = context['result'].read_bytes()
    input_files = sorted(p for p in context['root'].rglob('*') if p.is_file() and '.git' not in p.parts)
    input_before = [ref(p) for p in input_files]
    known_before, phrases_before, graph_before = observe(context, False)
    known_after, phrases_after, graph_after = observe(context, True)
    assert context['selected_phrase'] in phrases_before
    assert context['selected_phrase'] not in phrases_after
    assert PRIVATE_PROSE in phrases_after and set(context['private_texts']) <= set(phrases_after)
    assert all(known_after[digest] == kind for digest, kind in known_before.items())
    assert known_after[ref(context['result'])['sha256']] == 'review'
    assert context['result'].read_bytes() == parent_before
    before_rows = {(row['path'], row['sha256'], row['kind']) for row in graph_before['known_refs']}
    after_rows = {(row['path'], row['sha256'], row['kind']) for row in graph_after['known_refs']}
    assert before_rows <= after_rows
    assert len(graph_after['review_text_origins']) == 1
    observation = graph_after['review_text_origins'][0]
    assert observation['claim_status'] == 'UNVERIFIED'
    assert observation['extractions'] == [{'edge': ['current_inventory', 'scope'], 'value': context['selected_phrase']}]
    assert observation['source_snapshot']['sha256'] not in known_after
    assert input_before == [ref(p) for p in input_files]
    write(tmp_path / 'observed-consumer.json', {'before': graph_before, 'after': graph_after,
        'known_before': known_before, 'known_after': known_after, 'phrases_before': phrases_before,
        'phrases_after': phrases_after, 'input_refs_before_after': input_before,
        'parent_bytes_unchanged': True, 'synthetic_metadata_only': True})
