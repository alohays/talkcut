"""A historical schema mention does not erase full private alias provenance."""
import json
from pathlib import Path

from test_privacy_inventory_alias_rows import ROOT, case, observe
from test_privacy_inventory_alias_rows import (
    replay as replay,  # noqa: PLC0414 - exported pytest fixture
)

from talkcut import privacy_checks as privacy
from talkcut.project import artifact_ref, atomic_json


def test_historical_alias_schema_retains_rows_parents_and_private_prose(tmp_path, replay):
    value = case(tmp_path, replay)
    copied = value['copied_path']
    body = json.loads(copied.read_bytes())
    phrase = 'This complete unselected private fixture sentence must remain in the protection corpus.'
    body.update(schema_version='independent-execution-tool-alias-inventory/v1', private_prose=phrase)
    atomic_json(copied, body)
    for request in value['requests']:
        if request['parent']['path'] == str(copied):
            request['parent'] = artifact_ref(copied)
    atomic_json(value['task'] / 'goal-handoff.local.json',
                {'historical_inventory': artifact_ref(value['origin_path']), 'copied_review': artifact_ref(copied)})
    before = {path: path.read_bytes() for path in (value['origin_path'], copied)}
    observations = observe(value, value['requests'], replay)
    assert len(observations) == 6
    _, phrases, _ = privacy._known_private_inventory(value['task'], value['sources'], ROOT,
                            synthetic_replay=replay, inventory_alias_row_reobservations=value['requests'])
    assert phrase in phrases
    result = privacy.build_private_inventory(value['task'], value['sources'], ROOT, archive_dir=tmp_path / 'preserved',
                            synthetic_replay=replay, inventory_alias_row_reobservations=value['requests'])
    assert result['classification_status'] == result['known_graph']['completeness'] == 'UNVERIFIED'
    assert len(result['known_graph']['inventory_alias_row_reobservations']) == 6
    rows = {row['path']: row for row in result['entries']}
    assert rows[str(copied)]['classification'] == 'review'
    archived = result['preserved_private_inputs'][str(copied)]
    assert Path(archived['path']).read_bytes() == before[copied]
    authority = privacy._verified_synthetic_replay(replay, ROOT)
    for ref in [authority['bundle'], *authority['artifacts'], *authority['external_inputs']]:
        assert rows[ref['path']]['sha256'] == ref['sha256']
    for observation in observations:
        assert observation['claim_status'] == observation['execution_status'] == 'UNVERIFIED'
        assert observation['history_supported'] is False
        for hop in observation['alias_identity']['hops']:
            assert rows[hop['path']]['sha256'] == hop['link_bytes_sha256']
            assert rows[hop['path']]['classification'] == 'UNCLASSIFIED'
        target = observation['alias_identity']['target']
        assert rows[target['path']]['sha256'] == target['sha256']
        assert rows[target['path']]['classification'] == 'UNCLASSIFIED'
    assert before == {path: path.read_bytes() for path in before}
