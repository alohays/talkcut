"""Complete original oversized-inventory probe syntax; never executed."""

PROBE = r'''
from pathlib import Path
import json, hashlib, sys, importlib.util, os
from datetime import datetime, timezone
from talkcut.project import artifact_ref, atomic_json
HERE = Path(__file__).resolve().parent
exec((HERE / 'probe_auxiliary.py').read_text().split("for key in ['runner'")[0])
raw = json.loads((HERE / 'bounded-closure-results.json').read_text())
row = next((r for r in raw['cases'] if r['case'] == 'oversized_binary_named_stdout'))
case, directory, sources, *unused = setup('oversized-stdout-inventory')
runref = VERIFIED_FAILURE_RUN
result = privacy.build_private_inventory(directory, sources, ROOT, synthetic_negative_runs=[runref], synthetic_replay=row['input'], **unused[-2])
atomic_json(HERE / 'oversized-stdout-inventory.json', result)
report = {'schema_version': 'independent-oversized-stdout-inventory-probe/v1', 'at': datetime.now(timezone.utc).isoformat(), 'source': artifact_ref(SOURCE), 'script': artifact_ref(__file__), 'challenge': artifact_ref(HERE / 'bounded-closure-results.json'), 'inventory': artifact_ref(HERE / 'oversized-stdout-inventory.json'), 'binary_named_stdout_in_inventory': row['actual_stdout']['path'] in {r['path'] for r in result['entries']}, 'external_reference_in_inventory': row['actual_external_ref']['path'] in {r['path'] for r in result['entries']}, 'unresolved': result['unresolved'], 'classification_status': result['classification_status'], 'scope': 'Authored bounded metadata adversarial probe only; no final private corpus approval.'}
atomic_json(HERE / 'oversized-stdout-inventory-result.json', report)
print(json.dumps({'report': artifact_ref(HERE / 'oversized-stdout-inventory-result.json'), **{k: report[k] for k in ['binary_named_stdout_in_inventory', 'external_reference_in_inventory', 'unresolved', 'classification_status']}}))
'''

SOURCE_MODULE = '45744ded78fc8a1b182a342cf98c4d863ed0cb2167fc9a47eaec71eb41e866b3'
