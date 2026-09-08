"""Portable full-map report data; source fixtures are parsed, never executed."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from acceptance_origin_fixture import encoded
from report_data_origin_fixture import fixture as original_fixture
from report_data_origin_fixture import refresh as original_refresh
from report_data_origin_fixture import write

REPLACEMENTS = {
    'src/talkcut/acceptance.py': 'report-canonical-evaluator.py.txt',
    'src/talkcut/project.py': 'report-canonical-project.py.txt',
    'src/talkcut/__main__.py': 'report-canonical-cli.py.txt',
}


def fixture(tmp_path, **options):
    parts = original_fixture(tmp_path, serialization='canonical_json_lf', **options)
    parts['previous_sources'] = {role: Path(ref['path']).read_bytes() for role, ref in parts['sources'].items()}
    for role, filename in REPLACEMENTS.items():
        Path(parts['sources'][role]['path']).write_bytes((Path(__file__).parent / 'fixtures' / filename).read_bytes())
    parts['additional_map'] = {f'docs/synthetic-{index:03}.txt': hashlib.sha256(str(index).encode()).hexdigest()
                               for index in range(122)}
    refresh(parts)
    return parts


def refresh(parts):
    # Construct complete synthetic retained metadata; never call its old writer.
    original_refresh(parts)
    authority = parts['data_authority']
    maps_path = Path(authority['source_maps']['path'])
    maps = json.loads(maps_path.read_bytes())
    for index, (report, parent, case) in enumerate(zip(parts['reports'], authority['parents'], maps['cases'], strict=True)):
        report['files'].update(parts['additional_map'])
        report['code_tree_hash'] = hashlib.sha256(encoded(report['files'])).hexdigest()
        raw = (encoded(report) if parts['serialization'] == 'canonical_json_lf'
               else json.dumps(report, ensure_ascii=False, allow_nan=False, indent=2).encode()) + b'\n'
        original = write(parent['original']['path'], raw)
        snapshot = write(parent['snapshot']['path'], raw)
        parent.update(original=original, snapshot=snapshot)
        case.update(parent={'kind': 'review', **original}, declared_code_tree_hash=report['code_tree_hash'])
        case['members'] += [{'name': name, 'expected_sha256': digest} for name, digest in parts['additional_map'].items()]
        if 'full_map_mutator' in parts:
            parts['full_map_mutator'](case)
    authority['source_maps'] = write(maps_path, maps)
    if 'full_authority_mutator' in parts:
        parts['full_authority_mutator'](authority)
    parts['data_authority_ref'] = write(parts['folder'] / 'data-authority.json', authority)
    parts['parents'] = authority['parents']
    write(parts['directory'] / 'checkpoint.local.json', {'original_reports': [p['original'] for p in parts['parents']]})
