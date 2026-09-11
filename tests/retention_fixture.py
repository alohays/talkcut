"""Fully synthetic metadata; retained historical Python is parsed, never run."""
from __future__ import annotations

import ast
import hashlib
import json
from pathlib import Path
from typing import Any

from talkcut import privacy_retention_origins as retention
from talkcut.project import TalkCutError

FIXTURES = Path(__file__).parent / 'fixtures'


def ref(path: Path) -> dict[str, str]:
    return {'path': str(path.resolve()), 'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}


def write(path: Path, value: Any) -> dict[str, str]:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + '\n')
    return ref(path)


def read(value: dict[str, str]) -> tuple[Path, bytes]:
    path = Path(value['path'])
    if path.stat().st_size > retention.MAX_RETENTION_BYTES:
        raise TalkCutError('PUBLICATION_PRIVACY_UNVERIFIED', 'Fixture bounded read')
    data = path.read_bytes()
    if hashlib.sha256(data).hexdigest() != value['sha256']:
        raise TalkCutError('PUBLICATION_PRIVACY_UNVERIFIED', 'Fixture original digest differs')
    return path, data


def document(value: dict[str, str]) -> dict[str, Any]:
    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, item in items:
            if key in result:
                raise TalkCutError('PUBLICATION_PRIVACY_UNVERIFIED', 'Duplicate JSON keys')
            result[key] = item
        return result
    return json.loads(read(value)[1], object_pairs_hook=pairs)


def fixture(tmp_path: Path, variant: int = 0) -> dict[str, Any]:
    root = tmp_path / 'repo'
    project = root / 'projects/fixture-retention'
    output = project / 'evidence/transcript-corpus-independent' / ('a' * 32)
    output.mkdir(parents=True)
    source = root / 'retained-source.py'
    source.write_bytes((FIXTURES / f'source-{variant}.py.txt').read_bytes())
    script = root / 'retained-reproducer.py'
    script.write_bytes((FIXTURES / f'script-{variant}.py.txt').read_bytes())
    old = output / 'old-scanner.gitblob.local.py'
    old.write_bytes((FIXTURES / f'old_scanner-{variant}.py.txt').read_bytes())
    tree = retention.syntax(source.read_bytes())
    producer = retention.named_function(tree, '_known_private_inventory')
    fields = retention.dict_fields(producer.body[-1].value.elts[2])
    known: dict[str, Any] = {key: [] for key in fields}
    known.update({key: node.value for key, node in fields.items() if isinstance(node, ast.Constant)})
    source_hashes = {'screen': '1' * 64}
    known.update(project=str(project), source_hashes=source_hashes, derived_phrase_count=3,
                 historical_refs=0, historical_unresolved=0)
    strings = retention.legacy_inventory_writers(producer, fields)
    code = {'path': str(root / 'copy.py'), 'sha256': '2' * 64, 'classification': 'UNCLASSIFIED',
            'reason': strings['CODE_REASON'], 'matching_git_source_bytes': []}
    known['public_work_candidates'] = [code]
    if 'PRESERVATION' in strings:
        known['public_work_candidates'].append({**code, 'path': str(root / 'preserved.py'),
            'original_reference': {'path': str(root / 'original.py'), 'sha256': '2' * 64},
            'preservation': strings['PRESERVATION']})
    known['unfollowed_refs'] = [{k: code[k] for k in ('path', 'sha256', 'reason')},
        {'path': str(root / 'external.json'), 'sha256': '3' * 64, 'reason': strings['EXTERNAL_REASON']}]
    script_tree = retention.syntax(script.read_bytes())
    paths = retention.path_assignments(script_tree, root, script)
    input_ref = write(paths['raw_input_path'], {'historical_artifacts': [], 'source_snapshots': []})
    supporting = {}
    for variable, field in [('previous_path', 'previous_diagnostic'), ('current_r3_path', 'latest_prior_r3'), ('runtime', 'runtime_origin_parent')]:
        supporting[field] = write(paths[variable], {'schema_version': 'synthetic-private-context/v1'})
    written = retention.dict_fields(retention.assignment(script_tree, 'report'))
    report = {key: None for key in written}
    report.update({key: node.value for key, node in written.items() if isinstance(node, ast.Constant)})
    transcript_rows = []
    for i in range(19):
        artifact = {'path': str(project / 'transcripts' / f'{i:02}-fixture.json'), 'sha256': f'{i+10:064x}'}
        transcript_rows.append({'artifact': artifact, 'bytes': 100, 'speech_fields': [], 'plain_transcript_lines': [],
                               'private_exact_hash_retained': True, 'assigned_kind': 'transcript'})
    marker = transcript_rows[11]
    marker.update(schema_version='transcript/v1', source_sha256='1' * 64,
                  speech_fields=[{'pointer': '/segments/0/text', 'characters': 80, 'qualifies_40_chars': True, 'sha256': '4' * 64}])
    known['known_refs'] = [{**r['artifact'], 'kind': 'transcript'} for r in transcript_rows]
    known['known_ref_count'] = len(known['known_refs'])
    report.update(supporting)
    report.update(current_inventory=known, source_before={'path': str(root / 'src/talkcut/privacy_checks.py'), 'sha256': ref(source)['sha256']},
                  source_after={'path': str(root / 'src/talkcut/privacy_checks.py'), 'sha256': ref(source)['sha256']},
                  reproducer=ref(script), actual_current_inventory_inputs={'raw_privacy_input': input_ref, 'registered_source_hashes': source_hashes},
                  previous_scanner={**ref(old), 'git_blob_oid': 'afc6b719d22612354a95cd22f052c91022387b41'},
                  current_phrase_ref={'path': str(output / 'current-phrases.private.json'), 'sha256': '5' * 64},
                  removed_phrase_ref={'path': str(output / 'removed-runtime-phrases.private.json'), 'sha256': '6' * 64},
                  transcript_files_checked=transcript_rows)
    for key in ('added_phrase_count', 'prior_r3_phrase_count', 'previous_exact_phrase_count', 'previous_saved_phrase_count',
                'independent_expected_unique_speech_strings', 'independent_expected_speech_occurrences', 'missing_speech_count',
                'removed_phrase_count', 'unexplained_removed_count'):
        report[key] = 0
    for key in ('expected_speech_strings', 'missing_speech_strings', 'unexplained_removed', 'added_phrase_hashes', 'previous_transcript_node_files'):
        report[key] = []
    report.update(started_at='2000-01-01T00:00:00Z', finished_at='2000-01-01T00:00:01Z', wall_seconds=1.0,
                  current_phrase_count=3, public_code_unchanged_during_execution=True, status='EXACT_TRANSCRIPT_RETENTION_CONFIRMED',
                  protected_project_files_unchanged=[{'path': str(project / n), 'sha256': '7' * 64}
                     for n in ('project.json', 'acceptance.local.json', 'checkpoint.local.json')])
    result = output / 'result.local.json'
    selected = {'schema_version': 'review-machine-field-authority/v1', 'family': 'transcript_corpus_inventory',
                'result': write(result, report), 'reproducer': ref(script), 'source_snapshot': ref(source),
                'input': input_ref, 'previous_scanner': ref(old)}
    return {'root': root, 'project': project, 'output': output, 'source': source, 'script': script,
            'report': report, 'selected': selected, 'result': result}


def rebound(context: dict[str, Any]) -> None:
    context['selected']['source_snapshot'] = ref(context['source'])
    context['selected']['reproducer'] = ref(context['script'])
    context['report']['reproducer'] = ref(context['script'])
    for name in ('source_before', 'source_after'):
        context['report'][name]['sha256'] = ref(context['source'])['sha256']
    context['selected']['result'] = write(context['result'], context['report'])


def verify(context: dict[str, Any]) -> dict[str, Any]:
    return retention.verify_retention_inventory(context['selected'], context['root'], read, document)
