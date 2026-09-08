"""Real-file fixture for the consumer; synthetic metadata, never past execution."""
from __future__ import annotations

import hashlib
import subprocess
from pathlib import Path
from typing import Any

from retention_fixture import fixture, rebound, ref, write

from talkcut import privacy_checks as privacy
from talkcut.project import init_project

PRIVATE_PROSE = 'This separate synthetic private review prose must stay protected after every machine leaf projection.'


def git(root: Path, *argv: str) -> str:
    return subprocess.check_output(['git', *argv], cwd=root, text=True, stderr=subprocess.PIPE).strip()


def consumer_fixture(tmp_path: Path, variant: int) -> dict[str, Any]:
    context = fixture(tmp_path, variant)
    root, directory = context['root'], context['project']
    original_source = root / 'src/talkcut/privacy_checks.py'
    original_source.parent.mkdir(parents=True)
    original_source.write_bytes(context['source'].read_bytes())
    git(root, 'init', '--initial-branch=main')
    git(root, 'add', 'src/talkcut/privacy_checks.py')
    git(root, '-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid', 'commit', '-m', 'Synthetic source grammar fixture')
    old_scanner = Path(context['selected']['previous_scanner']['path'])
    assert git(root, 'hash-object', '-w', str(old_scanner)) == context['report']['previous_scanner']['git_blob_oid']
    screen, speaker = root / 'registered-screen.bin', root / 'registered-speaker.bin'
    screen.write_bytes(b'Synthetic screen source identity; no decoded media claim.')
    speaker.write_bytes(b'Synthetic speaker source identity; no decoded media claim.')
    project = init_project(directory, screen, speaker)
    registered = {role: row['sha256'] for role, row in project['sources'].items()}
    write(directory / 'acceptance.local.json', {'schema_version': 'synthetic-private-control/v1', 'status': 'UNVERIFIED'})
    write(directory / 'checkpoint.local.json', {'reason': PRIVATE_PROSE})
    report = context['report']
    report['protected_project_files_unchanged'] = [ref(directory / name) for name in ('project.json', 'acceptance.local.json', 'checkpoint.local.json')]
    report['actual_current_inventory_inputs']['registered_source_hashes'] = registered
    rows = []
    expected = []
    texts = []
    for i in range(19):
        path = directory / 'transcripts' / f'{i:02}-fixture.json'
        text = f'Synthetic private transcript statement number {i:02} is retained in the complete private phrase corpus.'
        body = {'text': text}
        if i == 11:
            body.update(schema_version='transcript/v1', source_sha256=registered['screen'])
        artifact = write(path, body)
        digest = hashlib.sha256(text.encode()).hexdigest()
        row = {'artifact': artifact, 'bytes': path.stat().st_size,
               'speech_fields': [{'pointer': '/text', 'characters': len(text), 'sha256': digest, 'qualifies_40_chars': True}],
               'plain_transcript_lines': [], 'private_exact_hash_retained': True, 'assigned_kind': 'transcript',
               'schema_version': body.get('schema_version'), 'source_sha256': body.get('source_sha256')}
        rows.append(row)
        expected.append({'sha256': digest, 'characters': len(text), 'exact_string_retained': True,
                         'origins': [{'artifact': artifact, 'json_pointer': '/text', 'field': 'text'}]})
        texts.append(text)
    report['transcript_files_checked'] = rows
    report['expected_speech_strings'] = expected
    report['independent_expected_unique_speech_strings'] = len(expected)
    report['independent_expected_speech_occurrences'] = len(expected)
    report['current_phrase_count'] = len(texts)
    report['current_phrase_ref'] = write(Path(report['current_phrase_ref']['path']), sorted(texts))
    report['removed_phrase_ref'] = write(Path(report['removed_phrase_ref']['path']), [])
    previous_nodes = [{**r['artifact'], 'kind': 'transcript'} for r in rows]
    report['previous_diagnostic'] = write(Path(report['previous_diagnostic']['path']),
        {'protected_phrase_count': len(texts), 'private_inventory': {'known_refs': previous_nodes}})
    report['latest_prior_r3'] = write(Path(report['latest_prior_r3']['path']), {'private_inventory': {'derived_phrase_count': len(texts)}})
    report['runtime_origin_parent'] = write(Path(report['runtime_origin_parent']['path']),
        {'schema_version': 'synthetic-runtime-reference/v1', 'source_sha256': registered['screen'], 'artifacts': []})
    report['previous_exact_phrase_count'] = report['previous_saved_phrase_count'] = report['prior_r3_phrase_count'] = len(texts)
    report['previous_transcript_node_files'] = [{**r['artifact'], 'bytes': r['bytes'], 'within_original_text_inspection_bound': True} for r in rows]
    known = report['current_inventory']
    known.update(source_hashes=registered, derived_phrase_count=len(texts))
    known['known_refs'] = previous_nodes + [{**ref(directory / n), 'kind': 'review'} for n in ('project.json', 'acceptance.local.json', 'checkpoint.local.json')]
    for source in project['sources'].values():
        for key in ('path', 'original_path'):
            known['known_refs'].append({**ref(Path(source[key])), 'kind': 'media'})
    known['known_ref_count'] = len(known['known_refs'])
    for candidate in known['public_work_candidates']:
        path = Path(candidate['path'])
        path.write_text('VALUE = "synthetic unrelated public candidate bytes"\n')
        candidate.update(ref(path))
        if 'original_reference' in candidate:
            original = Path(candidate['original_reference']['path'])
            original.write_bytes(path.read_bytes())
            candidate['original_reference'] = ref(original)
    first = known['public_work_candidates'][0]
    external_path = Path(known['unfollowed_refs'][1]['path'])
    external = write(external_path, {'value': 'Synthetic external reference bytes.'})
    known['unfollowed_refs'][0] = {k: first[k] for k in ('path', 'sha256', 'reason')}
    known['unfollowed_refs'][1].update(external)
    _, commands, _ = privacy._public_source_candidates(root, set(registered.values()))
    known['public_source_candidate_commands'] = commands
    rebound(context)
    authority_path = directory / 'authority/retention-root.json'
    authority = write(authority_path, context['selected'])
    locator = {'schema_version': 'review-text-origin/v1', 'kind': 'retention_inventory_field',
               'parent': ref(context['result']), 'selector': ['current_inventory', 'scope'], 'authority': authority}
    context.update(registered=registered, locator=locator, authority=authority, private_texts=texts,
                   selected_phrase=known['scope'], synthetic_metadata_only=True)
    return context


def observe(context: dict[str, Any], selected: bool) -> tuple[dict[str, str], list[str], dict[str, Any]]:
    return privacy._known_private_inventory(context['project'], context['registered'], context['root'],
        review_text_origins=[context['locator']] if selected else [],
        review_text_origin_authorities=[context['authority']] if selected else [])
