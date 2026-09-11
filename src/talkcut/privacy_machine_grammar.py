"""Closed syntax of historical inventory writers; no historical code is run."""

CANDIDATE = """
def collect_candidate(candidate_path: Path, original_ref: dict[str, Any], ref: dict[str, Any]) -> None:
    actual_path = _file(ref)
    candidate_body = None
    if actual_path.stat().st_size <= MAX_UNIT_BYTES:
        try:
            candidate_body = json.loads(actual_path.read_text())
        except (ValueError, UnicodeDecodeError):
            candidate_body = None
    if contains_transcript(candidate_body):
        add(candidate_path, 'transcript', ref['sha256'])
    else:
        role = body_candidates.get((str(candidate_path), ref['sha256']))
        candidate = {**ref, 'classification': 'UNCLASSIFIED', 'reason': BODY_REASON if role else CODE_REASON, 'matching_git_source_bytes': source_candidates.get(ref['sha256'], [])}
        if role:
            candidate['publication_role'] = role
        if ref is not original_ref:
            candidate['original_reference'] = original_ref
            candidate['preservation'] = PRESERVATION
        public_candidates[str(actual_path)] = candidate
        unfollowed.append({**ref, 'reason': candidate['reason']})
"""

WALK = """
def walk(value: Any, transcript: bool=False, key: str='') -> None:
    if key in {'toolchain', 'producer', 'code_identity', 'tools_before', 'tools_after'} and (not transcript) and (not contains_transcript(value)):
        return
    if isinstance(value, dict):
        transcript = transcript or explicit_transcript(value)
        if transcript:
            protect_values(value)
        if isinstance(value.get('path'), str) and isinstance(value.get('sha256'), str):
            path = Path(value['path'])
            code_or_archive = path.suffix.lower() in {'.py', '.pyi', '.pyc', '.so', '.dylib', '.whl'} or path.name.endswith('.tar.gz')
            kind = 'media' if value['sha256'] in digests else 'transcript' if transcript else 'media' if path.suffix.lower() in media_suffixes else 'review'
            canonical_path = path if path.is_absolute() else (repo_root or directory) / path
            transcript = transcript or value['sha256'] in git_transcripts
            if transcript and kind != 'media':
                kind = 'transcript'
            public_code = repo_root is not None and any((canonical_path.resolve() == (repo_root / origin['git_path']).resolve() for origin in source_candidates.get(value['sha256'], [])))
            fixture = fixture_claims.get((str(canonical_path), value['sha256']))
            if fixture is not None:
                _require(not transcript and value['sha256'] not in digests, 'Private source/transcript cannot use synthetic failure provenance')
                for actual_ref in (fixture['preserved_original'], fixture['actual_current']):
                    collect_candidate(Path(actual_ref['path']), actual_ref, actual_ref)
            elif transcript or value['sha256'] in known:
                add(canonical_path, kind if transcript else known[value['sha256']], value['sha256'], historical=True)
            elif not public_code and kind != 'media' and (code_or_archive or value['sha256'] in source_candidates or value['sha256'] in source_snapshot_hashes or ((str(canonical_path), value['sha256']) in body_candidates)):
                candidate_path = path if path.is_absolute() else (repo_root or directory) / path
                original_ref = {'path': str(candidate_path), 'sha256': value['sha256']}
                ref = source_locators.get((str(candidate_path), value['sha256']), original_ref)
                if ref is original_ref and str(candidate_path) in source_paths and (candidate_path == candidate_path.resolve()) and (not candidate_path.is_symlink()) and candidate_path.is_file() and (sha256(candidate_path) != value['sha256']):
                    _require(re.fullmatch('[a-f0-9]{64}', value['sha256']), 'Historical source digest is invalid')
                    unresolved_sources[str(candidate_path), value['sha256']] = {**original_ref, 'classification': 'UNCLASSIFIED', 'status': 'UNVERIFIED', 'current_ref': artifact_ref(candidate_path), 'reason': UNRESOLVED_REASON}
                else:
                    collect_candidate(candidate_path, original_ref, ref)
            elif not public_code and path.is_absolute() and (path.resolve().is_relative_to(directory) or value['sha256'] in digests or transcript):
                add(path, kind, value['sha256'], historical=True)
            elif not public_code:
                unfollowed.append({'path': value['path'], 'sha256': value['sha256'], 'reason': EXTERNAL_REASON})
        for child_key, child in value.items():
            walk(child, transcript, child_key)
    elif isinstance(value, list):
        for child in value:
            walk(child, transcript)
"""


# Canonical complete AST grammars, not caller-selected source digests.
# Paths/digest checks and final inventory fields are validated separately.
# Every other node, including all nested helper bodies, remains in each shape.
INVOCATION_SHAPES: dict[str, frozenset[str]] = {
    'module': frozenset({
        '0ed9e84b86a24a8abbc22e3cf70435d3ca7bf025577c421be8d5cad91284971c',
        '45744ded78fc8a1b182a342cf98c4d863ed0cb2167fc9a47eaec71eb41e866b3',
        'c13cf6ee4d653870daefd96efab749ddf46d18af79d09e28a74dce169b12d149',
        'c2e533092059b7f761874bb89012b23dd3a4a13518068ccb942a76ab34d2f613',
        'e486353e0679ec1c41ceaa55b5d25abeecd5aa3131dbd11d9ef05e22da963fa3',
    }),
    'known': frozenset({
        '0372c53001e8e75383169cbcafd2e04278d0803109d3bb5f5a9a20e4eb6815db',
        '09b6dc435cb77bc431f53bd0ab0671ca0ad6e4af1bbc4c96b8d46cca7303d762',
        '12a8024429af5b18aeb0f6d17ed1a92a081217fd6a8ae2815d4fd843279ed5ff',
        '32f1fb37ca90925f0cc9b1a1a1e1939c23d6de693b6f4a1dd7a0deb657134819',
        'd3655c723056b3524a6244c97ab223698ffefecd36f77c113464f6e40daa8562',
    }),
    'builder': frozenset({
        'f0b7b3a7f0e8d878cb29067e1aff3aa1eeb01593f022d18b81fbf4e002ed83dc',
    }),
    'scan': frozenset({
        '21f9eca48227a1bcf476ba2872b9f083d2b8e5c27402f48177921592968ca459',
        '459c817b40ac918d9e9fb46e8c2746440774b8a6323e1f4e21ed7cc9a426e308',
        '632bad0c19fcc1b5ed9a523bcbab021e08fdcf9e7b740331c391c83f5cfe1673',
    }),
    'helper': frozenset({
        '0f7c976c34c6b0a4930ddb07da5bcc6e0095471bfe7485f485afa95075ef18be',
    }),
    'probe': frozenset({
        '82c4c7043233cd1835d8991f1a280f65ee9f12351b7e235770ae7550cbcd9a92',
    }),
}
