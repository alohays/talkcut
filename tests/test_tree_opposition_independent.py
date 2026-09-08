"""Independent synthetic original Git objects; no project/private corpus data."""
import gzip
import hashlib
import io
import zipfile

import pytest
from test_privacy_git_structural import git, object_value, repository

from talkcut import privacy_checks as pc
from talkcut.project import TalkCutError


def obj(root, kind, data, algorithm):
    value = object_value(kind, data, algorithm)
    observed = git(root, 'hash-object', '-w', '-t', kind, '--stdin', data=data).decode().strip()
    assert observed == value.oid
    return value


def rec(mode, name, child):
    return mode.encode() + b' ' + name.encode() + b'\0' + bytes.fromhex(child.oid)


def scan(root, head, trees, phrases=(), private=None):
    for i, tree in enumerate(trees):
        git(root, 'update-ref', f'refs/opposition/tree-{i}', tree.oid)
    s = pc.Scan(private or {}, list(phrases))
    report = pc._git_inventory(root, head.oid, s, [])
    return s, report


def matches(scanner, phrase):
    digest = hashlib.sha256(phrase.encode()).hexdigest()
    return [r for r in scanner.findings if r.get('matched_sha256') == digest]


@pytest.mark.parametrize('algorithm', ['sha1', 'sha256'])
def test_shared_subtree_across_two_roots_preserves_distinct_full_paths(tmp_path, algorithm):
    root, _, _, head = repository(tmp_path, algorithm)
    leaf = obj(root, 'blob', b'Ordinary fixture leaf\n', algorithm)
    subtree = obj(root, 'tree', rec('100644', 'suffix', leaf), algorithm)
    first = obj(root, 'tree', rec('40000', 'alpha', subtree), algorithm)
    second = obj(root, 'tree', rec('40000', 'beta', subtree), algorithm)
    s, report = scan(root, head, [first, second], ['alpha/suffix', 'beta/suffix'])
    assert not s.unknown
    assert matches(s, 'alpha/suffix') and matches(s, 'beta/suffix')
    contexts = report['selected_tree_structures']
    assert {(x['root_oid'], x['path']) for x in contexts} == {
        (first.oid, ''), (first.oid, 'alpha'), (second.oid, ''), (second.oid, 'beta')}
    assert sum(r['sha256'] == hashlib.sha256(subtree.data).hexdigest() for r in s.units) == 1
    assert {x['oid'] for x in report['selected_ref_objects']}.issuperset({first.oid, second.oid, subtree.oid, leaf.oid})


@pytest.mark.parametrize('algorithm', ['sha1', 'sha256'])
@pytest.mark.parametrize('where', ['root', 'nested', 'leaf'])
@pytest.mark.parametrize('kind', ['review', 'transcript', 'credentials', 'media'])
def test_whole_private_digest_has_precedence_at_each_original_level(tmp_path, algorithm, where, kind):
    root, _, _, head = repository(tmp_path, algorithm)
    leaf = obj(root, 'blob', b'Complete synthetic private artifact\n', algorithm)
    nested = obj(root, 'tree', rec('100644', 'leaf', leaf), algorithm)
    top = obj(root, 'tree', rec('40000', 'branch', nested), algorithm)
    target = {'root': top, 'nested': nested, 'leaf': leaf}[where]
    digest = hashlib.sha256(target.data).hexdigest()
    s, report = scan(root, head, [top], private={digest: kind})
    assert any(f['kind'] == 'private_' + kind and f['sha256'] == digest for f in s.findings)
    assert all(c['oid'] != target.oid for c in report['selected_tree_structures'])
    assert {r['oid'] for r in report['selected_ref_objects']}.issuperset({top.oid, nested.oid, leaf.oid})


@pytest.mark.parametrize('ordinary_first', [False, True])
@pytest.mark.parametrize('envelope', ['zip', 'gzip', 'blob'])
def test_binary_tree_context_never_suppresses_ordinary_copy(tmp_path, ordinary_first, envelope):
    root, _, _, head = repository(tmp_path)
    leaf = obj(root, 'blob', b'Public fixture\n', 'sha1')
    tree = obj(root, 'tree', rec('100644', 'leaf', leaf), 'sha1')
    s = pc.Scan({}, [])
    if envelope == 'zip':
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, 'w') as z:
            z.writestr('git-ref-tree/' + tree.oid, tree.data)
        data = stream.getvalue()
    else:
        data = gzip.compress(tree.data) if envelope == 'gzip' else tree.data
    def ordinary():
        s.payload(data, 'ordinary-' + envelope)
    if ordinary_first:
        ordinary()
    git(root, 'update-ref', 'refs/opposition/tree', tree.oid)
    report = pc._git_inventory(root, head.oid, s, [])
    if not ordinary_first:
        ordinary()
    assert any(r['location'].startswith('ordinary-') for r in s.unknown)
    assert len(report['selected_tree_structures']) == 1
    assert sum(u['sha256'] == hashlib.sha256(tree.data).hexdigest() for u in s.units) == 1


@pytest.mark.parametrize('algorithm', ['sha1', 'sha256'])
def test_replacement_blob_does_not_hide_original_selected_leaf(tmp_path, algorithm):
    root, _, _, head = repository(tmp_path, algorithm)
    old_phrase = 'Synthetic original selected content remains protected.'
    new_phrase = 'Synthetic replacement content is independently protected.'
    original = obj(root, 'blob', old_phrase.encode(), algorithm)
    replacement = obj(root, 'blob', new_phrase.encode(), algorithm)
    tree = obj(root, 'tree', rec('100644', 'leaf', original), algorithm)
    git(root, 'update-ref', 'refs/replace/' + original.oid, replacement.oid)
    s, report = scan(root, head, [tree], [old_phrase, new_phrase])
    assert matches(s, old_phrase) and matches(s, new_phrase) and not s.unknown
    assert {r['oid'] for r in report['selected_ref_objects']}.issuperset({original.oid, replacement.oid, tree.oid})


@pytest.mark.parametrize('algorithm', ['sha1', 'sha256'])
def test_symlink_submodule_and_empty_private_directory_remain_explicit(tmp_path, algorithm):
    root, empty, _, head = repository(tmp_path, algorithm)
    phrase = 'Synthetic literal symlink target is protected.'
    link = obj(root, 'blob', phrase.encode(), algorithm)
    tree = obj(root, 'tree', rec('40000', '.env', empty) + rec('120000', 'link', link) + rec('160000', 'submodule', head), algorithm)
    s, report = scan(root, head, [tree], [phrase])
    assert matches(s, phrase)
    reasons = [r['reason'] for r in s.unknown]
    assert any('Private project/environment' in r for r in reasons)
    assert any('symlink' in r for r in reasons)
    assert any('submodule' in r for r in reasons)
    assert {e['path'] for c in report['selected_tree_structures'] for e in c['entries']} == {'.env', 'link', 'submodule'}


@pytest.mark.parametrize('algorithm', ['sha1', 'sha256'])
@pytest.mark.parametrize('fault', ['wrong_kind', 'missing', 'listing_duplicate'])
def test_original_typed_child_or_complete_listing_failure_is_unverified(tmp_path, monkeypatch, algorithm, fault):
    root, _, _, head = repository(tmp_path, algorithm)
    leaf = obj(root, 'blob', b'Fixture leaf\n', algorithm)
    child = obj(root, 'tree', rec('100644', 'leaf', leaf), algorithm)
    top = obj(root, 'tree', rec('40000', 'directory', child), algorithm)
    original_command = pc._command
    fired = []
    def command(argv, cwd, traces, **kwargs):
        data = original_command(argv, cwd, traces, **kwargs)
        if fault == 'wrong_kind' and argv[-3:] == ['cat-file', '-t', child.oid]:
            fired.append(True)
            return b'blob\n'
        if fault == 'missing' and argv[-3:] == ['cat-file', 'tree', child.oid]:
            fired.append(True)
            return data[:-1]
        if fault == 'listing_duplicate' and argv[-5:] == ['ls-tree', '-r', '-z', '--full-tree', top.oid]:
            fired.append(True)
            return data + data
        return data
    monkeypatch.setattr(pc, '_command', command)
    s, report = scan(root, head, [top])
    assert fired == [True]
    assert any('structural inspection failed' in x['reason'] for x in s.unknown)
    assert not report['selected_tree_structures']
    assert any(x['oid'] == top.oid for x in report['selected_ref_objects'])


@pytest.mark.parametrize('limit,valid', [('depth', True), ('depth', False), ('path_bytes', True), ('path_bytes', False), ('entries', True), ('entries', False)])
def test_exact_traversal_bound_and_one_beyond(monkeypatch, limit, valid):
    leaf = object_value('blob', b'fixture')
    branch = object_value('tree', rec('100644', 'leaf', leaf))
    root = object_value('tree', rec('40000', 'dir', branch))
    values = {x.oid: x for x in (leaf, branch, root)}
    budget = {'depth': ('MAX_GIT_TREE_DEPTH', 1), 'path_bytes': ('MAX_TOTAL_BYTES', 3 + 8), 'entries': ('MAX_UNITS', 2)}
    name, exact = budget[limit]
    monkeypatch.setattr(pc, name, exact if valid else exact - 1)
    s = pc.Scan({}, [])
    listing = f'100644 blob {leaf.oid}\tdir/leaf\0'.encode()
    if valid:
        pc._selected_tree_inventory(root, s, lambda oid, kind: values[oid], lambda value: None, listing)
        # Unit/byte limits also govern Scan. Traversal context is only expected
        # when that independent inherited scanner budget was not exhausted.
        assert not any('structural inspection failed' in r['reason'] for r in s.unknown)
    else:
        with pytest.raises(TalkCutError):
            pc._selected_tree_inventory(root, s, lambda oid, kind: values[oid], lambda value: None, listing)
        assert not s.git_tree_structural
