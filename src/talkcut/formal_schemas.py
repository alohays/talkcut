"""Explicit formal artifact policy; validator text does not declare artifact roles.

The legacy floor conservatively retains every schema reserved at the historical
compatibility boundary. Its presence does not assert that incidental old tokens
were semantically formal. New declarations need an explicit owner and role.
Changes to this module are public code-policy changes covered by code_identity.
"""
from __future__ import annotations

import ast
import hashlib
import json
import os
import re
import stat
from pathlib import Path
from typing import Any

from .project import TalkCutError

# Exact compatibility floor retained from the original reserved policy.
LEGACY_SCHEMA_TYPES: tuple[str, ...] = (
    'acceptance-index/v1',
    'acceptance-snapshot/v1',
    'acoustic-analysis/v1',
    'analysis-operation/v1',
    'artifact-audit/v1',
    'audio-processing/v1',
    'audio-sync-analysis/v1',
    'baseline-input/v1',
    'boundary-fixture/v1',
    'boundary-input/v1',
    'captured-ai-exchange/v1',
    'codex-cli-render/v1',
    'codex-cli-session/v1',
    'codex-debug-prompt-input/v1',
    'codex-session-slice/v1',
    'codex_cli_direct_images/v1',
    'composite-input/v1',
    'composite-registration-snapshot/v1',
    'composite-registration/v1',
    'composite-review-receipt/v1',
    'composite-review-recipe/v1',
    'composite-review-request/v1',
    'context-collection-operation/v1',
    'current_native_source_bytes/v1',
    'dgist-first-lecture/v1',
    'dgist-roundtrip/v1',
    'edit-plan/v1',
    'editorial-binding/v1',
    'editorial-execution-failure/v1',
    'editorial-expectations/v1',
    'editorial-fixture-input/v1',
    'editorial-fixture-validation/v1',
    'editorial-operation/v1',
    'editorial-preparation/v1',
    'editorial-process/v1',
    'editorial-snapshot/v1',
    'editorial-verification/v1',
    'evaluator-av-positive-controls/v2',
    'evaluator-av-positive/v2',
    'evaluator-av-probe-input/v2',
    'evaluator-negative-receipt/v1',
    'evaluator-negative-request/v1',
    'evaluator-negative-run/v1',
    'evaluator-positive-revalidation/v2',
    'execution-receipt/v1',
    'explicit_runtime_alias_rows/v1',
    'failure-input/v1',
    'failure-run/v1',
    'fixture-provenance/v1',
    'full-decode/v1',
    'goal-acceptance/v1',
    'goal-checkpoint/v1',
    'historical-source-tree-snapshot/v1',
    'historical-synthetic-harness/v1',
    'installed-package-probe/v1',
    'labelled-evaluator-counterfactual/v2',
    'lecture-context-collection/v1',
    'lecture-context/v1',
    'legacy_direct_runtime_refs/v1',
    'local-audio-calibration-request/v1',
    'measurement-check/v1',
    'measurement-result/v1',
    'measurement-run/v1',
    'mp4-geometry/v1',
    'multimodal-review/v1',
    'native-audio-execution/v1',
    'native-audio-request/v1',
    'native_integer_video_pts_and_mono_pcm16_16000_mov/v1',
    'negative-probe-response/v1',
    'negative-process/v1',
    'oss-verification/v1',
    'output-audio-anchor/v1',
    'output-sync-anchors/v1',
    'physical-pcm-execution/v1',
    'physical-pcm-observations/v1',
    'plan-operation/v1',
    'prepare-release/v1',
    'private-bounded-process-execution/v1',
    'private-codex-cli-run/v1',
    'private-exclusion-corpus/v1',
    'private-handoff/v1',
    'private-native-audio-case/v1',
    'private-native-audio-launch/v1',
    'private-native-audio-launch/v2',
    'private-native-audio-run/v1',
    'private-native-intake-candidate/v1',
    'private-native-probe-request/v1',
    'private-runtime-build/v1',
    'private-task-inventory/v1',
    'private-unregistered-native-policy-input/v1',
    'provider-control-transport/v1',
    'provider-failure-input/v1',
    'provider-failure-run/v1',
    'publication-privacy-input/v1',
    'publication-privacy-result/v1',
    'quality-failure/v1',
    'quality-input/v1',
    'recomputed-reproducibility/v1',
    'recovery-example/v1',
    'recovery-input/v1',
    'recovery-review-cycle/v1',
    'render-evidence/v1',
    'render-execution-failure/v1',
    'render-process/v1',
    'render/v1',
    'reproducibility-audit-snapshot/v1',
    'reproducibility-input/v1',
    'review-bundle/v1',
    'review-capability/v1',
    'review-extraction-failure/v1',
    'review-import/v1',
    'review-registration/v1',
    'review-request/v1',
    'source-analysis/v1',
    'source-difference-observations/v1',
    'source-inspection/v1',
    'source-output-quality/v1',
    'source-registration/v1',
    'source-window-native-intake/v1',
    'sync-import/v1',
    'sync-input/v1',
    'sync-model/v1',
    'synthetic-privacy-replay/v1',
    'talkcut-doctor/v1',
    'talkcut-error/v1',
    'talkcut-goal-handoff/v1',
    'talkcut-inspect/v1',
    'talkcut-native-intake/v1',
    'talkcut-project/v1',
    'talkcut-status/v1',
    'terminal-ai-execution/v1',
    'terminal-ai-request/v1',
    'terminal-review-context-policy/v1',
    'terminal-review-context/v1',
    'timeline/v1',
    'transcript/v1',
    'verification-command/v1',
    'workflow-input/v1',
    'workflow-qc/v1',
    'workflow-render/v1',
)
LEGACY_SCHEMA_TYPES_SHA256 = '8c50e9f7d9962db1a1d8dda2e64bb00d95d7dd23aa503e1f50f4e454c1e65360'

# These are declarations, including imported control contracts without writers.
# A comparison, grammar fixture or historical diagnostic is not a declaration.
FORMAL_SCHEMA_DECLARATIONS: tuple[dict[str, str], ...] = (
    {"schema": 'private-byte-preservation/v1', "owner": "talkcut.privacy_checks", "role": 'formal_artifact'},
    {"schema": 'review-json-schema-dialect-authority/v1', "owner": "talkcut.privacy_checks", "role": 'control_contract'},
    {"schema": 'review-machine-field-authority/v1', "owner": "talkcut.privacy_checks", "role": 'control_contract'},
    {"schema": 'review-text-origin/v1', "owner": "talkcut.privacy_checks", "role": 'control_contract'},
    {"schema": 'review-text-source-authority/v1', "owner": "talkcut.privacy_checks", "role": 'control_contract'},
    {"schema": 'review-verification-source-authority/v1', "owner": "talkcut.privacy_checks", "role": 'control_contract'},
)

# This is a finite coverage alarm, not Python execution or data-flow analysis.
_MAX_FILE_BYTES = 16 * 1024 * 1024
_MAX_POLICY_BYTES = 64 * 1024 * 1024
_MAX_POLICY_FILES = 512
_POLICY_CACHE: dict[str, tuple[tuple[Any, ...], frozenset[str]]] = {}


def _require(condition: bool) -> None:
    if not condition:
        raise TalkCutError("PUBLICATION_PRIVACY_UNVERIFIED", "Formal schema declarations are malformed or uncovered")


def _name(value: Any) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[a-z][a-z0-9_-]*/v[0-9]+", value) is not None


def _declarations(value: Any) -> dict[str, dict[str, str]]:
    _require(isinstance(value, tuple))
    result: dict[str, dict[str, str]] = {}
    for row in value:
        _require(isinstance(row, dict) and set(row) == {"schema", "owner", "role"})
        _require(_name(row["schema"]) and row["schema"] not in result and row["schema"] not in LEGACY_SCHEMA_TYPES)
        _require(isinstance(row["owner"], str)
                 and re.fullmatch(r"talkcut\.[a-z][a-z0-9_]*", row["owner"]) is not None)
        _require(isinstance(row["role"], str) and row["role"] in {"formal_artifact", "control_contract"})
        result[row["schema"]] = row
    return result


def _identity(path: Path) -> tuple[Any, ...]:
    info = path.lstat()
    _require(stat.S_ISREG(info.st_mode) and not path.is_symlink()
             and path == path.resolve() and info.st_size <= _MAX_FILE_BYTES)
    return (str(path), info.st_dev, info.st_ino, info.st_mode, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _files(repo: Path) -> tuple[tuple[Any, ...], ...]:
    paths: list[Path] = []
    visited = 0
    def unreadable(error: OSError) -> None:
        raise error
    for relative, suffix in (("src/talkcut", ".py"), ("schemas", ".json")):
        directory = repo / relative
        if directory.exists() or directory.is_symlink():
            _require(directory.is_dir() and directory == directory.resolve() and not directory.is_symlink())
            for parent, folders, files in os.walk(directory, followlinks=False, onerror=unreadable):
                visited += 1 + len(files)
                _require(visited <= _MAX_POLICY_FILES * 4)
                for name in folders:
                    folder = Path(parent) / name
                    _require(folder.is_dir() and not folder.is_symlink() and folder == folder.resolve())
                paths.extend(Path(parent) / name for name in sorted(files) if name.endswith(suffix))
    _require(len(paths) <= _MAX_POLICY_FILES)
    rows = tuple(_identity(path) for path in sorted(paths))
    _require(sum(row[4] for row in rows) <= _MAX_POLICY_BYTES)
    return rows


def _read(row: tuple[Any, ...]) -> bytes:
    path = Path(row[0])
    _require(_identity(path) == row)
    with path.open("rb") as stream:
        value = stream.read(row[4] + 1)
    _require(len(value) == row[4] and _identity(path) == row)
    return value


def _syntax(value: bytes) -> ast.Module:
    try:
        return ast.parse(value)
    except (ValueError, SyntaxError, UnicodeError, LookupError) as exc:
        raise TalkCutError("PUBLICATION_PRIVACY_UNVERIFIED", "Formal schema source is not valid Python bytes") from exc


def _literal(node: ast.AST) -> Any:
    # literal_eval alone discards duplicate dictionary keys.
    for child in ast.walk(node):
        if isinstance(child, ast.Dict):
            keys = [ast.literal_eval(key) if key is not None else None for key in child.keys]
            _require(all(isinstance(key, str) for key in keys) and len(keys) == len(set(keys)))
    return ast.literal_eval(node)


def _repo_declarations(tree: ast.Module) -> dict[str, dict[str, str]]:
    expected = {"LEGACY_SCHEMA_TYPES", "LEGACY_SCHEMA_TYPES_SHA256", "FORMAL_SCHEMA_DECLARATIONS"}
    assignments: dict[str, Any] = {}
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id in expected:
                    _require(target.id not in assignments and len(node.targets) == 1)
                    assignments[target.id] = _literal(node.value)
            _require(all(not any(isinstance(child, ast.Name) and child.id in expected for child in ast.walk(target))
                         or isinstance(target, ast.Name) and target.id in expected for target in node.targets))
        elif isinstance(node, ast.AnnAssign):
            if isinstance(node.target, ast.Name) and node.target.id in expected:
                _require(node.target.id not in assignments and node.value is not None)
                assert node.value is not None
                assignments[node.target.id] = _literal(node.value)
            else:
                _require(not any(isinstance(child, ast.Name) and child.id in expected for child in ast.walk(node.target)))
        # Repo policy is inert data; no top-level calls or mutation declarations.
        elif not isinstance(node, (ast.Import, ast.ImportFrom, ast.FunctionDef, ast.ClassDef)):
            _require(isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str))
    _require(set(assignments) == expected)
    _require(assignments["LEGACY_SCHEMA_TYPES"] == LEGACY_SCHEMA_TYPES
             and assignments["LEGACY_SCHEMA_TYPES_SHA256"] == LEGACY_SCHEMA_TYPES_SHA256)
    return _declarations(assignments["FORMAL_SCHEMA_DECLARATIONS"])


def _writer_types(tree: ast.Module) -> set[str]:
    constants: dict[str, list[ast.AST]] = {}
    for statement in tree.body:
        if isinstance(statement, ast.Assign):
            for target in statement.targets:
                if isinstance(target, ast.Name):
                    constants.setdefault(target.id, []).append(statement.value)
        elif isinstance(statement, ast.AnnAssign) and isinstance(statement.target, ast.Name) and statement.value is not None:
            constants.setdefault(statement.target.id, []).append(statement.value)
    values: set[str] = set()

    def output(node: ast.AST) -> None:
        if isinstance(node, ast.Name):
            matches = constants.get(node.id, [])
            stores = [item for item in ast.walk(tree)
                      if isinstance(item, ast.Name) and isinstance(item.ctx, ast.Store) and item.id == node.id]
            alternative_bindings = [item for item in ast.walk(tree)
                                    if isinstance(item, ast.arg) and item.arg == node.id
                                    or isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and item.name == node.id
                                    or isinstance(item, ast.alias) and (item.asname or item.name.split(".")[0]) == node.id]
            _require(len(matches) == len(stores) == 1 and not alternative_bindings)
            node = matches[0]
        _require(isinstance(node, ast.Constant) and _name(node.value))
        assert isinstance(node, ast.Constant) and isinstance(node.value, str)
        values.add(node.value)

    for node in ast.walk(tree):
        if isinstance(node, ast.Dict):
            for key, value in zip(node.keys, node.values, strict=True):
                if isinstance(key, ast.Constant) and key.value == "schema_version":
                    output(value)
        elif isinstance(node, ast.Call):
            for keyword in node.keywords:
                if keyword.arg == "schema_version":
                    output(keyword.value)
        elif isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for target in targets:
                if isinstance(target, ast.Subscript) and isinstance(target.slice, ast.Constant) and target.slice.value == "schema_version":
                    _require(node.value is not None)
                    assert node.value is not None
                    output(node.value)
    return values


def _schema_types(value: Any) -> set[str]:
    values: set[str] = set()
    if isinstance(value, dict):
        properties = value.get("properties")
        if isinstance(properties, dict) and "schema_version" in properties:
            declaration = properties["schema_version"]
            _require(isinstance(declaration, dict) and ("const" in declaration or "enum" in declaration))
            if "const" in declaration:
                _require(_name(declaration["const"]))
                values.add(declaration["const"])
            if "enum" in declaration:
                labels = declaration["enum"]
                _require(isinstance(labels, list) and bool(labels) and all(_name(label) for label in labels))
                _require(len(labels) == len(set(labels)))
                values.update(labels)
            if "const" in declaration and "enum" in declaration:
                _require(declaration["const"] in declaration["enum"])
        for child in value.values():
            values.update(_schema_types(child))
    elif isinstance(value, list):
        for child in value:
            values.update(_schema_types(child))
    return values


def _json(value: bytes) -> Any:
    def pairs(rows: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, child in rows:
            _require(key not in result)
            result[key] = child
        return result
    def invalid_constant(value: str) -> Any:
        _require(False)
    return json.loads(value, object_pairs_hook=pairs, parse_constant=invalid_constant)


def _validate_schema_coverage(repo: Path, declared: frozenset[str]) -> None:
    """Refuse undeclared supported output expressions and JSON Schema type fields.

    Supports literal dictionaries, keyword constructors, subscript assignments,
    and their single module string constants. Imported accepted types are
    protected by explicit declarations, independently of any local constructor.
    Unknown output expressions refuse; arbitrary Python data flow is not inferred.
    """
    rows = _files(repo)
    for row in rows:
        data = _read(row)
        values = _writer_types(_syntax(data)) if row[0].endswith(".py") else _schema_types(_json(data))
        _require(values <= declared)
    _require(_files(repo) == rows)


def validate_schema_coverage(repo: Path, declared: frozenset[str]) -> None:
    """Check bounded declared output coverage without executing repository code."""
    try:
        _validate_schema_coverage(repo, declared)
    except (OSError, ValueError, TypeError, RecursionError, SyntaxError) as exc:
        raise TalkCutError("PUBLICATION_PRIVACY_UNVERIFIED", "Formal schema declarations are malformed or uncovered") from exc


def formal_schema_types(repo: Path | None = None) -> frozenset[str]:
    """Installed policy is always the floor; inert repo policy can only extend it."""
    try:
        _require(isinstance(LEGACY_SCHEMA_TYPES, tuple) and all(_name(value) for value in LEGACY_SCHEMA_TYPES))
        _require(hashlib.sha256("\n".join(LEGACY_SCHEMA_TYPES).encode()).hexdigest() == LEGACY_SCHEMA_TYPES_SHA256)
        installed = _declarations(FORMAL_SCHEMA_DECLARATIONS)
        declared = frozenset(LEGACY_SCHEMA_TYPES) | frozenset(installed)
        if repo is None:
            return declared
        repo = repo.resolve(strict=True)
        rows = _files(repo)
        cache_key = str(repo)
        # Every read rechecks the complete bounded file set and physical identity.
        # Installed-policy edits also invalidate any repository coverage cache.
        stamp = (rows, tuple((name, tuple(sorted(row.items()))) for name, row in installed.items()))
        cached = _POLICY_CACHE.get(cache_key)
        if cached is not None and cached[0] == stamp:
            _require(_files(repo) == rows)
            return declared | cached[1]
        policy_path = repo / "src/talkcut/formal_schemas.py"
        policy_row = next((row for row in rows if row[0] == str(policy_path)), None)
        if policy_row is not None:
            supplied = _repo_declarations(_syntax(_read(policy_row)))
            _require(all(supplied.get(name) == row for name, row in installed.items()))
            declared |= frozenset(supplied)
            for declaration in supplied.values():
                owner = declaration["owner"].split(".", 1)[1] + ".py"
                _require((repo / "src/talkcut" / owner).is_file() or Path(__file__).with_name(owner).is_file())
        validate_schema_coverage(repo, declared)
        _require(_files(repo) == rows)
        if len(_POLICY_CACHE) >= 16:
            _POLICY_CACHE.clear()
        _POLICY_CACHE[cache_key] = (stamp, declared)
        return declared
    except (OSError, ValueError, TypeError, RecursionError, SyntaxError) as exc:
        raise TalkCutError("PUBLICATION_PRIVACY_UNVERIFIED", "Formal schema declarations are malformed or uncovered") from exc
