"""Closed source-derived metadata does not exempt private prose or transcripts."""
import ast
import copy
import json
import sys
from pathlib import Path

import pytest
from test_privacy_checks import commit, git, publication_input
from test_privacy_replay import project

from talkcut import privacy_checks as privacy
from talkcut.project import TalkCutError, artifact_ref, atomic_json

PHRASE = "test_generated_origin_definition_is_long_and_independently_bound"
PROSE = "This separate authored private review rationale must remain protected in every observation."


def fixture(tmp_path, kind="python_inspection"):
    root = tmp_path / "repository"
    root.mkdir()
    git(root, "init", "--initial-branch=main")
    relative = "tests/test_generated.py" if kind == "python_inspection" else "docs/generated.md"
    source = root / relative
    source.parent.mkdir()
    content = (f"def {PHRASE}():\n    return 1\n" if kind == "python_inspection"
               else "# Generated documentation\n\n" + PHRASE + "\n\nAnother paragraph.\n")
    source.write_text(content)
    commit(root)
    preserved = tmp_path / "preserved-source.txt"
    preserved.write_text(content)
    directory, registered = project(tmp_path)
    parent = directory / "audits" / "origin.json"
    parent.parent.mkdir()
    row = {"path": str(source), "sha256": artifact_ref(source)["sha256"], "utf8_bytes": len(content.encode()),
           "is_symlink": False, "imports": [], "functions": [PHRASE], "asset_creation_calls": []}
    value = ({"schema_version": "independent-oss-inspection/v1", "public_files": [row], "reason": PROSE}
             if kind == "python_inspection" else
             {"schema_version": "artifact-audit-response/v1", "documentation_reviews": [
                 {"path": str(source), "sha256": artifact_ref(source)["sha256"],
                  "claims": [{"quote": PHRASE, "reason": PROSE, "disposition": "UNVERIFIED"}]}]})
    atomic_json(parent, value)
    locator = {"schema_version": "review-text-origin/v1", "kind": kind, "parent": artifact_ref(parent),
               "selector": ["public_files", 0] if kind == "python_inspection" else ["documentation_reviews", 0, "claims", 0, "quote"],
               "source": {"original_path": str(source), "snapshot": artifact_ref(preserved),
                          "git_revision": git(root, "rev-parse", "HEAD"), "git_path": relative,
                          "git_blob": git(root, "rev-parse", "HEAD:" + relative)}}
    if kind == "document_paragraph":
        locator["paragraph_index"] = 1
    atomic_json(directory / "checkpoint.local.json", {"source_sha256": registered["screen"], "ref": artifact_ref(parent)})
    parts = root, directory, registered, parent, locator
    authorize(parts)
    return parts


def authorize(parts):
    """Explicit synthetic authority root; never an actual independent audit claim."""
    root, directory, _, parent, locator = parts
    folder = directory / "authority"
    folder.mkdir(exist_ok=True)
    source = locator["source"]
    files = {source["git_path"]: source["snapshot"]["sha256"]}
    identity = {"code_revision": source["git_revision"], "files": files, "code_tree_hash": privacy.object_hash(files)}
    before = {"code_identity": identity, "documentation_example_files": {}, "documentation_example_hash": privacy.object_hash({})}
    atomic_json(folder / "verification.json", {"schema_version": "oss-verification/v1", "repo_root": str(root), "before": before, "after": before})
    verification = artifact_ref(folder / "verification.json")
    deps = {"code_tree_hash": identity["code_tree_hash"], "documentation_example_hash": before["documentation_example_hash"],
            "verification_hash": verification["sha256"]}
    inputs = [{"path": source["original_path"], "sha256": source["snapshot"]["sha256"]}]
    atomic_json(folder / "snapshot.json", {"schema_version": "reproducibility-audit-snapshot/v1", "verification": verification,
                                           "dependencies": deps, "input_refs": inputs})
    snapshot = artifact_ref(folder / "snapshot.json")
    atomic_json(folder / "request.json", {"schema_version": "artifact-audit-request/v1", "scope": "reproducibility_license_support",
                                          "reviewer_role": "independent_auditor", "reviewer_task_id": "synthetic-unit-task",
                                          "snapshot_hash": snapshot["sha256"], "dependencies": deps, "input_artifacts": [snapshot, *inputs]})
    request = artifact_ref(folder / "request.json")
    producer = folder / "producer.py"
    producer.write_text("public = {**report['before']['code_identity']['files'], **report['before']['documentation_example_files']}\n")
    inspection_path = parent if locator["kind"] == "python_inspection" else folder / "inspection.json"
    response_path = parent if locator["kind"] != "python_inspection" else folder / "response.json"
    inspection = json.loads(inspection_path.read_bytes()) if inspection_path.exists() else {"schema_version": "independent-oss-inspection/v1"}
    if "public_files" not in inspection:
        inspection["public_files"] = [{"path": source["original_path"], "sha256": source["snapshot"]["sha256"],
                                      "utf8_bytes": Path(source["snapshot"]["path"]).stat().st_size, "is_symlink": False}]
    inspection.update({"request": request, "snapshot": snapshot,
                       "inspected_artifacts": [{**ref, "bytes": Path(ref["path"]).stat().st_size} for ref in [snapshot, *inputs]]})
    atomic_json(inspection_path, inspection)
    stdout = folder / "stdout.jsonl"
    atomic_json(stdout, {"stage": "inspection_completed_without_issuing_audit_verdict", "result": artifact_ref(inspection_path)})
    stderr = folder / "stderr.log"
    stderr.write_text("")
    atomic_json(folder / "execution.json", {"schema_version": "independent-audit-command/v1", "argv": [str(Path(sys.executable)), "-I", "-B", str(producer)],
                                            "cwd": str(root), "exit_code": 0, "started_at": "synthetic-start", "finished_at": "synthetic-end",
                                            "wall_seconds": 0.0, "stdout": artifact_ref(stdout), "stderr": artifact_ref(stderr)})
    execution = artifact_ref(folder / "execution.json")
    response = json.loads(response_path.read_bytes()) if response_path.exists() else {"schema_version": "artifact-audit-response/v1"}
    response.update({"inspection": artifact_ref(inspection_path), "actual_inspection_execution": execution})
    atomic_json(response_path, response)
    authority = {"schema_version": "review-text-source-authority/v1", "inspection": artifact_ref(inspection_path), "request": request,
                 "snapshot": snapshot, "verification": verification, "execution": execution,
                 "producer": artifact_ref(producer), "response": artifact_ref(response_path)}
    atomic_json(folder / "root.json", authority)
    locator["authority"] = artifact_ref(folder / "root.json")
    locator["parent"] = artifact_ref(parent)
    atomic_json(directory / "checkpoint.local.json", {"ref": artifact_ref(parent)})


def observe(parts, locators=None):
    root, directory, registered, _, locator = parts
    return privacy._known_private_inventory(directory, registered, root,
                                             review_text_origins=[locator] if locators is None else locators,
                                             review_text_origin_authorities=[] if locators == [] else [locator["authority"]])


@pytest.mark.parametrize("kind", ["python_inspection", "document_paragraph"])
def test_actual_git_bound_fields_preserve_private_hashes_and_every_entry(tmp_path, kind):
    parts = fixture(tmp_path, kind)
    root, directory, registered, parent, locator = parts
    known_before, phrases_before, _ = observe(parts, [])
    known_after, phrases_after, graph = observe(parts)
    assert PHRASE in phrases_before and PHRASE not in phrases_after
    assert PROSE in phrases_after and all(known_after[k] == v for k, v in known_before.items())
    assert known_after[artifact_ref(parent)["sha256"]] == "review"
    assert graph["review_text_origins"][0]["claim_status"] == "UNVERIFIED"
    before = privacy.build_private_inventory(directory, registered, root)
    after = privacy.build_private_inventory(directory, registered, root, review_text_origins=[locator], review_text_origin_authorities=[locator["authority"]],
                                            archive_dir=tmp_path / "archive")
    old = {r["path"]: r for r in before["entries"]}
    new = {r["path"]: r for r in after["entries"]}
    assert all(new[name] == row for name, row in old.items())
    assert len(new) >= len(old) and not after["unresolved"]
    assert new[locator["source"]["snapshot"]["path"]]["classification"] == "UNCLASSIFIED"
    preserved = after["preserved_private_inputs"][str(parent)]
    assert artifact_ref(Path(preserved["path"])) == preserved and preserved["sha256"] == artifact_ref(parent)["sha256"]


@pytest.mark.parametrize("kind", ["python_inspection", "document_paragraph"])
@pytest.mark.parametrize("origin", ["same_parent_reason", "separate_review", "transcript"])
def test_any_unverified_or_transcript_origin_keeps_the_phrase(tmp_path, kind, origin):
    parts = fixture(tmp_path, kind)
    _, directory, registered, parent, locator = parts
    if origin == "same_parent_reason":
        value = json.loads(parent.read_bytes())
        value["reason"] = PHRASE
        atomic_json(parent, value)
        locator["parent"] = artifact_ref(parent)
        atomic_json(directory / "checkpoint.local.json", {"ref": artifact_ref(parent)})
    else:
        target = directory / ("transcripts" if origin == "transcript" else "evidence") / "other.json"
        target.parent.mkdir()
        atomic_json(target, {"schema_version": "transcript/v1" if origin == "transcript" else "private-review/v1",
                             "source_sha256": registered["screen"], "text": PHRASE})
    if origin == "same_parent_reason":
        authorize(parts)
    _, phrases, _ = observe(parts)
    assert PHRASE in phrases
    scan = privacy.Scan({}, phrases)
    scan.payload(PHRASE.encode(), "public-counterfactual")
    assert any(row["kind"] == "protected_transcript_phrase" for row in scan.findings)


@pytest.mark.parametrize("mutation", ["kind", "extra", "selector_bool", "selector_float", "selector_string", "selector_negative",
                                      "selector_wrong", "selector_absent", "revision", "blob", "path_traversal", "path_alias",
                                      "snapshot_hash", "source_path", "source_extra", "parent_hash", "parent_extra_ref"])
def test_forged_or_stale_origin_authority_is_rejected(tmp_path, mutation):
    parts = fixture(tmp_path)
    row = parts[-1]
    if mutation == "kind":
        row["kind"] = "reason_literal"
    elif mutation == "extra":
        row["approved"] = True
    elif mutation.startswith("selector_"):
        row["selector"] = {"selector_bool": ["public_files", True], "selector_float": ["public_files", 0.0],
                           "selector_string": ["public_files", "0"], "selector_negative": ["public_files", -1],
                           "selector_wrong": ["reason", 0], "selector_absent": ["public_files", 100]}[mutation]
    elif mutation == "revision":
        row["source"]["git_revision"] = "0" * 40
    elif mutation == "blob":
        row["source"]["git_blob"] = "0" * 40
    elif mutation == "path_traversal":
        row["source"]["git_path"] = "tests/../tests/test_generated.py"
    elif mutation == "path_alias":
        original = Path(row["source"]["snapshot"]["path"])
        alias = original.with_name("alias")
        alias.symlink_to(original)
        row["source"]["snapshot"]["path"] = str(alias)
    elif mutation == "snapshot_hash":
        row["source"]["snapshot"]["sha256"] = "0" * 64
    elif mutation == "source_path":
        row["source"]["original_path"] += ".other"
    elif mutation == "source_extra":
        row["source"]["public"] = True
    elif mutation == "parent_hash":
        row["parent"]["sha256"] = "0" * 64
    else:
        row["parent"]["bytes"] = 1
    with pytest.raises(TalkCutError):
        observe(parts)


@pytest.mark.parametrize("mutation", ["functions", "imports", "asset_creation_calls", "utf8_bytes", "is_symlink", "extra", "schema", "transcript"])
def test_rehashed_parent_cannot_forge_full_extraction_row(tmp_path, mutation):
    parts = fixture(tmp_path)
    parent, locator = parts[-2:]
    value = json.loads(parent.read_bytes())
    if mutation in {"functions", "imports", "asset_creation_calls"}:
        value["public_files"][0][mutation].append(PROSE)
    elif mutation == "utf8_bytes":
        value["public_files"][0][mutation] += 1
    elif mutation == "is_symlink":
        value["public_files"][0][mutation] = 0
    elif mutation == "extra":
        value["public_files"][0]["private_reason"] = PROSE
    elif mutation == "schema":
        value["schema_version"] = "source-review/v1"
    else:
        value["other"] = {"schema_version": "transcript/v1", "text": PHRASE}
    atomic_json(parent, value)
    locator["parent"] = artifact_ref(parent)
    authorize(parts)
    with pytest.raises(TalkCutError):
        observe(parts)


@pytest.mark.parametrize("mutation", ["quote", "paragraph_bool", "paragraph_other", "document_hash", "selector_reason"])
def test_document_quote_requires_its_exact_declared_paragraph(tmp_path, mutation):
    parts = fixture(tmp_path, "document_paragraph")
    parent, locator = parts[-2:]
    value = json.loads(parent.read_bytes())
    if mutation == "quote":
        value["documentation_reviews"][0]["claims"][0]["quote"] = PHRASE[:-1]
    elif mutation == "document_hash":
        value["documentation_reviews"][0]["sha256"] = "0" * 64
    elif mutation == "selector_reason":
        locator["selector"][-1] = "reason"
    else:
        locator["paragraph_index"] = True if mutation == "paragraph_bool" else 0
    atomic_json(parent, value)
    locator["parent"] = artifact_ref(parent)
    authorize(parts)
    with pytest.raises(TalkCutError):
        observe(parts)


def test_duplicate_locator_and_duplicate_json_are_not_silent(tmp_path):
    parts = fixture(tmp_path)
    with pytest.raises(TalkCutError, match="duplicated"):
        observe(parts, [parts[-1], copy.deepcopy(parts[-1])])
    parent = parts[-2]
    data = parent.read_text()
    parent.write_text(data.replace('{"', '{"schema_version":"forged","', 1))
    parts[-1]["parent"] = artifact_ref(parent)
    with pytest.raises(TalkCutError, match="duplicate|bounded JSON|changed|differs"):
        observe(parts)


def test_source_equality_does_not_exempt_unmapped_machine_diagnostics(tmp_path):
    parts = fixture(tmp_path)
    parent, locator = parts[-2:]
    value = json.loads(parent.read_bytes())
    value["diagnostic"] = PHRASE
    atomic_json(parent, value)
    locator["parent"] = artifact_ref(parent)
    atomic_json(parts[1] / "checkpoint.local.json", {"ref": artifact_ref(parent)})
    authorize(parts)
    assert PHRASE in observe(parts)[1]


def test_bound_historical_source_copy_does_not_read_new_checkout_content(tmp_path):
    parts = fixture(tmp_path)
    Path(parts[-1]["source"]["original_path"]).write_text("# Changed current worktree bytes\n")
    _, phrases, _ = observe(parts)
    assert PHRASE not in phrases and PROSE in phrases


def test_fixed_parser_and_public_scan_bounds_are_unchanged():
    assert privacy.MAX_UNIT_BYTES == 16 * 1024 * 1024
    assert privacy.MAX_TOTAL_BYTES == 256 * 1024 * 1024
    assert ast.parse(Path(privacy.__file__).read_text())


@pytest.mark.parametrize("kind", ["python_inspection", "document_paragraph"])
def test_observation_cannot_replace_a_frozen_authority_parent(tmp_path, kind):
    parts = fixture(tmp_path, kind)
    parent, locator = parts[-2:]
    value = json.loads(parent.read_bytes())
    value["invented_provenance"] = PHRASE
    changed = parent.with_name("rehashed-copy.json")
    atomic_json(changed, value)
    locator["parent"] = artifact_ref(changed)
    with pytest.raises(TalkCutError, match="separately frozen authority"):
        observe(parts)


@pytest.mark.parametrize("mutation", ["absent", "unregistered_copy", "changed_bytes", "duplicate", "unused"])
def test_authority_roots_are_separate_complete_and_immutable(tmp_path, mutation):
    root, directory, sources, _, locator = fixture(tmp_path)
    authorities = [locator["authority"]]
    if mutation == "absent":
        authorities = []
    elif mutation == "unregistered_copy":
        copied = tmp_path / "unregistered-root.json"
        copied.write_bytes(Path(locator["authority"]["path"]).read_bytes())
        locator["authority"] = artifact_ref(copied)
    elif mutation == "changed_bytes":
        Path(locator["authority"]["path"]).write_text('{}')
    elif mutation == "duplicate":
        authorities *= 2
    else:
        with pytest.raises(TalkCutError, match="no occurrence"):
            privacy._review_text_origin_inventory([], directory, root, set(sources.values()), authorities)
        return
    with pytest.raises(TalkCutError):
        privacy._review_text_origin_inventory([locator], directory, root, set(sources.values()), authorities)


@pytest.mark.parametrize("kind", ["python_inspection", "document_paragraph"])
def test_new_public_copy_cannot_replace_original_source_authority(tmp_path, kind):
    root, _, _, _, locator = parts = fixture(tmp_path, kind)
    source = Path(locator["source"]["original_path"])
    source.write_text(source.read_text() + "\n# " + PROSE + "\n")
    commit(root, "New counterfactual public copy, not original audit source")
    copied = tmp_path / "new-source-copy.txt"
    copied.write_bytes(source.read_bytes())
    locator["source"].update({"snapshot": artifact_ref(copied), "git_revision": git(root, "rev-parse", "HEAD"),
                              "git_blob": git(root, "rev-parse", "HEAD:" + locator["source"]["git_path"])})
    with pytest.raises(TalkCutError, match="original request and verification"):
        observe(parts)


@pytest.mark.parametrize("mutation", ["snapshot", "request", "verification", "execution", "producer", "response", "inspection"])
def test_every_frozen_root_edge_refuses_replacement_bytes(tmp_path, mutation):
    parts = fixture(tmp_path)
    authority = json.loads(Path(parts[-1]["authority"]["path"]).read_bytes())
    selected = Path(authority[mutation]["path"])
    selected.write_bytes(selected.read_bytes() + b"\n")
    with pytest.raises(TalkCutError, match="changed"):
        observe(parts)


def test_duplicate_keys_in_authority_root_are_rejected(tmp_path):
    parts = fixture(tmp_path)
    locator = parts[-1]
    path = Path(locator["authority"]["path"])
    path.write_text(path.read_text().replace('{"', '{"schema_version":"forged","', 1))
    locator["authority"] = artifact_ref(path)
    with pytest.raises(TalkCutError, match="duplicate|bounded JSON"):
        observe(parts)


@pytest.mark.parametrize("mutation", ["none", "truncated", "extra_prose", "private_duplicate"])
def test_complete_document_recipe_is_exact_and_private_duplicates_win(tmp_path, mutation):
    parts = fixture(tmp_path, "document_paragraph")
    parent, locator = parts[-2:]
    document = Path(locator["source"]["snapshot"]["path"]).read_text().strip()
    value = json.loads(parent.read_bytes())
    quote = document[:-1] if mutation == "truncated" else document + "\n" + PROSE if mutation == "extra_prose" else document
    value["documentation_reviews"][0]["claims"][0]["quote"] = quote
    if mutation == "private_duplicate":
        value["private_reason"] = document
    locator["kind"] = "document_complete"
    locator.pop("paragraph_index")
    atomic_json(parent, value)
    authorize(parts)
    if mutation in {"truncated", "extra_prose"}:
        with pytest.raises(TalkCutError, match="exact complete source document"):
            observe(parts)
    else:
        _, phrases, _ = observe(parts)
        assert (document in phrases) == (mutation == "private_duplicate")
        assert PROSE in phrases


@pytest.mark.parametrize("kind", ["review", "transcript", "media", "credentials"])
def test_explicit_private_corpus_source_cannot_authorize_an_extraction(tmp_path, kind):
    parts = fixture(tmp_path)
    root, directory, registered, _, locator = parts
    raw_ref = publication_input(root, tmp_path)
    raw_path = Path(raw_ref["path"])
    raw = json.loads(raw_path.read_bytes())
    corpus_path = Path(raw["private_corpus"]["path"])
    corpus = json.loads(corpus_path.read_bytes())
    corpus["file_hashes"].append({"sha256": locator["source"]["snapshot"]["sha256"], "kind": kind})
    atomic_json(corpus_path, corpus)
    raw.update(private_corpus=artifact_ref(corpus_path), review_text_origins=[locator],
               review_text_origin_authorities=[locator["authority"]])
    atomic_json(raw_path, raw)
    with pytest.raises(TalkCutError, match="Explicit or audited private corpus bytes"):
        privacy.verify_release_privacy(artifact_ref(raw_path), root, project_dir=directory, expected_source_hashes=registered)


@pytest.mark.parametrize("malformed", [None, 1, "row", []])
def test_malformed_inspected_input_row_is_typed_refusal(tmp_path, malformed):
    parts = fixture(tmp_path)
    parent = parts[-2]
    value = json.loads(parent.read_bytes())
    value["inspected_artifacts"][0] = malformed
    atomic_json(parent, value)
    locator = parts[-1]
    authority_path = Path(locator["authority"]["path"])
    authority = json.loads(authority_path.read_bytes())
    authority["inspection"] = artifact_ref(parent)
    atomic_json(authority_path, authority)
    locator.update(parent=artifact_ref(parent), authority=artifact_ref(authority_path))
    # Rebind the response's inspection edge only so the malformed original input
    # row reaches its own production predicate, not an earlier stale reference.
    response_path = Path(authority["response"]["path"])
    response = json.loads(response_path.read_bytes())
    response["inspection"] = artifact_ref(parent)
    atomic_json(response_path, response)
    authority["response"] = artifact_ref(response_path)
    atomic_json(authority_path, authority)
    locator["authority"] = artifact_ref(authority_path)
    with pytest.raises(TalkCutError, match="omits or replaces original input rows"):
        observe(parts)
