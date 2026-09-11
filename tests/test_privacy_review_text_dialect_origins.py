"""Fixed offline dialect metadata remains separate from all private prose."""
import json
from pathlib import Path

import pytest
from test_privacy_replay import project
from test_privacy_review_text_origins import observe

from talkcut import privacy_checks as privacy
from talkcut.project import TalkCutError, artifact_ref, atomic_json

URI = "https://json-schema.org/draft/2020-12/schema"


def fixture(tmp_path):
    root = tmp_path / "repository"
    root.mkdir()
    directory, registered = project(tmp_path)
    parent = directory / "audits" / "schema.json"
    parent.parent.mkdir()
    atomic_json(parent, {"$schema": URI, "type": "object", "properties": {"value": {"type": "string"}}})
    locator = {"schema_version": "review-text-origin/v1", "kind": "json_schema_dialect",
               "parent": artifact_ref(parent), "selector": ["$schema"]}
    parts = root, directory, registered, parent, locator
    rebind(parts)
    return parts


def rebind(parts):
    _, directory, _, parent, locator = parts
    authority = directory / "dialect-authority.json"
    atomic_json(authority, {"schema_version": "review-json-schema-dialect-authority/v1", "parent": artifact_ref(parent)})
    locator.update(parent=artifact_ref(parent), authority=artifact_ref(authority))
    atomic_json(directory / "checkpoint.local.json", {"ref": artifact_ref(parent)})


def test_supported_dialect_preserves_every_private_file_and_vocabulary_dependency(tmp_path):
    parts = fixture(tmp_path)
    root, directory, registered, parent, locator = parts
    before = privacy.build_private_inventory(directory, registered, root)
    _, old, _ = observe(parts, [])
    _, new, graph = observe(parts)
    assert URI in old and URI not in new
    observation = graph["review_text_origins"][0]
    assert observation["extractions"] == [{"edge": ["$schema"], "value": URI}]
    assert observation["claim_status"] == "UNVERIFIED" and observation["commands"] == []
    after = privacy.build_private_inventory(directory, registered, root, review_text_origins=[locator],
                                            review_text_origin_authorities=[locator["authority"]])
    rows = {r["path"]: r for r in after["entries"]}
    assert all(rows[row["path"]] == row for row in before["entries"])
    assert all(ref["path"] in rows for ref in observation["authority_refs"])
    assert rows[str(parent)]["classification"] == "review"
    assert len([ref for ref in observation["authority_refs"] if "/draft202012/" in ref["path"]]) > 1


@pytest.mark.parametrize("where", ["description", "const", "nested_schema", "separate_review", "transcript"])
def test_dialect_does_not_remove_any_other_origin(tmp_path, where):
    parts = fixture(tmp_path)
    _, directory, registered, parent, _ = parts
    if where in {"description", "const", "nested_schema"}:
        value = json.loads(parent.read_bytes())
        if where == "nested_schema":
            value["properties"]["value"]["$schema"] = URI
        else:
            value[where] = URI
        atomic_json(parent, value)
        rebind(parts)
    else:
        target = directory / ("transcripts" if where == "transcript" else "evidence") / "other.json"
        target.parent.mkdir()
        atomic_json(target, {"schema_version": "transcript/v1" if where == "transcript" else "private-review/v1",
                             "source_sha256": registered["screen"], "text": URI})
    _, phrases, _ = observe(parts)
    assert URI in phrases


@pytest.mark.parametrize("mutation", ["invalid_type", "unknown_dialect", "fragment", "missing", "duplicate_json", "extra_authority",
                                      "wrong_parent", "alias", "wrong_selector", "duplicate_selector", "transcript_context"])
def test_malformed_unscoped_or_forged_dialect_is_refused(tmp_path, mutation):
    parts = fixture(tmp_path)
    _, _, _, parent, locator = parts
    value = json.loads(parent.read_bytes())
    if mutation in {"invalid_type", "unknown_dialect", "fragment", "missing", "transcript_context"}:
        if mutation == "invalid_type":
            value["type"] = 27
        elif mutation == "unknown_dialect":
            value["$schema"] = "https://private.invalid/schema"
        elif mutation == "fragment":
            value["$schema"] += "#"
        elif mutation == "missing":
            del value["$schema"]
        else:
            value["schema_version"] = "transcript/v1"
        atomic_json(parent, value)
        rebind(parts)
    elif mutation == "duplicate_json":
        parent.write_text('{"$schema": "' + URI + '", "$schema": "' + URI + '"}')
        rebind(parts)
    elif mutation == "extra_authority":
        target = Path(locator["authority"]["path"])
        authority = json.loads(target.read_bytes())
        authority["approved"] = True
        atomic_json(target, authority)
        locator["authority"] = artifact_ref(target)
    elif mutation == "wrong_parent":
        copied = parent.with_name("same-bytes.json")
        copied.write_bytes(parent.read_bytes())
        locator["parent"] = artifact_ref(copied)
    elif mutation == "alias":
        alias = parent.with_name("alias.json")
        alias.symlink_to(parent)
        locator["parent"]["path"] = str(alias)
    elif mutation == "wrong_selector":
        locator["selector"] = ["properties", "value", "$schema"]
    with pytest.raises(TalkCutError):
        observe(parts, [locator, locator] if mutation == "duplicate_selector" else None)
