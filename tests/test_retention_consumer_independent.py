"""Consumer boundary checks on a materialized synthetic retention report."""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from retention_consumer_fixture import consumer_fixture, observe
from retention_fixture import rebound, ref, write

from talkcut import privacy_checks as privacy
from talkcut.project import TalkCutError, atomic_json


def rebind(context):
    rebound(context)
    context["authority"] = write(Path(context["authority"]["path"]), context["selected"])
    context["locator"]["authority"] = context["authority"]
    context["locator"]["parent"] = ref(context["result"])


@pytest.mark.parametrize("variant", [0, 1])
def test_retention_full_parent_archive_and_transcript_denominator(tmp_path, variant):
    context = consumer_fixture(tmp_path, variant)
    parent = ref(context["result"])
    before = context["result"].read_bytes()
    result = privacy.build_private_inventory(
        context["project"], context["registered"], context["root"],
        review_text_origins=[context["locator"]],
        review_text_origin_authorities=[context["authority"]], archive_dir=tmp_path / "archive",
    )
    saved = result["preserved_private_inputs"][parent["path"]]
    assert Path(saved["path"]).read_bytes() == before == context["result"].read_bytes()
    graph = result["known_graph"]
    entries = {(row["path"], row["sha256"]): row for row in result["entries"]}
    assert graph["completeness"] == "UNVERIFIED"
    assert len(context["report"]["transcript_files_checked"]) == 19
    for row in context["report"]["transcript_files_checked"]:
        artifact = row["artifact"]
        assert entries[(artifact["path"], artifact["sha256"])]["classification"] == "transcript"
    assert entries[(parent["path"], parent["sha256"])]["classification"] == "review"
    scan = privacy.Scan({parent["sha256"]: "review"}, [])
    scan.payload(before, "synthetic-full-parent-publication")
    assert any(row["kind"] == "private_review" for row in scan.findings)


@pytest.mark.parametrize("copy_kind", ["same_parent_bytes", "new_transcript"])
def test_retention_selected_phrase_still_protected_at_unselected_origins(tmp_path, copy_kind):
    context = consumer_fixture(tmp_path, 0)
    if copy_kind == "same_parent_bytes":
        copy = context["project"] / "evidence/unselected-parent.json"
        copy.write_bytes(context["result"].read_bytes())
    else:
        copy = context["project"] / "transcripts/20-extra-private.json"
        write(copy, {"schema_version": "transcript/v1", "source_sha256": context["registered"]["screen"],
                     "text": context["selected_phrase"]})
    _, phrases, graph = observe(context, True)
    assert context["selected_phrase"] in phrases
    assert any(row["path"] == str(copy) for row in graph["known_refs"])
    scan = privacy.Scan({}, phrases)
    scan.payload(context["selected_phrase"].encode(), "synthetic-unselected-prose")
    assert any(row["kind"] == "protected_transcript_phrase" for row in scan.findings)


@pytest.mark.parametrize("position", ["root", "current_inventory", "selected_row", "outside_leaf"])
def test_retention_marker_or_outside_selector_cannot_acquire_leaf_scope(tmp_path, position):
    context = consumer_fixture(tmp_path, 0)
    marker = {"schema_version": "transcript/v1", "source_sha256": context["registered"]["screen"]}
    if position == "root":
        context["report"]["schema_version"] = "transcript/v1"
    elif position == "current_inventory":
        context["report"]["current_inventory"]["schema_version"] = "transcript/v1"
    elif position == "selected_row":
        context["report"]["current_inventory"]["public_work_candidates"][0].update(marker)
        context["locator"]["selector"] = ["current_inventory", "public_work_candidates", 0, "reason"]
    else:
        context["locator"]["selector"] = ["transcript_files_checked", 11, "schema_version"]
    rebind(context)
    with pytest.raises(TalkCutError):
        observe(context, True)


@pytest.mark.parametrize("variant", [0, 1])
def test_retention_unselected_sibling_mutation_during_traversal_refuses(tmp_path, monkeypatch, variant):
    context = consumer_fixture(tmp_path, variant)
    parent = context["result"]
    original = Path.read_text
    fired = []

    def changing_read(path, *args, **kwargs):
        value = original(path, *args, **kwargs)
        if path == parent and not fired:
            fired.append(str(path))
            data = json.loads(value)
            data["finished_at"] = "2000-01-01T00:00:02Z"
            atomic_json(path, data)
        return value

    monkeypatch.setattr(Path, "read_text", changing_read)
    with pytest.raises(TalkCutError, match="Review text origin bytes or identity changed"):
        observe(context, True)
    assert fired == [str(parent)]


def test_retention_kind_requires_retention_authority(tmp_path):
    context = consumer_fixture(tmp_path, 0)
    context["locator"]["kind"] = "machine_inventory_field"
    with pytest.raises(TalkCutError, match="kind differs from its bound authority family"):
        observe(context, True)


def test_retention_descriptor_sibling_does_not_bypass_source_private_guard(tmp_path):
    context = consumer_fixture(tmp_path, 0)
    path = context["project"] / "transcripts/private-source-copy.py"
    path.write_bytes(context["source"].read_bytes())
    with pytest.raises(TalkCutError, match="Known private bytes cannot supply review text source authority"):
        observe(context, True)
