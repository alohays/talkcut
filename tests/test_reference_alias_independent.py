"""Independent changes to directory aliases in the actual inventory collector."""

from pathlib import Path

import pytest
from test_privacy_reference_alias import nested_collector
from test_privacy_replay import ROOT, project

from talkcut import privacy_checks as privacy
from talkcut.project import TalkCutError, artifact_ref, atomic_json


def parent_alias(tmp_path):
    real = tmp_path / "real"
    real.mkdir()
    target = real / "payload.bin"
    target.write_bytes(b"Generated external tool bytes for directory-alias identity control")
    alias = tmp_path / "directory-alias"
    alias.symlink_to(real.name, target_is_directory=True)
    return alias, target, alias / target.name


def replace_parent_alias_with_same_byte_directory(alias, target):
    preserved = alias.with_name("preserved-original-directory-alias")
    alias.rename(preserved)
    alias.mkdir()
    (alias / target.name).write_bytes(target.read_bytes())


def test_stable_directory_alias_retains_hop_and_canonical_target(tmp_path):
    alias, target, requested = parent_alias(tmp_path)
    ns = nested_collector(tmp_path)
    expected = artifact_ref(target)["sha256"]
    ns["collect"](requested, expected)
    ns["collect"](requested, expected)
    assert set(ns["entries"]) == {str(alias), str(target)}
    assert all(row["classification"] == "UNCLASSIFIED" for row in ns["entries"].values())


def test_directory_alias_becoming_same_byte_directory_is_rejected(tmp_path):
    alias, target, requested = parent_alias(tmp_path)
    ns = nested_collector(tmp_path)
    expected = artifact_ref(target)["sha256"]
    ns["collect"](requested, expected)
    original = dict(ns["alias_observations"][str(requested)])
    replace_parent_alias_with_same_byte_directory(alias, target)
    assert requested.read_bytes() == target.read_bytes()
    assert not alias.is_symlink()
    assert original["hops"][0]["path"] == str(alias)
    with pytest.raises(TalkCutError):
        ns["collect"](requested, expected)
        atomic_json(tmp_path / "unexpected-collector-acceptance.json", {
            "entries": ns["entries"], "alias_observations": ns["alias_observations"],
        })


def test_full_inventory_rejects_parent_alias_removed_between_references(tmp_path, monkeypatch):
    directory, sources = project(tmp_path)
    external = tmp_path / "external"
    external.mkdir()
    alias, target, requested = parent_alias(external)
    declared = {"path": str(requested), "sha256": artifact_ref(target)["sha256"]}
    atomic_json(directory / "checkpoint.local.json", {
        "source_sha256": sources["screen"], "references": [declared, declared],
    })
    original = privacy._bookkeeping
    changed = False

    def mutate_after_first_resolved_target(path, task, *, referenced_input=False):
        nonlocal changed
        result = original(path, task, referenced_input=referenced_input)
        if Path(path) == target and not changed:
            changed = True
            replace_parent_alias_with_same_byte_directory(alias, target)
        return result

    monkeypatch.setattr(privacy, "_bookkeeping", mutate_after_first_resolved_target)
    with pytest.raises(TalkCutError):
        inventory = privacy.build_private_inventory(directory, sources, ROOT)
        atomic_json(tmp_path / "unexpected-inventory-acceptance.json", inventory)
    assert changed
