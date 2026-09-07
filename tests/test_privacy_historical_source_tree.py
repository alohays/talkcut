"""Complete historical copies remain separate from current runtime/source claims."""

import copy
import json
import os
import shutil

import pytest
from _privacy_source_tree import fixture, privacy, rebind

from talkcut.project import TalkCutError, artifact_ref, atomic_json


def snapshot(parts, *, private_old=False):
    if private_old:
        file = parts[3] / "sub/metadata.json"
        atomic_json(
            file,
            {
                "schema_version": "transcript/v1",
                "source_sha256": parts[1]["screen"],
                "segments": [
                    {
                        "text": "An authored historical private transcript sentence is still protected after current code replacement."
                    }
                ],
            },
        )
        value = json.loads(parts[5].read_bytes())
        row = next(row for row in value["files"] if row["path"] == "sub/metadata.json")
        row.update(sha256=artifact_ref(file)["sha256"], bytes=file.stat().st_size)
        atomic_json(parts[5], value)
        rebind(parts, manifest=True)
    directory = parts[0] / "evidence/historical-copy"
    directory.mkdir(parents=True)
    shutil.copytree(parts[3], directory / "source")
    build = json.loads(parts[4].read_bytes())
    tree = json.loads(parts[5].read_bytes())
    origin = copy.deepcopy(parts[-1])
    record = {
        "schema_version": "historical-source-tree-snapshot/v1",
        "origin": {
            "build": origin["build"],
            "manifest": origin["manifest"],
            "runner": build["runner"],
            "acquisition": build["source_acquisition"],
            "logical_source_root": str(parts[3]),
        },
        "tree": tree,
        "claim_status": "UNVERIFIED",
    }
    path = directory / "snapshot.json"
    atomic_json(path, record)
    return {"origin": origin, "snapshot": artifact_ref(path)}, directory


def observe(parts, locator):
    return privacy._auxiliary_historical_source_tree_inventory(
        [locator], parts[0], privacy.Path.cwd(), set(parts[1].values())
    )


def test_complete_old_copy_and_current_tree_are_both_real_denominators(tmp_path):
    parts = fixture(tmp_path)
    locator, directory = snapshot(parts)
    old = artifact_ref(parts[3] / "main.cpp")
    (parts[3] / "main.cpp").write_text("int changed_current_bytes;\n")
    with pytest.raises(TalkCutError, match="size/type|changed"):
        privacy._auxiliary_source_tree_inventory(
            [parts[-1]], parts[0], privacy.Path.cwd(), set(parts[1].values())
        )
    observation = observe(parts, locator)[0]
    assert (
        observation["row_count"] == len(observation["current_files"]) == 3
        and observation["claim_status"] == "UNVERIFIED"
    )
    assert observation["source_directory"] == str(parts[3]) and observation[
        "physical_snapshot_directory"
    ] == str(directory / "source")
    actual = next(
        row["actual"]
        for row in observation["files"]
        if row["original_relative_path"] == "main.cpp"
    )
    assert actual["sha256"] == old["sha256"] and actual["path"] != old["path"]
    inventory = privacy.build_private_inventory(
        parts[0],
        parts[1],
        privacy.Path.cwd(),
        auxiliary_historical_source_trees=[locator],
    )
    entries = {row["path"]: row for row in inventory["entries"]}
    assert {
        str(parts[3] / "main.cpp"),
        str(directory / "source/main.cpp"),
        str(parts[4]),
        str(parts[5]),
        str(directory / "snapshot.json"),
    } <= set(entries)
    assert (
        inventory["classification_status"] == "UNVERIFIED"
        and not inventory["excluded_directories"]
    )
    assert entries[str(directory / "snapshot.json")]["classification"] == "review"
    assert not inventory["known_graph"]["auxiliary_source_trees"]
    assert len(inventory["known_graph"]["auxiliary_historical_source_trees"]) == 1


@pytest.mark.parametrize(
    "damage",
    [
        "missing",
        "changed",
        "extra",
        "directory",
        "file_link",
        "directory_link",
        "hard_link",
        "old_header_replaced_with_current",
        "wrong_manifest",
        "wrong_digest",
        "reordered_rows",
        "wrong_logical_root",
        "mixed_build",
        "mixed_runner",
        "mixed_acquisition",
        "wrong_origin_locator",
        "copy_parent",
        "copy_value",
        "copy_formal",
        "snapshot_formal",
        "public_claim",
        "extra_claim",
        "absolute_row",
        "dotdot_row",
        "snapshot_namespace",
        "snapshot_alias",
        "snapshot_metadata_hardlink",
    ],
)
def test_incomplete_or_relabelled_historical_snapshot_rejects(tmp_path, damage):
    parts = fixture(tmp_path)
    locator, directory = snapshot(parts)
    file = directory / "source/main.cpp"
    record = json.loads((directory / "snapshot.json").read_bytes())
    if damage == "missing":
        file.unlink()
    elif damage == "changed":
        file.write_text("changed historical bytes")
    elif damage == "extra":
        (directory / "source/extra.cpp").write_text("extra historical byte file")
    elif damage == "directory":
        file.unlink()
        file.mkdir()
    elif damage == "file_link":
        file.unlink()
        file.symlink_to(parts[3] / "main.cpp")
    elif damage == "directory_link":
        shutil.rmtree(directory / "source/sub")
        (directory / "source/sub").symlink_to(
            parts[3] / "sub", target_is_directory=True
        )
    elif damage == "hard_link":
        file.unlink()
        os.link(parts[3] / "main.cpp", file)
    elif damage == "old_header_replaced_with_current":
        (parts[3] / "main.cpp").write_text("new current contents")
        shutil.copyfile(parts[3] / "main.cpp", file)
    elif damage == "wrong_manifest":
        record["origin"]["manifest"] = artifact_ref(parts[4])
    elif damage == "wrong_digest":
        record["tree"]["sha256"] = "f" * 64
    elif damage == "reordered_rows":
        record["tree"]["files"].reverse()
    elif damage == "wrong_logical_root":
        record["origin"]["logical_source_root"] = str(tmp_path)
    elif damage in ("mixed_build", "mixed_runner", "mixed_acquisition"):
        record["origin"][damage.split("_")[1]] = artifact_ref(parts[5])
    elif damage == "wrong_origin_locator":
        locator["origin"]["manifest"] = artifact_ref(parts[4])
    elif damage in ("copy_parent", "copy_value", "copy_formal"):
        value = json.loads(parts[6].read_bytes())
        if damage == "copy_parent":
            value["runtime"]["build_receipt"] = artifact_ref(parts[5])
        elif damage == "copy_value":
            value["runtime"]["actual_build_source_tree"]["files"].pop()
        else:
            value["schema_version"] = "multimodal-review/v1"
        atomic_json(parts[6], value)
        locator["origin"]["copies"][0]["parent"] = artifact_ref(parts[6])
    elif damage == "snapshot_formal":
        record["schema_version"] = "multimodal-review/v1"
    elif damage == "public_claim":
        record["claim_status"] = "PASS"
    elif damage == "extra_claim":
        record["classification"] = "public_work"
    elif damage in ("absolute_row", "dotdot_row"):
        record["tree"]["files"][0]["path"] = (
            str(parts[3] / ".gitmodules")
            if damage == "absolute_row"
            else "../.gitmodules"
        )
    elif damage == "snapshot_namespace":
        target = parts[0] / "transcripts/historical-copy"
        shutil.copytree(directory, target)
        directory = target
    elif damage == "snapshot_alias":
        target = parts[0] / "evidence/link"
        target.symlink_to(directory, target_is_directory=True)
        directory = target
    elif damage == "snapshot_metadata_hardlink":
        (directory / "snapshot.json").unlink()
        original = directory / "original.json"
        atomic_json(original, record)
        os.link(original, directory / "snapshot.json")
    if damage not in ("snapshot_metadata_hardlink",):
        atomic_json(directory / "snapshot.json", record)
    locator["snapshot"] = artifact_ref(directory / "snapshot.json")
    if damage == "snapshot_alias":
        locator["snapshot"]["path"] = str(directory / "snapshot.json")
    with pytest.raises(TalkCutError):
        observe(parts, locator)


@pytest.mark.parametrize("root_kind", ["snapshot", "current"])
def test_unreadable_unlisted_subtree_is_never_skipped(tmp_path, root_kind):
    parts = fixture(tmp_path)
    locator, directory = snapshot(parts)
    parent = directory / "source" if root_kind == "snapshot" else parts[3]
    hidden = parent / "unreadable-extra"
    hidden.mkdir()
    (hidden / "file").write_text("Unlisted bytes")
    hidden.chmod(0)
    try:
        with pytest.raises(PermissionError):
            list(os.scandir(hidden))
        with pytest.raises(TalkCutError, match="unreadable"):
            observe(parts, locator)
    finally:
        hidden.chmod(0o700)


def test_private_old_json_is_protected_after_current_public_text_replacement(tmp_path):
    parts = fixture(tmp_path)
    locator, directory = snapshot(parts, private_old=True)
    old = artifact_ref(directory / "source/sub/metadata.json")
    (parts[3] / "sub/metadata.json").write_text(
        "Current authored public code metadata."
    )
    private, phrases, known = privacy._known_private_inventory(
        parts[0],
        parts[1],
        privacy.Path.cwd(),
        auxiliary_historical_source_trees=[locator],
    )
    assert private[old["sha256"]] == "transcript"
    assert any("historical private transcript sentence" in value for value in phrases)
    assert old["path"] in {row["path"] for row in known["known_refs"]}
    assert old["sha256"] not in {
        row["sha256"] for row in known["public_work_candidates"]
    }


def test_historical_locator_is_explicit_and_conflicting_origins_reject(tmp_path):
    parts = fixture(tmp_path)
    locator, _ = snapshot(parts)
    (parts[3] / "main.cpp").write_text("changed current")
    with pytest.raises(TalkCutError):
        privacy.build_private_inventory(parts[0], parts[1], privacy.Path.cwd())
    with pytest.raises(TalkCutError):
        privacy.build_private_inventory(
            parts[0],
            parts[1],
            privacy.Path.cwd(),
            auxiliary_source_trees=[parts[-1]],
            auxiliary_historical_source_trees=[locator],
        )
    with pytest.raises(TalkCutError):
        privacy._auxiliary_historical_source_tree_inventory(
            [locator, locator], parts[0], privacy.Path.cwd(), set(parts[1].values())
        )
