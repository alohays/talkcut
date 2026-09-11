"""Authored byte-tree controls; no historical build or audiovisual approval."""

import ast
import json

import pytest
from _privacy_source_tree import collect, fixture, privacy, producer_source, rebind

from talkcut.project import TalkCutError, artifact_ref, atomic_json


def native_parts(tmp_path, *, legacy=True, renamed=True):
    parts = list(fixture(tmp_path))
    base, old_source, build = parts[2:5]
    source_name = "llama.cpp-qwen3a-valid-mel-floor" if renamed else "source"
    build_name = "build-r4" if renamed else "build"
    source = base / source_name
    if source != old_source:
        old_source.rename(source)
    parts[3] = source
    data = json.loads(build.read_bytes())
    for row in data["commands"]:
        row["cwd"] = str(source)
        row["argv"] = [str(source) if arg == str(old_source) else str(base / build_name)
                       if arg == str(base / "build") else arg for arg in row["argv"]]
    atomic_json(build, data)
    syntax = ast.parse(producer_source(data["commands"]))
    for node in syntax.body:
        if not isinstance(node, ast.Assign) or not isinstance(node.targets[0], ast.Name):
            continue
        name = node.targets[0].id
        if name in {"source", "build"}:
            node.value.right = ast.Constant(source_name if name == "source" else build_name)
        if legacy and name == "report":
            for i, key in enumerate(node.value.keys):
                if isinstance(key, ast.Constant) and key.value == "runtime_libraries":
                    node.value.values[i] = ast.parse(
                        "[ref(p) for p in sorted((build / 'bin').glob('*.dylib')) if p.is_file()]",
                        mode="eval").body
    (base / "producer.py").write_text(ast.unparse(ast.fix_missing_locations(syntax)) + "\n")
    extracted = base / "upstream-extracted-source"
    extracted.mkdir()
    archive = base / "upstream.tar.gz"
    archive.write_bytes(b"Authored archive observation only; not an executed acquisition")
    atomic_json(base / "acquisition.json", {
        "source_url": "https://example.invalid/authored-upstream", "upstream_commit": "a" * 40,
        "archive": artifact_ref(archive), "extracted_source": str(extracted),
        "elapsed_seconds": 1.0, "finished_at": "2026-01-01T00:00:00+00:00", "original_runtime_unchanged": True})
    parts[-1]["origin_scope"] = "current_native_source_bytes/v1"
    rebind(parts, origin=True)
    return parts


def observe(parts):
    return privacy._auxiliary_source_tree_inventory(
        [parts[-1]], parts[0], privacy.Path.cwd(), set(parts[1].values()))


@pytest.mark.parametrize("legacy", [False, True])
@pytest.mark.parametrize("renamed", [False, True])
def test_two_closed_recorders_keep_all_current_bytes_without_copy_history(tmp_path, legacy, renamed):
    parts = native_parts(tmp_path, legacy=legacy, renamed=renamed)
    observation = observe(parts)[0]
    assert observation["row_count"] == 3
    assert {row["actual"]["path"] for row in observation["files"]} == {
        str(p) for p in parts[3].rglob("*") if p.is_file()}
    assert observation["producer_grammar"] == (
        "legacy_direct_runtime_refs/v1" if legacy else "explicit_runtime_alias_rows/v1")
    for name in ("claim_status", "copy_history_status", "build_status", "runtime_status", "av_status"):
        assert observation[name] == "UNVERIFIED"
    result = collect(parts)
    assert not result["unresolved"]
    assert len(result["known_graph"]["auxiliary_source_trees"]) == 1
    assert result["classification_status"] == "UNVERIFIED"


@pytest.mark.parametrize("damage", ["omitted", "unknown", "boolean", "dict", "historical", "copied_added",
                                    "extraction_same", "extraction_outside", "extraction_symlink", "archive_symlink"])
def test_current_origin_cannot_authorize_copy_history_or_unbound_acquisition(tmp_path, damage):
    parts = native_parts(tmp_path)
    locator = parts[-1]
    if damage == "omitted":
        locator.pop("origin_scope")
    elif damage in {"unknown", "boolean", "dict"}:
        locator["origin_scope"] = {"unknown": "historical_source/v1", "boolean": True, "dict": {}}[damage]
    elif damage == "historical":
        with pytest.raises(TalkCutError, match="nonhistorical"):
            privacy._auxiliary_historical_source_tree_inventory(
                [{"origin": locator, "snapshot": locator["manifest"]}], parts[0], privacy.Path.cwd(), set(parts[1].values()))
        return
    else:
        path = parts[2] / "acquisition.json"
        data = json.loads(path.read_bytes())
        if damage == "copied_added":
            data["copied_source"] = str(parts[3])
        elif damage == "extraction_same":
            data["extracted_source"] = str(parts[3])
        elif damage == "extraction_outside":
            data["extracted_source"] = str(tmp_path)
        elif damage == "extraction_symlink":
            link = parts[2] / "alias"
            link.symlink_to(parts[3], target_is_directory=True)
            data["extracted_source"] = str(link)
        elif damage == "archive_symlink":
            link = parts[2] / "alias"
            link.symlink_to(data["archive"]["path"])
            data["archive"]["path"] = str(link)
        atomic_json(path, data)
        rebind(parts, origin=True)
    with pytest.raises(TalkCutError):
        observe(parts)


@pytest.mark.parametrize("replacement", [
    "source = base / '../source'", "source = base / '/absolute'", "source = base / './source'",
    "source = base / 'nested/source'", "source = base / (prefix + 'source')",
    "source = Path('source')", "source = base / ('a' * 129)",
    "source = base / 'build-r4'", "source = base / 'build-execution-synthetic'",
    "source = base / '" + "a" * 129 + "'", "source = base / '.hidden'",
])
def test_literal_source_root_is_one_bounded_component_not_arbitrary_python(tmp_path, replacement):
    parts = native_parts(tmp_path)
    producer = parts[2] / "producer.py"
    text = producer.read_text()
    assert "source = base / 'llama.cpp-qwen3a-valid-mel-floor'" in text
    producer.write_text(text.replace("source = base / 'llama.cpp-qwen3a-valid-mel-floor'", replacement))
    rebind(parts, origin=True)
    with pytest.raises(TalkCutError):
        observe(parts)


@pytest.mark.parametrize("damage", ["rebind", "import", "root_assertion", "unsorted", "recursive_glob",
                                    "missing_filter", "resolve_ref", "wrong_configure", "wrong_binary", "new_file"])
def test_legacy_row_grammar_does_not_admit_other_programs_or_skip_current_bytes(tmp_path, damage):
    parts = native_parts(tmp_path)
    assert observe(parts)[0]["row_count"] == 3
    producer = parts[2] / "producer.py"
    text = producer.read_text()
    if damage == "rebind":
        text += "\nsource = base\n"
    elif damage == "import":
        text += "\nimport os\n"
    elif damage == "root_assertion":
        text += "\nassert source == base / 'llama.cpp-qwen3a-valid-mel-floor'\n"
    elif damage == "unsorted":
        text = text.replace("sorted((build / 'bin').glob('*.dylib'))", "(build / 'bin').glob('*.dylib')")
    elif damage == "recursive_glob":
        text = text.replace(".glob('*.dylib')", ".rglob('*.dylib')")
    elif damage == "missing_filter":
        text = text.replace(" if p.is_file()]", "]")
    elif damage == "resolve_ref":
        text = text.replace("[ref(p) for p", "[ref(p.resolve()) for p")
    elif damage in {"wrong_configure", "wrong_binary"}:
        data = json.loads(parts[4].read_bytes())
        if damage == "wrong_configure":
            data["commands"][0]["argv"][2] = str(parts[2])
        else:
            fake = parts[2] / "other-binary"
            fake.write_bytes(b"Authored unrelated nonexecutable binary")
            data["binary"] = artifact_ref(fake)
        atomic_json(parts[4], data)
    elif damage == "new_file":
        (parts[3] / "unlisted.cpp").write_text("int complete_denominator_required;\n")
    producer.write_text(text)
    rebind(parts, origin=True)
    with pytest.raises(TalkCutError):
        observe(parts)
