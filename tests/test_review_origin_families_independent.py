"""Generated origin fixtures never approve whole parents or other prose origins."""

import json
from pathlib import Path

import pytest
from test_privacy_review_text_dialect_origins import fixture as dialect_fixture
from test_privacy_review_text_download_origins import fixture as download_fixture
from test_privacy_review_text_origins import observe
from test_privacy_review_text_verification_origins import fixture as junit_fixture
from test_privacy_review_text_wheel_origins import fixture as wheel_fixture

from talkcut import privacy_checks as privacy
from talkcut.project import TalkCutError, atomic_json

KINDS = ["junit", "wheel", "download", "dialect"]


def fixture(tmp_path, kind):
    if kind == "download":
        return download_fixture(tmp_path)[0]
    return {"junit": junit_fixture, "wheel": wheel_fixture, "dialect": dialect_fixture}[kind](tmp_path)


def direct(parts, locators=None, authorities=None, registered=None):
    root, directory, source_hashes, _, locator = parts
    return privacy._review_text_origin_inventory(
        [locator] if locators is None else locators, directory, root,
        set(source_hashes.values()) if registered is None else registered,
        [locator["authority"]] if authorities is None else authorities,
    )


@pytest.mark.parametrize("kind", KINDS)
def test_selected_field_never_exempts_original_whole_parent(tmp_path, kind):
    parts = fixture(tmp_path, kind)
    known, phrases, graph = observe(parts)
    observation = graph["review_text_origins"][0]
    assert observation["selected_value"] not in phrases
    scan = privacy.Scan(known, phrases)
    scan.payload(parts[-2].read_bytes(), "generated-public-copy")
    assert any(row["kind"] == "private_review" for row in scan.findings)
    assert observation["claim_status"] == "UNVERIFIED"


@pytest.mark.parametrize("kind", KINDS)
@pytest.mark.parametrize("context", ["private-review/v1", "transcript/v1"])
def test_equal_value_in_separate_prose_or_transcript_stays_protected(tmp_path, kind, context):
    parts = fixture(tmp_path, kind)
    observation = direct(parts)[0]
    _, directory, registered, _, _ = parts
    other = directory / "evidence" / "unselected-note.json"
    other.parent.mkdir(exist_ok=True)
    atomic_json(other, {"schema_version": context, "source_sha256": registered["screen"],
                       "arbitrary_metadata": {"unverified_reason": observation["selected_value"]}})
    _, phrases, _ = observe(parts)
    assert observation["selected_value"] in phrases


@pytest.mark.parametrize("kind", KINDS)
@pytest.mark.parametrize("mutation", ["undeclared_root", "duplicate_root", "duplicate_selector"])
def test_roots_and_origin_edges_are_closed(tmp_path, kind, mutation):
    parts = fixture(tmp_path, kind)
    locator = parts[-1]
    with pytest.raises(TalkCutError):
        direct(parts, locators=[locator, locator] if mutation == "duplicate_selector" else None,
               authorities=[] if mutation == "undeclared_root" else
               [locator["authority"], locator["authority"]] if mutation == "duplicate_root" else None)


@pytest.mark.parametrize("kind", KINDS)
def test_registered_source_hash_cannot_become_a_metadata_origin(tmp_path, kind):
    parts = fixture(tmp_path, kind)
    observation = direct(parts)[0]
    with pytest.raises(TalkCutError):
        direct(parts, registered={*parts[2].values(), observation["source_snapshot"]["sha256"]})


@pytest.mark.parametrize("kind", KINDS)
def test_oversized_original_family_input_is_rejected_before_read(tmp_path, monkeypatch, kind):
    parts = fixture(tmp_path, kind)
    if kind == "junit":
        target = Path(json.loads(parts[-2].read_bytes())["validations"]["junit"]["raw"]["path"])
    elif kind == "wheel":
        target = Path(parts[-1]["archive"]["path"])
    elif kind == "download":
        target = Path(json.loads(parts[-2].read_bytes())[0]["artifact"]["path"])
    else:
        target = parts[-2]
    with target.open("wb") as stream:
        stream.truncate(privacy.MAX_UNIT_BYTES + 1)
    read_bytes = Path.read_bytes
    attempted = []

    def guarded(path):
        if path == target:
            attempted.append(True)
            raise AssertionError("oversized original input was read")
        return read_bytes(path)

    monkeypatch.setattr(Path, "read_bytes", guarded)
    with pytest.raises(TalkCutError, match="oversized"):
        direct(parts)
    assert attempted == []
