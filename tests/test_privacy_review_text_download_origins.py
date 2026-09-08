"""No network: exact synthetic locked-byte URL origins and opposition."""
import copy
import json
from pathlib import Path

import pytest
from test_privacy_checks import commit, git
from test_privacy_review_text_origins import observe
from test_privacy_review_text_verification_origins import fixture as junit_fixture
from test_privacy_review_text_verification_origins import rebind

from talkcut import privacy_checks as privacy
from talkcut.project import TalkCutError, artifact_ref, atomic_json

URL = "https://files.pythonhosted.org/packages/synthetic/sample-1.0-py3-none-any.whl"


def fixture(tmp_path):
    base = junit_fixture(tmp_path)
    root, directory, registered, report_path, _ = base
    folder = report_path.parent / "locked-wheels"
    folder.mkdir()
    wheel = folder / "sample-1.0-py3-none-any.whl"
    wheel.write_bytes(b"Explicitly synthetic retained bytes; no download or wheel approval.")
    lock = root / "uv.lock"
    lock.write_text('version = 1\n[[package]]\nname = "sample"\nversion = "1.0"\nwheels = [{url = "' + URL + '", hash = "sha256:' + artifact_ref(wheel)["sha256"] + '", size = ' + str(wheel.stat().st_size) + '}]\n')
    commit(root)
    preserved = tmp_path / "preserved-lock.toml"
    preserved.write_bytes(lock.read_bytes())
    downloads = folder / "downloads.json"
    atomic_json(downloads, [{"url": URL, "method": "GET", "status": 200, "started_at": "synthetic-start", "finished_at": "synthetic-end",
                            "artifact": artifact_ref(wheel), "bytes": wheel.stat().st_size}])
    report = json.loads(report_path.read_bytes())
    identity = report["before"]["code_identity"]
    identity["files"]["uv.lock"] = artifact_ref(lock)["sha256"]
    identity["code_revision"] = git(root, "rev-parse", "HEAD")
    identity["code_tree_hash"] = privacy.object_hash(identity["files"])
    report["after"] = copy.deepcopy(report["before"])
    report["validations"]["runtime_wheels"] = {"archives": [artifact_ref(wheel)], "downloads": artifact_ref(downloads)}
    atomic_json(report_path, report)
    rebind(base)
    locator = {"schema_version": "review-text-origin/v1", "kind": "locked_download_url", "authority": base[-1]["authority"],
               "parent": artifact_ref(downloads), "selector": [0, "url"],
               "source": {"original_path": str(lock), "snapshot": artifact_ref(preserved), "git_revision": identity["code_revision"],
                          "git_path": "uv.lock", "git_blob": git(root, "rev-parse", "HEAD:uv.lock")}}
    return (root, directory, registered, downloads, locator), base


def update(parts, base):
    report_path = base[-2]
    report = json.loads(report_path.read_bytes())
    report["validations"]["runtime_wheels"]["downloads"] = artifact_ref(parts[-2])
    atomic_json(report_path, report)
    rebind(base)
    parts[-1].update(parent=artifact_ref(parts[-2]), authority=base[-1]["authority"])


def test_exact_locked_byte_url_preserves_complete_original_inventory(tmp_path):
    parts, _ = fixture(tmp_path)
    root, directory, registered, parent, locator = parts
    before = privacy.build_private_inventory(directory, registered, root)
    _, prior, _ = observe(parts, [])
    _, current, graph = observe(parts)
    assert URL in prior and URL not in current
    observation = graph["review_text_origins"][0]
    assert observation["complete_download_rows"] == json.loads(parent.read_bytes())
    after = privacy.build_private_inventory(directory, registered, root, review_text_origins=[locator], review_text_origin_authorities=[locator["authority"]])
    rows = {row["path"]: row for row in after["entries"]}
    assert all(rows[row["path"]] == row for row in before["entries"])
    assert all(ref["path"] in rows for ref in observation["authority_refs"])


@pytest.mark.parametrize("mutation", ["missing", "duplicate", "extra_key", "status_bool", "method", "byte_count", "url", "query", "username", "artifact_type"])
def test_download_requires_every_original_typed_row_and_locked_identity(tmp_path, mutation):
    parts, base = fixture(tmp_path)
    parent = json.loads(parts[-2].read_bytes())
    if mutation == "missing":
        parent.clear()
    elif mutation == "duplicate":
        parent.append(copy.deepcopy(parent[0]))
    elif mutation == "extra_key":
        parent[0]["public"] = True
    else:
        field, value = {"status_bool": ("status", True), "method": ("method", "POST"), "byte_count": ("bytes", 1),
                        "url": ("url", URL.replace("sample-1.0", "changed-1.0")), "query": ("url", URL + "?private=1"),
                        "username": ("url", URL.replace("https://", "https://private@")), "artifact_type": ("artifact", None)}[mutation]
        parent[0][field] = value
    atomic_json(parts[-2], parent)
    update(parts, base)
    with pytest.raises(TalkCutError, match="download|origin|selector"):
        observe(parts)


def test_private_report_prose_keeps_the_same_locked_url_protected(tmp_path):
    parts, base = fixture(tmp_path)
    report = json.loads(base[-2].read_bytes())
    report["private_reason"] = URL
    atomic_json(base[-2], report)
    update(parts, base)
    _, phrases, _ = observe(parts)
    assert URL in phrases


def test_locked_url_cannot_hide_changed_retained_wheel_bytes(tmp_path):
    parts, _ = fixture(tmp_path)
    row = json.loads(parts[-2].read_bytes())[0]
    Path(row["artifact"]["path"]).write_bytes(b"Different bytes")
    with pytest.raises(TalkCutError, match="bytes or identity changed"):
        observe(parts)
