"""Structured malformed-selector refusal through the actual complete consumer."""
import json
from pathlib import Path

import pytest
from oversized_fixture import fixture, observe, refresh, write

from talkcut.privacy_checks import _review_text_origin_inventory
from talkcut.project import TalkCutError


@pytest.mark.parametrize("selector", [[{}], [[]], None, [], "scope", [True]])
def test_malformed_selector_has_structured_refusal(tmp_path, selector):
    parts = fixture(tmp_path)
    assert observe(parts)
    locator = {"schema_version": "review-text-origin/v1", "kind": "machine_inventory_field",
               "parent": parts["parent"], "authority": parts["authority"], "selector": selector}
    with pytest.raises(TalkCutError):
        _review_text_origin_inventory([locator], parts["directory"], parts["root"],
                                     set(parts["registered"].values()), [parts["authority"]])


def test_original_source_artifact_limit_is_not_widened(tmp_path):
    parts = fixture(tmp_path)
    assert observe(parts)
    observation = parts["body"]["known_graph"]["synthetic_failure_fixtures"][0]
    raw = json.loads(Path(observation["run"]["path"]).read_bytes())
    count = 20001 - len(raw["artifacts"])
    raw["artifacts"].extend({"path": str(tmp_path / ("unread-extra-" + str(i))), "sha256": "1" * 64} for i in range(count))
    run = write(observation["run"]["path"], raw)
    observation["run"] = run
    for row in observation["rows"]:
        row["historical_run"] = run
    refresh(parts)
    with pytest.raises(TalkCutError, match="artifact denominator"):
        observe(parts)
