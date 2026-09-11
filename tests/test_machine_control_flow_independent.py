"""Counterfactual source grammar only; no historical producer is executed."""
from __future__ import annotations

import ast
import hashlib
from pathlib import Path

import pytest
from test_privacy_machine_writer_grammar import context as original_context
from test_privacy_machine_writer_grammar import select

from talkcut.project import TalkCutError

context = original_context


def test_unchanged_complete_writer_still_derives(context):
    result = select(context)
    assert result["value"] == context[3]["public_work_candidates"][0]["reason"]


@pytest.mark.parametrize("mutation", [
    "unconditional_return",
    "unconditional_raise",
    "walk_rebound",
    "collector_rebound",
    "pending_emptied",
])
def test_unreachable_or_rebound_writer_cannot_supply_field(context, tmp_path: Path, mutation):
    text, bound, _, known = context
    first_line, remainder = text.split("\n", 1)
    if mutation == "unconditional_return":
        changed = first_line + "\n    return None\n" + remainder
    elif mutation == "unconditional_raise":
        changed = first_line + '\n    raise RuntimeError("synthetic original writer does not run")\n' + remainder
    else:
        replacements = {
            "walk_rebound": "    walk = lambda *args, **kwargs: None\n",
            "collector_rebound": "    collect_candidate = lambda *args, **kwargs: None\n",
            "pending_emptied": "    pending = []\n",
        }
        assert text.count("    while pending:\n") == 1
        changed = text.replace("    while pending:\n", replacements[mutation] + "    while pending:\n")
    assert changed != text
    ast.parse(changed)
    original = tmp_path / "unmodified-original.py"
    original.write_text(text)
    candidate = tmp_path / (mutation + ".py")
    candidate.write_text(changed)
    bound["source"] = {"path": str(candidate), "sha256": hashlib.sha256(candidate.read_bytes()).hexdigest()}
    bound["source_tree"] = ast.parse(candidate.read_bytes())
    expected_row = dict(known["public_work_candidates"][0])
    try:
        with pytest.raises(TalkCutError):
            select(context)
    finally:
        assert known["public_work_candidates"][0] == expected_row
        assert original.read_text() == text
        assert candidate.read_text() == changed
