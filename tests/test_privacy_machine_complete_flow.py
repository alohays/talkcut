"""Complete syntax controls without executing the supplied source bodies."""
from __future__ import annotations

import ast

import pytest
from test_privacy_machine_writer_grammar import context as original_context
from test_privacy_machine_writer_grammar import select

from talkcut.project import TalkCutError

context = original_context


@pytest.mark.parametrize("insertion", [
    "    stop_before_original_loop()\n",
    "    while True:\n        pass\n",
    "    def unrelated_writer():\n        return None\n",
    "    walk.__defaults__ = (True, '')\n",
    "    setattr(collect_candidate, '__code__', unrelated_code)\n",
    "    with unrelated_context():\n        pass\n",
])
def test_complete_enclosing_scope_refuses_extra_execution(context, insertion):
    text, bound, _, _ = context
    changed = text.replace("    while pending:", insertion + "    while pending:")
    bound["source_tree"] = ast.parse(changed)
    with pytest.raises(TalkCutError, match="complete supported original invocation-scope grammar"):
        select(context)


def test_computed_metadata_is_not_abstracted_from_invocation_scope(context):
    text, bound, _, _ = context
    changed = text.replace('"completeness": "UNVERIFIED",', '"scope": stop_during_return(), "completeness": "UNVERIFIED",')
    bound["source_tree"] = ast.parse(changed)
    with pytest.raises(TalkCutError, match="computed replacement expression"):
        select(context)


def test_ast_grammar_ignores_only_positions_and_formatting(context):
    text, bound, _, _ = context
    original = select(context)
    bound["source_tree"] = ast.parse("\n\n" + ast.unparse(ast.parse(text)) + "\n")
    assert select(context) == original
