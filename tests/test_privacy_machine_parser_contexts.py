"""Finite source decoding demonstrations using AST parsing, never execution."""
from __future__ import annotations

import ast

import pytest

from talkcut import privacy_machine_origins as machine
from talkcut.project import TalkCutError


@pytest.mark.parametrize("raw", [
    b"value = 'plain'\n",
    "value = 'café'\n".encode(),
    b"# coding: utf-8\nvalue = 'plain'\n",
    b"#!/usr/bin/python3\n# coding: utf-8\nvalue = 'plain'\n",
    b"\xef\xbb\xbfvalue = 'plain'\n",
    b"# coding: latin-1\nvalue = 'plain'\n",
    b"# coding: cp1252\nvalue = 'plain'\n",
    b"# first\n# second\n# coding: missing_codec\nvalue = 'plain'\n",
])
def test_supported_byte_sources_match_actual_python_ast(raw):
    assert ast.dump(machine.syntax(raw)) == ast.dump(ast.parse(raw))


@pytest.mark.parametrize("raw", [
    b"# coding: talkcut_missing_codec\nvalue = 'plain'\n",
    b"# coding: utf-16\nvalue = 'plain'\n",
    "# coding: latin-1\nvalue = 'café'\n".encode(),
    b"# coding: latin-1\nvalue = 'caf\xe9'\n",
    b"\xef\xbb\xbf# coding: latin-1\nvalue = 'plain'\n",
])
def test_invalid_or_differently_decoded_source_bytes_refuse(raw):
    with pytest.raises(TalkCutError):
        machine.syntax(raw)


@pytest.mark.parametrize("header", ["", "# coding: missing_codec\n", "# coding: utf-16\n"])
def test_exec_string_does_not_apply_source_coding_declaration(header):
    text = header + "value = 'plain'\n"
    assert ast.dump(machine.syntax_text(text)) == ast.dump(ast.parse(text))
    assert ast.dump(machine.helper_prefix((text + "STOP\n").encode(), "STOP")) == ast.dump(ast.parse(text))


@pytest.mark.parametrize("newline", ["\n", "\r\n", "\r"])
def test_whole_ascii_read_text_normalizes_newlines_before_split(newline):
    raw = newline.join(["# coding: missing_codec", "value = 'plain'", "STOP", "unused = 1"]).encode()
    expected = ast.parse("# coding: missing_codec\nvalue = 'plain'\n")
    assert ast.dump(machine.helper_prefix(raw, "STOP")) == ast.dump(expected)


@pytest.mark.parametrize("raw", [b"value = 1\nSTOP\n\xff", b"value = 1\nSTOP\n\xc3\xa9", b"\xef\xbb\xbfvalue=1\nSTOP", b"value=1\nSTOP\nSTOP"])
def test_invalid_or_unbound_helper_suffix_cannot_be_hidden(raw):
    with pytest.raises(TalkCutError):
        machine.helper_prefix(raw, "STOP")


def test_exec_string_bom_is_not_silently_removed():
    with pytest.raises(TalkCutError):
        machine.syntax_text("\ufeffvalue = 1\n")
