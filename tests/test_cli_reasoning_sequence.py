"""Synthetic structural controls; no captured model or audiovisual evidence."""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest
from test_codex_cli_transport import fixture

from talkcut import codex_cli_transport as cli
from talkcut.project import TalkCutError


def sequence(f, count):
    rows = copy.deepcopy(f["rows"])
    pairs = []
    for index in range(count):
        mirror, response = copy.deepcopy(rows[10:12])
        mirror["payload"]["item"]["id"] = f"reasoning-{index}"
        response["payload"]["id"] = f"reasoning-{index}"
        response["payload"]["internal_chat_message_metadata_passthrough"] = {
            "turn_id": f["tid"]
        }
        pairs.extend([mirror, response])
    return rows[:10] + pairs + rows[12:]


def parse(f, rows):
    session = b"".join((json.dumps(row) + "\n").encode() for row in rows)
    return cli.parse_cli_intake(
        session,
        f["preview"],
        prompt=f["prompt"],
        frames=f["frames"],
        model_revision=f["model"],
        cli_version=f["version"],
        cwd=f["cwd"],
        stdout=f["stdout"],
        final=f["final"].encode(),
    )


@pytest.mark.parametrize("count", [1, 2, 5, cli.MAX_REASONING_ITEMS])
def test_bounded_complete_sequences_remain_unscoped(tmp_path, monkeypatch, count):
    f = fixture(tmp_path, monkeypatch)
    result = parse(f, sequence(f, count))
    assert result["scope"] == "UNSCOPED_INTAKE_ONLY"
    assert result["accepted_av_coverage_seconds"] == 0
    assert result["input_delivery"] == "tool_results_as_text"
    assert result["raw_text"] == f["final"]


@pytest.mark.parametrize("count", [0, cli.MAX_REASONING_ITEMS + 1])
def test_empty_and_overbound_sequences_reject(tmp_path, monkeypatch, count):
    f = fixture(tmp_path, monkeypatch)
    with pytest.raises(TalkCutError):
        parse(f, sequence(f, count))


@pytest.mark.parametrize("position", [0, 2, 4])
@pytest.mark.parametrize(
    "mutation",
    [
        "missing_id",
        "empty_id",
        "nonstring_id",
        "duplicate_id",
        "final_id",
        "missing_mirror",
        "extra_mirror",
        "mirror_id",
        "missing_mirror_id",
        "mirror_summary",
        "mirror_raw_content",
        "mirror_unknown_field",
        "visible_summary",
        "visible_content",
        "tool_field",
        "role_field",
        "encrypted_object",
        "wrong_turn",
        "opaque_metadata",
    ],
)
def test_each_reasoning_pair_is_validated(tmp_path, monkeypatch, position, mutation):
    f = fixture(tmp_path, monkeypatch)
    rows = sequence(f, 5)
    mirror_index = 10 + position * 2
    mirror = rows[mirror_index]["payload"]["item"]
    response = rows[mirror_index + 1]["payload"]
    if mutation == "missing_id":
        response.pop("id")
    elif mutation == "empty_id":
        mirror["id"] = response["id"] = " "
    elif mutation == "nonstring_id":
        mirror["id"] = response["id"] = 42
    elif mutation == "duplicate_id":
        mirror["id"] = response["id"] = "reasoning-1"
    elif mutation == "final_id":
        mirror["id"] = response["id"] = "answer"
    elif mutation == "missing_mirror":
        rows.pop(mirror_index)
    elif mutation == "extra_mirror":
        rows.insert(mirror_index, copy.deepcopy(rows[mirror_index]))
    elif mutation == "mirror_id":
        mirror["id"] = "unrelated"
    elif mutation == "missing_mirror_id":
        mirror.pop("id")
    elif mutation == "mirror_summary":
        mirror["summary_text"] = ["visible text"]
    elif mutation == "mirror_raw_content":
        mirror["raw_content"] = ["visible text"]
    elif mutation == "mirror_unknown_field":
        mirror["content"] = []
    elif mutation == "visible_summary":
        response["summary"] = [{"type": "summary_text", "text": "visible text"}]
    elif mutation == "visible_content":
        response["content"] = [{"type": "input_text", "text": "hidden input"}]
    elif mutation == "tool_field":
        response["tool_calls"] = []
    elif mutation == "role_field":
        response["role"] = "user"
    elif mutation == "encrypted_object":
        response["encrypted_content"] = {"text": "visible content"}
    elif mutation == "wrong_turn":
        response["internal_chat_message_metadata_passthrough"]["turn_id"] = "other"
    elif mutation == "opaque_metadata":
        response["internal_chat_message_metadata_passthrough"]["content"] = "extra"
    with pytest.raises(TalkCutError):
        parse(f, rows)


@pytest.mark.parametrize(
    "mutation",
    [
        "mirror_after_response",
        "swapped_mirrors",
        "swapped_responses",
        "all_mirrors_before_responses",
        "reasoning_before_input",
        "reasoning_after_final",
        "user_mirror_after_reasoning",
        "final_mirror_before_last_reasoning",
        "chronology",
        "extra_user",
        "extra_tool",
        "extra_agent",
        "world_replacement",
        "stdout_tool",
        "raw_final",
        "frame_metadata",
        "frame_order",
    ],
)
def test_sequence_order_and_existing_guards_reject(tmp_path, monkeypatch, mutation):
    f = fixture(tmp_path, monkeypatch)
    rows = sequence(f, 5)
    if mutation == "mirror_after_response":
        rows[14], rows[15] = rows[15], rows[14]
    elif mutation == "swapped_mirrors":
        rows[10], rows[14] = rows[14], rows[10]
    elif mutation == "swapped_responses":
        rows[11], rows[15] = rows[15], rows[11]
    elif mutation == "all_mirrors_before_responses":
        rows[10:20] = rows[10:20:2] + rows[11:20:2]
    elif mutation == "reasoning_before_input":
        pair = rows[10:12]
        del rows[10:12]
        rows[8:8] = pair
    elif mutation == "reasoning_after_final":
        pair = rows[18:20]
        del rows[18:20]
        rows[20:20] = pair
    elif mutation == "user_mirror_after_reasoning":
        rows[9], rows[10] = rows[10], rows[9]
    elif mutation == "final_mirror_before_last_reasoning":
        rows[18], rows[20] = rows[20], rows[18]
    elif mutation == "chronology":
        rows[15]["timestamp"] = "2025-12-31T00:00:00+00:00"
    elif mutation == "extra_user":
        rows.insert(16, copy.deepcopy(rows[8]))
    elif mutation == "extra_tool":
        rows[15]["payload"] = {"type": "function_call", "name": "read"}
    elif mutation == "extra_agent":
        rows[15]["payload"] = {"type": "agent_message", "message": "another agent"}
    elif mutation == "world_replacement":
        rows.insert(16, copy.deepcopy(rows[6]))
    elif mutation == "stdout_tool":
        f["stdout"] = f["stdout"].replace(b"agent_message", b"tool_message")
    elif mutation == "raw_final":
        f["final"] += "\n"
    elif mutation == "frame_metadata":
        f["frames"][0]["timestamp"] = "1000"
        f["prompt"] = cli.terminal_cli_prompt(
            Path(f["base"]["path"]).read_text(), f["frames"], f["outputs"]
        )
    elif mutation == "frame_order":
        rows[8]["payload"]["content"][0]["text"] = "wrong image path/index"
    with pytest.raises(TalkCutError):
        parse(f, rows)
