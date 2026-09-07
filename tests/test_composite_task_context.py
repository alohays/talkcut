"""Synthetic task-context/decision controls, never executed AI or AV approval.

Only the explicit candidate-consumer cases isolate verify_imported_review;
all context, exact-time and CLI metadata checks exercise production functions.
"""

import copy
import hashlib
import json
from pathlib import Path

import pytest

from talkcut.codex_cli_transport import CHILD_SUFFIX, SUFFIX, terminal_cli_prompt
from talkcut.composite_review import validate_task_context
from talkcut.contracts import code_identity
from talkcut.project import TalkCutError, artifact_ref, content_hash
from talkcut.review import authorize_candidate_review

ROOT = Path.cwd()


def fixture(task="analysis", role="proposer", start="300", scope="analysis"):
    clip = {"path": "/synthetic/test-only/clip.mp4", "sha256": "a" * 64}
    interval = [start, str(int(start) + 30)]
    context = {
        "schema_version": "terminal-review-context/v1",
        "task": task,
        "role": role,
        "scope": scope,
        "intervals": [interval],
        "clip_to_parent_offset": start,
        "input_clip_hashes": [clip["sha256"]],
        "source_kind": "real",
        "precision_required": False,
        "details": {},
    }
    request = {
        "review_context": context,
        "frames": [{"review_context": copy.deepcopy(context)}, {}],
        "input_clip_hashes": [clip["sha256"]],
        "media_clip": clip,
        "precision_required": False,
        "audio_interval": ["0", "480003/16000"],
        "scope": scope,
        "intervals": [interval],
        "inputs": [{"clip": clip, "interval": interval}],
    }
    if scope == "deletion":
        context["details"] = {
            "candidate_id": "candidate-test-only",
            "requested_interval": [str(int(start) + 5), str(int(start) + 25)],
            "source_domain": ["0", "3600"],
        }
        request["details"] = copy.deepcopy(context["details"])
        request["frames"][0]["review_context"] = copy.deepcopy(context)
    if scope == "seam":
        context["details"] = {"seam_time": str(int(start) + 15)}
        request["details"] = copy.deepcopy(context["details"])
        request["frames"][0]["review_context"] = copy.deepcopy(context)
    recipe = {
        "review_context_policy": {
            "schema_version": "terminal-review-context-policy/v1",
            "role": role,
        }
    }
    return request, recipe


@pytest.mark.parametrize("role", ["proposer", "adversarial"])
def test_calibration_is_explicit_and_bounded(role):
    request, recipe = fixture(role=role)
    for key in ("scope", "inputs", "intervals"):
        request.pop(key)
    context = request["review_context"]
    context.update(
        task="calibration",
        scope="generated_calibration",
        source_kind="generated_calibration",
        intervals=[request["audio_interval"]],
        clip_to_parent_offset="0",
    )
    request["frames"][0]["review_context"] = copy.deepcopy(context)
    validate_task_context(request, recipe)
    request["scope"] = "analysis"
    with pytest.raises(TalkCutError, match="relabeled"):
        validate_task_context(request, recipe)


@pytest.mark.parametrize("start", ["0", "300", "1700"])
def test_real_clip_parent_offsets_are_preserved(start):
    validate_task_context(*fixture(start=start))


@pytest.mark.parametrize(
    "scope",
    ["analysis", "deletion", "output", "seam", "layout", "lip_sync", "source_sync"],
)
def test_adversarial_scopes_are_explicit_not_precision_approval(scope):
    validate_task_context(
        *fixture(task="adversarial_review", role="adversarial", scope=scope)
    )


def test_legacy_has_no_silent_extra_metadata():
    validate_task_context({"frames": [{}]}, {})
    with pytest.raises(TalkCutError):
        validate_task_context({"frames": [{"review_context": {}}]}, {})


@pytest.mark.parametrize(
    "payload,recipe",
    [
        ({"frames": [{}], "review_context": None}, {}),
        ({"frames": [{}]}, {"review_context_policy": None}),
        ({"frames": [{}], "review_context": None}, {"review_context_policy": None}),
    ],
)
def test_explicit_null_task_metadata_does_not_become_legacy(payload, recipe):
    with pytest.raises(TalkCutError):
        validate_task_context(payload, recipe)


@pytest.mark.parametrize(
    "case",
    [
        "frame_omits_context",
        "frame_changes_offset",
        "duplicate_context",
        "second_frame_only",
        "different_root_interval",
        "different_root_scope",
        "different_clip_hash",
        "different_parent_offset",
        "wrong_role",
        "unsupported_task",
        "source_kind",
        "precision_integer",
        "request_precision_integer",
        "extra_answer_field",
        "policy_extra",
        "policy_missing",
        "policy_wrong_role",
        "multiple_inputs",
        "omitted_inputs",
        "different_extraction_clip",
        "outside_parent",
        "empty_intervals",
        "empty_parent",
        "offset_boolean",
        "real_task_as_calibration",
        "first_frame_numeric_alias",
    ],
)
def test_contradictory_or_unbound_task_context_rejected(case):
    request, recipe = fixture()
    context = request["review_context"]
    if case == "frame_omits_context":
        request["frames"][0].clear()
    elif case == "frame_changes_offset":
        request["frames"][0]["review_context"]["clip_to_parent_offset"] = "0"
    elif case == "duplicate_context":
        request["frames"][1]["review_context"] = copy.deepcopy(context)
    elif case == "second_frame_only":
        request["frames"].reverse()
    elif case == "different_root_interval":
        request["intervals"] = [["301", "330"]]
    elif case == "different_root_scope":
        request["scope"] = "output"
    elif case == "different_clip_hash":
        context["input_clip_hashes"] = ["b" * 64]
    elif case == "different_parent_offset":
        context["clip_to_parent_offset"] = "0"
    elif case == "wrong_role":
        context["role"] = "adversarial"
    elif case == "unsupported_task":
        context["task"] = "owner_acceptance"
    elif case == "source_kind":
        context["source_kind"] = "generated_calibration"
    elif case == "precision_integer":
        context["precision_required"] = 0
    elif case == "request_precision_integer":
        request["precision_required"] = 0
    elif case == "extra_answer_field":
        context["expected"] = {"verdict": "PASS"}
    elif case == "policy_extra":
        recipe["review_context_policy"]["skip_validation"] = True
    elif case == "policy_missing":
        recipe.clear()
    elif case == "policy_wrong_role":
        recipe["review_context_policy"]["role"] = "proposer_and_reviewer"
    elif case == "multiple_inputs":
        request["inputs"] *= 2
    elif case == "omitted_inputs":
        request["inputs"] = []
    elif case == "different_extraction_clip":
        request["inputs"][0]["clip"] = {"path": "/other", "sha256": "b" * 64}
    elif case == "outside_parent":
        request["inputs"][0]["interval"] = ["301", "329"]
    elif case == "empty_intervals":
        context["intervals"] = request["intervals"] = []
    elif case == "empty_parent":
        request["inputs"][0]["interval"] = ["300", "300"]
    elif case == "offset_boolean":
        context["clip_to_parent_offset"] = False
    elif case == "real_task_as_calibration":
        context["task"] = "calibration"
    elif case == "first_frame_numeric_alias":
        request["frames"][0]["review_context"]["precision_required"] = 0
    # For metadata mutations, bind the altered frame exactly. They must still
    # fail against the actual scope, source clip and fixed calibrated role.
    if case not in {
        "frame_omits_context",
        "frame_changes_offset",
        "duplicate_context",
        "second_frame_only",
        "first_frame_numeric_alias",
    }:
        request["frames"][0]["review_context"] = copy.deepcopy(context)
    with pytest.raises((TalkCutError, ValueError, TypeError)):
        validate_task_context(request, recipe)


@pytest.mark.parametrize("alias", [[False, 1], [0, True], [0.0, 1.0]])
def test_calibration_numeric_aliases_are_not_equal_metadata(alias):
    request, recipe = fixture()
    for key in ("scope", "inputs", "intervals"):
        request.pop(key)
    request["audio_interval"] = [0, 1]
    context = request["review_context"]
    context.update(
        task="calibration",
        scope="generated_calibration",
        source_kind="generated_calibration",
        intervals=[alias],
        clip_to_parent_offset="0",
    )
    request["frames"][0]["review_context"] = copy.deepcopy(context)
    with pytest.raises(TalkCutError):
        validate_task_context(request, recipe)


@pytest.mark.parametrize(
    "case",
    [
        "candidate_omitted",
        "candidate_empty",
        "requested_omitted",
        "domain_omitted",
        "wrong_frame_candidate",
        "different_root_candidate",
        "candidate_outside_clip",
        "context_before_missing",
        "context_after_missing",
        "boolean_start",
        "integer_end",
        "context_details_not_object",
        "source_domain_omits_clip",
    ],
)
def test_deletion_needs_the_actual_candidate_and_full_context(case):
    request, recipe = fixture(
        task="adversarial_review", role="adversarial", scope="deletion"
    )
    context = request["review_context"]
    details = context["details"]
    if case == "candidate_omitted":
        details.pop("candidate_id")
    elif case == "candidate_empty":
        details["candidate_id"] = "   "
    elif case == "requested_omitted":
        details.pop("requested_interval")
    elif case == "domain_omitted":
        details.pop("source_domain")
    elif case == "wrong_frame_candidate":
        request["frames"][0]["review_context"]["details"]["candidate_id"] = "another"
    elif case == "different_root_candidate":
        request["details"]["candidate_id"] = "another"
    elif case == "candidate_outside_clip":
        details["requested_interval"] = ["299", "315"]
    elif case == "context_before_missing":
        details["requested_interval"] = ["301", "315"]
    elif case == "context_after_missing":
        details["requested_interval"] = ["305", "329"]
    elif case == "boolean_start":
        details["requested_interval"] = [False, "315"]
    elif case == "integer_end":
        details["requested_interval"] = ["305", 315]
    elif case == "context_details_not_object":
        context["details"] = []
    elif case == "source_domain_omits_clip":
        details["source_domain"] = ["301", "330"]
    if case not in {"wrong_frame_candidate", "different_root_candidate"}:
        request["details"] = copy.deepcopy(context["details"])
        request["frames"][0]["review_context"] = copy.deepcopy(context)
    with pytest.raises((TalkCutError, ValueError, TypeError)):
        validate_task_context(request, recipe)


def test_whole_context_is_distinct_from_requested_deletion():
    request, recipe = fixture(
        task="adversarial_review", role="adversarial", scope="deletion"
    )
    assert request["review_context"]["intervals"] == [["300", "330"]]
    assert request["review_context"]["details"]["requested_interval"] == ["305", "325"]
    validate_task_context(request, recipe)


@pytest.mark.parametrize("scope", ["analysis", "output", "deletion", "seam"])
@pytest.mark.parametrize(
    "claim",
    [
        {"expected": {"candidate_decision": "approve_deletion"}},
        {"proposal_confidence": 1.0},
        {"owner_acceptance": "approved"},
        {"complete_sentence_context": True},
    ],
)
def test_matching_root_and_frame_cannot_introduce_auxiliary_approval(scope, claim):
    request, recipe = fixture(
        task="adversarial_review", role="adversarial", scope=scope
    )
    context = request["review_context"]
    context["details"].update(claim)
    request["details"] = copy.deepcopy(context["details"])
    request["frames"][0]["review_context"] = copy.deepcopy(context)
    with pytest.raises(TalkCutError):
        validate_task_context(request, recipe)


@pytest.mark.parametrize(
    "spans",
    [
        [["305", "325"]],
        [["300", "310"], ["315", "330"]],
        [["300", "315"], ["315", "330"]],
        [[300, "330"]],
    ],
)
def test_task_must_request_the_entire_actual_extraction(spans):
    request, recipe = fixture(
        task="adversarial_review", role="adversarial", scope="deletion"
    )
    request["intervals"] = copy.deepcopy(spans)
    request["review_context"]["intervals"] = copy.deepcopy(spans)
    request["frames"][0]["review_context"] = copy.deepcopy(request["review_context"])
    with pytest.raises(TalkCutError):
        validate_task_context(request, recipe)


def test_existing_workflow_deletion_metadata_has_no_approval():
    request, recipe = fixture(
        task="adversarial_review", role="adversarial", scope="deletion"
    )
    context = request["review_context"]
    context["details"].update(
        deleted_interval=["306", "326"], complete_sentence_context="UNVERIFIED"
    )
    request["details"] = copy.deepcopy(context["details"])
    request["frames"][0]["review_context"] = copy.deepcopy(context)
    validate_task_context(request, recipe)


def specimen(start="15", end="35", a="20", b="30"):
    clip = {"path": "/independent-structural-only/no-model.mp4", "sha256": "a" * 64}
    details = {
        "candidate_id": "candidate-independent",
        "requested_interval": [a, b],
        "source_domain": ["0", "100"],
    }
    ctx = {
        "schema_version": "terminal-review-context/v1",
        "task": "adversarial_review",
        "role": "adversarial",
        "scope": "deletion",
        "intervals": [[start, end]],
        "input_clip_hashes": [clip["sha256"]],
        "clip_to_parent_offset": start,
        "source_kind": "real",
        "precision_required": False,
        "details": copy.deepcopy(details),
    }
    req = {
        "frames": [{"review_context": copy.deepcopy(ctx)}, {}],
        "review_context": ctx,
        "scope": "deletion",
        "intervals": copy.deepcopy(ctx["intervals"]),
        "details": copy.deepcopy(details),
        "inputs": [{"clip": clip, "interval": [start, end], "parent_sha256": "source"}],
        "media_clip": clip,
        "input_clip_hashes": [clip["sha256"]],
        "audio_interval": ["0", str(int(end) - int(start))],
        "precision_required": False,
    }
    policy = {
        "review_context_policy": {
            "schema_version": "terminal-review-context-policy/v1",
            "role": "adversarial",
        }
    }
    return req, policy


def bind(req):
    req["frames"][0]["review_context"] = copy.deepcopy(req["review_context"])


def test_candidate_details_are_in_actual_cli_prompt_once():
    req, policy = specimen()
    validate_task_context(req, policy)
    base = "Synthetic structural metadata fixture only. No actual AI execution or approval."
    child = "Synthetic placeholder. No actual model execution."
    prompt = terminal_cli_prompt(
        base,
        req["frames"],
        [
            {
                "node_id": "synthetic",
                "artifact_sha256": hashlib.sha256(child.encode()).hexdigest(),
                "text": child,
            }
        ],
    )
    rendered = json.loads(prompt.split(SUFFIX, 1)[1].split(CHILD_SUFFIX, 1)[0])
    assert rendered[0]["review_context"]["details"] == req["details"]
    assert sum("review_context" in row for row in rendered) == 1


@pytest.mark.parametrize(
    "args", [("0", "7", "0", "2"), ("93", "100", "98", "100"), ("0", "100", "0", "100")]
)
def test_context_handles_clamp_to_actual_source_edges(args):
    validate_task_context(*specimen(*args))


@pytest.mark.parametrize(
    "case", ["root_extra", "frame_extra", "numeric_alias", "root_omission"]
)
def test_deletion_details_exactly_bind_root_and_first_frame(case):
    req, policy = specimen()
    if case == "root_extra":
        req["details"]["candidate_rationale"] = "unexpected"
    elif case == "frame_extra":
        req["frames"][0]["review_context"]["details"]["candidate_rationale"] = (
            "unexpected"
        )
    elif case == "numeric_alias":
        req["details"]["requested_interval"] = [20, 30]
    else:
        req.pop("details")
    with pytest.raises(TalkCutError):
        validate_task_context(req, policy)


@pytest.mark.parametrize(
    "payload",
    [
        {"expected": {"candidate_decision": "approve_deletion"}},
        {"proposal_confidence": 1.0},
        {"complete_sentence_context": True},
        {"owner_acceptance": "approved"},
    ],
)
def test_answer_or_approval_fields_are_not_allowed_scoped_task_details(payload):
    req, policy = specimen()
    req["details"].update(payload)
    req["review_context"]["details"] = copy.deepcopy(req["details"])
    bind(req)
    with pytest.raises(TalkCutError):
        validate_task_context(req, policy)


@pytest.mark.parametrize(
    "intervals", [[["20", "30"]], [["15", "22"], ["23", "35"]], [["15", "34"]]]
)
def test_declared_review_intervals_include_entire_required_candidate_context(intervals):
    req, policy = specimen()
    req["intervals"] = intervals
    req["review_context"]["intervals"] = copy.deepcopy(intervals)
    bind(req)
    with pytest.raises(TalkCutError):
        validate_task_context(req, policy)


def isolated_proof(tmp_path, monkeypatch):
    """Isolate existing decision consumer after its separately tested provider gate."""
    req, policy = specimen()
    validate_task_context(req, policy)
    p = tmp_path / "synthetic-inspection.json"
    p.write_text(json.dumps({"sha256": "source", "video": {"coverage": ["0", "100"]}}))
    candidate = {
        "id": "candidate-independent",
        "start": "20",
        "end": "30",
        "proposer_run_id": "synthetic-proposer",
    }
    plan = {
        "source_hashes": {"screen": "source"},
        "contract_hash": "synthetic-contract",
        "inspection_refs": {"screen": artifact_ref(p)},
        "timing": {"screen_origin": "0"},
        "protected_intervals": [],
        "candidates": [candidate],
    }
    req["dependencies"] = {
        "source_hashes": plan["source_hashes"],
        "plan_hash": content_hash(plan),
        "code_tree_hash": code_identity(ROOT)["code_tree_hash"],
        "contract_hash": "synthetic-contract",
    }
    proof = {
        "import": {"artifact_ref": {"path": "synthetic", "sha256": "synthetic"}},
        "record": {
            "proposer_run_id": "synthetic-proposer",
            "receipt": {"path": "synthetic", "sha256": "synthetic"},
        },
        "request": req,
        "receipt": {"run_id": "synthetic-review"},
        "response": {
            "candidate_id": "candidate-independent",
            "candidate_decision": "approve_deletion",
            "complete_sentence_context": True,
        },
    }
    monkeypatch.setattr("talkcut.review.verify_imported_review", lambda ref: proof)
    return proof, candidate, plan


def test_deletion_metadata_and_required_response_reach_existing_consumer(
    tmp_path, monkeypatch
):
    _proof, candidate, plan = isolated_proof(tmp_path, monkeypatch)
    assert (
        authorize_candidate_review({}, candidate, plan)["candidate_id"]
        == candidate["id"]
    )


@pytest.mark.parametrize(
    "field,value",
    [
        ("candidate_id", None),
        ("candidate_id", "another"),
        ("candidate_decision", "keep"),
        ("candidate_decision", "reject_deletion"),
        ("candidate_decision", None),
        ("complete_sentence_context", 1),
        ("complete_sentence_context", False),
    ],
)
def test_missing_or_nonapproval_candidate_response_never_authorizes(
    tmp_path, monkeypatch, field, value
):
    proof, candidate, plan = isolated_proof(tmp_path, monkeypatch)
    proof["response"][field] = value
    with pytest.raises(TalkCutError, match="explicitly approve"):
        authorize_candidate_review({}, candidate, plan)


def test_guard_and_consumer_both_reject_narrow_declared_context(tmp_path, monkeypatch):
    proof, candidate, plan = isolated_proof(tmp_path, monkeypatch)
    proof["request"]["intervals"] = [["20", "30"]]
    proof["request"]["review_context"]["intervals"] = [["20", "30"]]
    bind(proof["request"])
    with pytest.raises(TalkCutError):
        validate_task_context(proof["request"], specimen()[1])
    with pytest.raises(TalkCutError, match="complete candidate context"):
        authorize_candidate_review({}, candidate, plan)


def set_details(req, values):
    req["review_context"]["details"] = copy.deepcopy(values)
    req["details"] = copy.deepcopy(values)
    bind(req)


@pytest.mark.parametrize(
    "deleted",
    [
        [False, "25"],
        ["20", 25],
        ["20", 25.0],
        ["14", "25"],
        ["25", "36"],
        ["15", "20"],
        ["30", "35"],
        ["22", "22"],
        {"start": "20", "end": "25"},
    ],
)
def test_applied_interval_is_typed_within_clip_and_overlaps_candidate(deleted):
    req, policy = specimen()
    details = copy.deepcopy(req["details"])
    details["deleted_interval"] = deleted
    set_details(req, details)
    with pytest.raises((TalkCutError, ValueError, TypeError)):
        validate_task_context(req, policy)


@pytest.mark.parametrize("value", ["PASS", "approved", False, None, 0, 1])
def test_complete_sentence_input_only_allows_literal_unverified(value):
    req, policy = specimen()
    details = copy.deepcopy(req["details"])
    details["complete_sentence_context"] = value
    set_details(req, details)
    with pytest.raises(TalkCutError):
        validate_task_context(req, policy)


def test_known_optional_workflow_fields_validate_without_approval():
    req, policy = specimen()
    details = copy.deepcopy(req["details"])
    details.update(
        deleted_interval=["19", "29"], complete_sentence_context="UNVERIFIED"
    )
    set_details(req, details)
    validate_task_context(req, policy)


@pytest.mark.parametrize("value", [True, 20, 20.0, "14", "36", None])
def test_seam_time_is_an_exact_string_within_actual_clip(value):
    req, policy = specimen()
    req["scope"] = req["review_context"]["scope"] = "seam"
    set_details(req, {"seam_time": value})
    with pytest.raises((TalkCutError, ValueError, TypeError)):
        validate_task_context(req, policy)


def test_seam_has_only_its_typed_time():
    req, policy = specimen()
    req["scope"] = req["review_context"]["scope"] = "seam"
    set_details(req, {"seam_time": "20"})
    validate_task_context(req, policy)
    set_details(req, {"seam_time": "20", "precision_supported": True})
    with pytest.raises(TalkCutError):
        validate_task_context(req, policy)


@pytest.mark.parametrize("scope", ["layout", "lip_sync", "source_sync"])
def test_other_scopes_cannot_gain_claim_fields(scope):
    req, policy = specimen()
    req["scope"] = req["review_context"]["scope"] = scope
    set_details(req, {})
    validate_task_context(req, policy)
    set_details(req, {"expected": "PASS"})
    with pytest.raises(TalkCutError):
        validate_task_context(req, policy)
