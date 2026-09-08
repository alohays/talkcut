"""Fixed counterfactuals only after unchanged real positive evidence validates."""

from __future__ import annotations

import copy
import json
import shutil
from pathlib import Path
from typing import Any
from uuid import uuid4

from .contracts import CHECK_REQUIREMENTS, code_identity
from .project import TalkCutError, artifact_ref, atomic_json, sha256
from .provider_failure_checks import (
    _closure,
    _retained_import,
    _snapshot,
    _stale_refusal,
    _subjects,
)

SCOPES = {
    "transcript_only": "Current actual review input/provenance followed by the production audiovisual observation gate",
    "always_keep": "Complete independently audited actual editorial fixtures followed by the production empty-selector gate",
    "fabricated_pass": "Current actual individual review-ledger entry followed by the production reviewer actor gate; not final acceptance",
}
FAULTS = {
    "transcript_only": "transcript_only_observation",
    "always_keep": "empty_editorial_selection",
    "fabricated_pass": "missing_reviewer_actor",
}
REASONS = {
    "transcript_only": "Actual audiovisual observation missing",
    "always_keep": "Always-keep selection omits independently verified editorial cuts",
    "fabricated_pass": "Separate AI reviewer cannot claim owner approval",
}


class CounterfactualRejection(TalkCutError):
    """Only an intended gate rejection after a verified real positive."""

    def __init__(self, reason: str, facts: dict[str, Any]):
        super().__init__("NEGATIVE_COUNTERFACTUAL_REJECTED", reason)
        self.facts = facts


def require(condition: Any, reason: str) -> None:
    if not condition:
        raise TalkCutError("NEGATIVE_EVIDENCE_UNVERIFIED", reason)


def file(ref: Any) -> Path:
    require(
        isinstance(ref, dict)
        and set(ref) == {"path", "sha256"}
        and isinstance(ref["path"], str)
        and isinstance(ref["sha256"], str),
        "Positive control needs an exact hashed artifact reference",
    )
    path = Path(ref["path"])
    require(
        path.is_absolute()
        and path.is_file()
        and not path.is_symlink()
        and path == path.resolve()
        and sha256(path) == ref["sha256"],
        "Positive control artifact is absent, aliased or changed",
    )
    return path


def read(ref: Any) -> dict[str, Any]:
    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            require(key not in result, "Positive control JSON has duplicate keys")
            result[key] = value
        return result

    path = file(ref)
    require(
        path.stat().st_size <= 16 * 1024 * 1024,
        "Positive control JSON exceeds its finite bound",
    )
    value = json.loads(path.read_bytes(), object_pairs_hook=unique)
    require(isinstance(value, dict), "Positive control JSON must be an object")
    assert isinstance(value, dict)
    return value


def bound_controls(
    ref: dict[str, Any] | None, repo: Path, dependencies: dict[str, Any]
) -> dict[str, dict[str, str]]:
    if ref is None:
        return {}
    value = read(ref)
    require(
        set(value) == {"schema_version", "dependencies", "controls"}
        and value["schema_version"] == "evaluator-av-positive-controls/v2"
        and value["dependencies"] == dependencies
        and dependencies.get("code_tree_hash") == code_identity(repo)["code_tree_hash"],
        "Positive controls differ from current evaluator dependencies",
    )
    controls = value["controls"]
    require(
        isinstance(controls, dict) and set(controls) <= set(SCOPES),
        "Unknown or malformed positive control registry",
    )
    assert isinstance(controls, dict)
    for key, item in controls.items():
        envelope = read(item)
        field = "editorial_fixture" if key == "always_keep" else "review_import"
        require(
            set(envelope)
            == {"schema_version", "case_id", "dependencies", "subjects", field}
            and envelope["schema_version"] == "evaluator-av-positive/v2"
            and envelope["case_id"] == key
            and envelope["dependencies"] == dependencies,
            "Positive control envelope has unrelated fields or dependencies",
        )
        file(envelope[field])
        _subjects(envelope["subjects"], dependencies)
    return controls


def inputs(
    case_id: str,
    positive: dict[str, str],
    dependencies: dict[str, Any],
    *,
    attack: bool,
) -> dict[str, Any]:
    require(case_id in SCOPES, "Unknown audiovisual negative case")
    return {
        "schema_version": "evaluator-av-probe-input/v2",
        "case_id": case_id,
        "positive_control": positive,
        "dependencies": dependencies,
        "fault": FAULTS[case_id] if attack else "none",
    }


def _review_positive(
    envelope: dict[str, Any], repo: Path, directory: Path
) -> dict[str, Any]:
    from .acceptance import Evaluator
    from .review import (
        validate_observation_content,
        validate_review_actor,
        verify_imported_review,
    )

    original = envelope["review_import"]
    imported = read(original)
    require(
        imported.get("status") == "PASS"
        and imported.get("owner_acceptance") == "pending",
        "Original import is not a validated pending-owner positive",
    )
    local = directory / "original-import.json"
    shutil.copyfile(file(original), local)
    require(sha256(local) == original["sha256"], "Positive import copy changed")
    proof = verify_imported_review(artifact_ref(local))
    record, request, execution = (
        proof[key] for key in ("record", "request", "receipt")
    )
    dependencies = envelope["dependencies"]
    require(
        record.get("dependencies")
        == request.get("dependencies")
        == execution.get("dependencies")
        == dependencies,
        "Positive review source/code/contract/timeline/output dependencies differ",
    )
    require(
        not any(
            item.get(flag)
            for item in (
                imported,
                record,
                request,
                execution,
                proof["capability"],
                proof["response"],
            )
            for flag in ("test_only", "synthetic", "mock", "self_attested_only")
        ),
        "Synthetic or mocked review cannot be the real positive",
    )
    evaluator = Evaluator(
        directory, "negative-positive-entry", directory / "unused-contract.json", repo
    )
    evaluator.deps = copy.deepcopy(dependencies)
    capability_ref = imported["artifact_refs"]["capability"]
    evaluator.load_capability(capability_ref)
    evaluator.receipt(record["receipt"], provider=True)
    capability = evaluator.capabilities[capability_ref["sha256"]]
    scope = request.get("scope")
    require(
        scope in {"output", "analysis", "deletion", "seam", "layout", "lip_sync"},
        "Positive individual review has an unsupported scope",
    )
    parent_hash = (
        dependencies.get("source_hashes", {}).get("screen")
        if scope in {"analysis", "deletion"}
        else dependencies.get("output_hash")
    )
    require(
        parent_hash
        and request.get("inputs")
        and all(item.get("parent_sha256") == parent_hash for item in request["inputs"]),
        "Positive review inputs differ from current source/output",
    )
    validate_observation_content(proof["response"], request, capability)
    validate_review_actor(record, execution)
    require(
        proof["response"].get("verdict") == "PASS", "Actual review positive is not PASS"
    )
    file(original)
    return {
        **proof,
        "normalized_capability": capability,
        "facts": {
            "positive_control": envelope["review_import"],
            "provider_execution": record["receipt"],
            "dependencies": dependencies,
            "input_count": len(request["inputs"]),
            "scope": scope,
        },
    }


def _editorial_positive(
    envelope: dict[str, Any], repo: Path, directory: Path
) -> dict[str, Any]:
    from .editorial_checks import _selection_matches, _span, verify_editorial_fixtures

    original = envelope["editorial_fixture"]
    raw = read(original)
    deps = raw.get("dependencies", {})
    require(
        all(
            deps.get(key) == envelope["dependencies"].get(key) and deps.get(key)
            for key in ("code_tree_hash", "contract_hash")
        ),
        "Editorial positive code or contract differs from the current evaluator",
    )
    # Relocate only exact import envelopes to route new validation output. Every
    # original provider/source/expectation reference and all their bytes remain.
    local = copy.deepcopy(raw)
    copied: list[dict[str, str]] = []
    verified_imports: list[dict[str, Any]] = []
    for index, fixture in enumerate(local.get("fixtures", [])):
        bindings = []
        if fixture.get("expectations_review"):
            bindings.append((fixture, "expectations_review"))
        bindings += [
            (fixture["deletion_reviews"], key)
            for key in fixture.get("deletion_reviews", {})
        ]
        for serial, (owner, key) in enumerate(bindings):
            reference = owner[key]
            checked_directory = directory / f"fixture-{index}-positive-{serial}"
            checked_directory.mkdir()
            checked = _review_positive(
                {
                    "review_import": reference,
                    "dependencies": {
                        **deps,
                        "source_hashes": {"screen": fixture["source"]["sha256"]},
                    },
                },
                repo,
                checked_directory,
            )
            verified_imports.append(
                {
                    "original": reference,
                    "revalidated": checked["import"]["artifact_ref"],
                }
            )
            target = directory / f"fixture-{index}-review-{serial}.json"
            shutil.copyfile(file(reference), target)
            require(
                sha256(target) == reference["sha256"], "Editorial import copy changed"
            )
            copied.append(reference)
            owner[key] = artifact_ref(target)
    measured = verify_editorial_fixtures(local, repo, directory / "editorial-readback")
    require(
        set(measured) == set(CHECK_REQUIREMENTS["editorial_fixture"])
        and all(value is True for value in measured.values()),
        "Complete actual editorial positive and independent expectation audit are unavailable",
    )
    cases = [read(fixture["expectations"])["cases"] for fixture in raw["fixtures"]]
    require(
        all(
            _selection_matches(
                items,
                [_span(item) for item in items if item["expected_action"] == "cut"],
                complete_ledger=True,
            )
            for items in cases
        ),
        "Verified editorial positive does not satisfy the production selector",
    )
    file(original)
    for reference in copied:
        file(reference)
    return {
        "cases": cases,
        "verified_imports": verified_imports,
        "facts": {
            "positive_control": original,
            "measurements": measured,
            "fixture_count": len(cases),
            "case_counts": [len(items) for items in cases],
        },
    }


def probe(
    repo: Path, case_id: str, value: dict[str, Any], output_dir: Path | None
) -> dict[str, Any]:
    from .acceptance import EvidenceError
    from .editorial_checks import _selection_matches
    from .review import validate_observation_content, validate_review_actor

    require(
        case_id in SCOPES and isinstance(value, dict), "Unsupported audiovisual probe"
    )
    dependencies = value.get("dependencies", {})
    positive = value.get("positive_control")
    fault = value.get("fault")
    require(isinstance(positive, dict), "Positive control reference must be an object")
    assert isinstance(positive, dict)
    require(
        isinstance(dependencies, dict)
        and isinstance(fault, str)
        and fault in {"none", FAULTS[case_id]}
        and value == inputs(case_id, positive, dependencies, attack=fault != "none")
        and dependencies.get("code_tree_hash") == code_identity(repo)["code_tree_hash"],
        "Audiovisual probe differs from its closed fixed input",
    )
    envelope = read(positive)
    field = "editorial_fixture" if case_id == "always_keep" else "review_import"
    require(
        set(envelope)
        == {"schema_version", "case_id", "dependencies", "subjects", field}
        and envelope["schema_version"] == "evaluator-av-positive/v2"
        and envelope["case_id"] == case_id
        and envelope["dependencies"] == dependencies,
        "Positive envelope differs from the fixed current probe",
    )
    require(
        output_dir is not None, "Audiovisual probe needs a private output directory"
    )
    assert output_dir is not None
    directory = output_dir / "positive-rechecks" / uuid4().hex
    directory.mkdir(parents=True)
    _subjects(envelope["subjects"], dependencies)
    refs = _closure(positive)
    before = _snapshot(refs, repo)
    atomic_json(directory / "before.json", before)
    before_ref = artifact_ref(directory / "before.json")
    try:
        proof = (
            _editorial_positive(envelope, repo, directory)
            if case_id == "always_keep"
            else _review_positive(envelope, repo, directory)
        )
    except (
        EvidenceError,
        TalkCutError,
        ValueError,
        KeyError,
        TypeError,
        OSError,
    ) as exc:
        raise TalkCutError(
            "NEGATIVE_POSITIVE_UNVERIFIED",
            "Legitimate positive unavailable: " + str(exc),
        ) from exc
    positive_record = _preserve_positive(
        proof, envelope, positive, directory / "positive-revalidated.json"
    )
    if fault == "none":
        after = _snapshot(refs, repo)
        require(
            before == after,
            "Original source/output/success/code changed during positive validation",
        )
        atomic_json(directory / "after.json", after)
        return {
            **proof["facts"],
            "positive_verified": True,
            "counterfactual": False,
            "audiovisual_review": "UNVERIFIED",
            "coverage": [],
            "execution_artifacts": {
                "before": before_ref,
                "positive": positive_record,
                "after": artifact_ref(directory / "after.json"),
            },
        }
    if case_id == "transcript_only":
        changed = copy.deepcopy(proof["response"])
        changed.update(observed_modalities=["text"], continuous_video_observed=False)
    elif case_id == "fabricated_pass":
        changed = copy.deepcopy(proof["record"])
        changed.pop("reviewer_role")
    else:
        changed = {"selected": [], "complete_ledger": True}
    atomic_json(
        directory / "counterfactual.json",
        {
            "schema_version": "review-import/v1",
            "local_schema": "labelled-evaluator-counterfactual/v2",
            "test_only": True,
            "status": "UNVERIFIED",
            "owner_acceptance": "pending",
            "control": {
                "kind": fault,
                "test_only": True,
                "counterfactual": True,
                "actual_provider_outcome": False,
            },
            "fault": fault,
            "positive_control": positive,
            "value": changed,
            "audiovisual_review": "UNVERIFIED",
            "coverage": [],
        },
    )
    try:
        if case_id == "transcript_only":
            validate_observation_content(
                changed, proof["request"], proof["normalized_capability"]
            )
        elif case_id == "fabricated_pass":
            validate_review_actor(changed, proof["receipt"])
        else:
            require(
                all(
                    _selection_matches(items, [], complete_ledger=True)
                    for items in proof["cases"]
                ),
                REASONS[case_id],
            )
    except TalkCutError as exc:
        if str(exc) != REASONS[case_id]:
            raise
        counterfactual_ref = artifact_ref(directory / "counterfactual.json")
        after_fault = _snapshot(refs, repo)
        require(
            before == after_fault,
            "Original source/output/success/code changed during fault",
        )
        atomic_json(directory / "after-fault.json", after_fault)
        stale_before = _stale_refusal(counterfactual_ref, directory)
        require(stale_before["refused"], "Counterfactual became usable as a positive")
        recovery_directory = directory / "recovery"
        recovery_directory.mkdir()
        recovery = (
            _editorial_positive(envelope, repo, recovery_directory)
            if case_id == "always_keep"
            else _review_positive(envelope, repo, recovery_directory)
        )
        require(
            recovery["facts"] == proof["facts"],
            "Unchanged positive did not recover its original facts",
        )
        recovery_record = _preserve_positive(
            recovery, envelope, positive, directory / "recovery-revalidated.json"
        )
        require(
            _normalized_positive(recovery_record, envelope)
            == _normalized_positive(positive_record, envelope),
            "Unchanged positive did not recover its complete original observations",
        )
        stale_after = _stale_refusal(counterfactual_ref, directory)
        require(stale_after["refused"], "Recovery promoted the old counterfactual")
        after_recovery = _snapshot(refs, repo)
        require(
            before == after_recovery,
            "Original source/output/success/code changed during recovery",
        )
        atomic_json(directory / "after-recovery.json", after_recovery)
        raise CounterfactualRejection(
            str(exc),
            {
                **proof["facts"],
                "positive_verified": True,
                "counterfactual": True,
                "recovery_verified": True,
                "original_provider_bytes_unchanged": before
                == after_fault
                == after_recovery,
                "audiovisual_review": "UNVERIFIED",
                "coverage": [],
                "execution_artifacts": {
                    "before": before_ref,
                    "positive": positive_record,
                    "counterfactual": counterfactual_ref,
                    "after_fault": artifact_ref(directory / "after-fault.json"),
                    "recovery": recovery_record,
                    "after_recovery": artifact_ref(directory / "after-recovery.json"),
                    "stale_before": stale_before["artifact_ref"],
                    "stale_after": stale_after["artifact_ref"],
                },
            },
        ) from exc
    raise TalkCutError(
        "NEGATIVE_EVIDENCE_UNVERIFIED",
        "Fixed audiovisual counterfactual unexpectedly passed",
    )


def _expected_imports(envelope: dict[str, Any]) -> list[dict[str, Any]]:
    if envelope["case_id"] != "always_keep":
        return [envelope["review_import"]]
    raw = read(envelope["editorial_fixture"])
    result = []
    for fixture in raw["fixtures"]:
        if fixture.get("expectations_review"):
            result.append(fixture["expectations_review"])
        result.extend(fixture.get("deletion_reviews", {}).values())
    return result


def _preserve_positive(
    proof: dict[str, Any],
    envelope: dict[str, Any],
    positive: dict[str, Any],
    destination: Path,
) -> dict[str, str]:
    imports = (
        proof["verified_imports"]
        if envelope["case_id"] == "always_keep"
        else [
            {
                "original": envelope["review_import"],
                "revalidated": proof["import"]["artifact_ref"],
            }
        ]
    )
    observed = (
        {"cases": proof["cases"]}
        if envelope["case_id"] == "always_keep"
        else {
            key: proof[key]
            for key in ("record", "request", "capability", "receipt", "response")
        }
    )
    atomic_json(
        destination,
        {
            "schema_version": "evaluator-positive-revalidation/v2",
            "positive_control": positive,
            "case_id": envelope["case_id"],
            "facts": proof["facts"],
            "observed": observed,
            "review_imports": imports,
        },
    )
    return artifact_ref(destination)


def _normalized_positive(
    ref: dict[str, Any], envelope: dict[str, Any]
) -> dict[str, Any]:
    from datetime import datetime

    value = read(ref)
    require(
        set(value)
        == {
            "schema_version",
            "positive_control",
            "case_id",
            "facts",
            "observed",
            "review_imports",
        }
        and value["schema_version"] == "evaluator-positive-revalidation/v2"
        and value["case_id"] == envelope["case_id"]
        and read(value["positive_control"]) == envelope,
        "Retained positive revalidation differs from the original binding",
    )
    imports = value["review_imports"]
    expected = _expected_imports(envelope)
    require(
        isinstance(imports, list)
        and len(imports) == len(expected)
        and all(
            isinstance(item, dict)
            and set(item) == {"original", "revalidated"}
            and item["original"] == original
            for item, original in zip(imports, expected, strict=True)
        ),
        "Retained positive/recovery import denominator differs",
    )
    normalized = copy.deepcopy(value)
    normalized["review_imports"] = []
    for item in imports:
        original = read(item["original"])["artifact_refs"]
        for original_ref in original.values():
            file(original_ref)
        imported = _retained_import(item["revalidated"], original, fault=False)
        datetime.fromisoformat(imported["imported_at"])
        # Only actual revalidation time and same-byte private import-copy paths
        # differ between fixed subprocess replays. Every other field stays bound.
        normalized["review_imports"].append(
            {
                "original": item["original"],
                "revalidated": {
                    **{
                        key: val
                        for key, val in imported.items()
                        if key not in {"imported_at", "artifact_refs"}
                    },
                    "artifact_refs": original,
                },
            }
        )
    return normalized


def stable_response(
    response: dict[str, Any], positive: dict[str, Any], repo: Path
) -> dict[str, Any]:
    """Validate retained actual files before normalizing private replay paths."""
    facts = response.get("facts", {})
    if facts.get("positive_verified") is not True:
        return response
    envelope = read(positive)
    _subjects(envelope["subjects"], envelope["dependencies"])
    observed = _snapshot(_closure(positive), repo)
    refs = facts.get("execution_artifacts", {})
    fault = facts.get("counterfactual") is True
    required = (
        {
            "before",
            "positive",
            "counterfactual",
            "after_fault",
            "recovery",
            "after_recovery",
            "stale_before",
            "stale_after",
        }
        if fault
        else {"before", "positive", "after"}
    )
    require(
        isinstance(refs, dict) and set(refs) == required,
        "Measured conservation/recovery artifact denominator differs",
    )
    values = {}
    for key, ref in refs.items():
        _closure(ref)
        values[key] = (
            _normalized_positive(ref, envelope)
            if key in {"positive", "recovery"}
            else read(ref)
        )
    for key in (
        {"before", "after_fault", "after_recovery"} if fault else {"before", "after"}
    ):
        require(
            values[key] == observed,
            "Original reference before/after inventory differs from current complete closure",
        )
    require(
        values["positive"]["positive_control"] == positive,
        "Positive observation used another envelope",
    )
    if fault:
        from .provider_failure_checks import STALE_CONTROL_REASON

        require(
            facts.get("recovery_verified") is True
            and facts.get("original_provider_bytes_unchanged") is True
            and values["recovery"] == values["positive"],
            "Actual post-fault positive recovery is missing or changed",
        )
        for key in ("stale_before", "stale_after"):
            require(
                values[key]
                == {
                    "refused": True,
                    "reason": STALE_CONTROL_REASON,
                    "code": "REVIEW_UNVERIFIED",
                },
                "Retained counterfactual became usable as stale approval",
            )
        counterfactual = values["counterfactual"]
        require(
            counterfactual.get("schema_version") == "review-import/v1"
            and counterfactual.get("local_schema")
            == "labelled-evaluator-counterfactual/v2"
            and counterfactual.get("positive_control") == positive
            and counterfactual.get("fault") == FAULTS[envelope["case_id"]]
            and counterfactual.get("test_only") is True
            and counterfactual.get("status") == "UNVERIFIED"
            and counterfactual.get("coverage") == [],
            "Retained counterfactual lost its specific fault or private provenance",
        )
    return {**response, "facts": {**facts, "execution_artifacts": values}}
