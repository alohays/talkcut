"""Collections of original executed source contexts, never aggregate AI receipts."""

from __future__ import annotations

import json
import os
from fractions import Fraction
from itertools import pairwise
from pathlib import Path
from typing import Any

from .contracts import code_identity, verify_contract
from .project import TalkCutError, artifact_ref
from .timeline import as_fraction, union_intervals

COLLECTION_SCHEMA = "lecture-context-collection/v1"
CORE_DEPENDENCIES = {"source_hashes", "code_tree_hash", "contract_hash"}
MAX_CHILDREN = 10000


def _require(condition: Any, reason: str) -> None:
    if not condition:
        raise TalkCutError("CONTEXT_COLLECTION_UNVERIFIED", reason)


def _span(value: Any) -> tuple[Fraction, Fraction]:
    _require(
        isinstance(value, (list, tuple)) and len(value) == 2,
        "Context interval is missing",
    )
    left, right = map(as_fraction, value)
    _require(left < right, "Context interval is empty")
    return left, right


def _strings(values: list[tuple[Fraction, Fraction]]) -> list[list[str]]:
    return [[str(left), str(right)] for left, right in values]


def proposer_ids(value: dict[str, Any]) -> list[str]:
    """Original ids only; plural fields do not fall back to a fabricated id."""
    if "proposer_run_ids" in value:
        ids = value["proposer_run_ids"]
        _require(
            isinstance(ids, list)
            and ids
            and all(isinstance(item, str) and item for item in ids)
            and len(ids) == len(set(ids)),
            "Original proposal execution ids are missing or duplicated",
        )
        _require(
            value.get("proposer_run_id") in (None, ids[0])
            and (len(ids) == 1 or value.get("proposer_run_id") is None),
            "A collection cannot claim one aggregate provider execution",
        )
        return sorted(ids)
    return [value["proposer_run_id"]] if value.get("proposer_run_id") else []


def proposer_prompts(value: dict[str, Any]) -> list[str]:
    if "proposer_prompt_sha256s" in value:
        prompts = value["proposer_prompt_sha256s"]
        _require(
            isinstance(prompts, list)
            and prompts
            and all(isinstance(item, str) and item for item in prompts)
            and len(prompts) == len(set(prompts)),
            "Original proposal prompt hashes are missing or duplicated",
        )
        return sorted(prompts)
    prompt = value.get("proposer_prompt_sha256", value.get("prompt_sha256"))
    return [prompt] if prompt else []


def _execution_evidence(
    ref: dict[str, Any], execution: dict[str, Any]
) -> tuple[set[str], list[dict[str, Any]]]:
    """Read ids from an already validated execution, including actual DAG leaves."""
    from .review import _artifact

    ids = {execution["run_id"]}
    artifacts: dict[tuple[str, str], dict[str, Any]] = {}

    def collect(value: Any) -> None:
        if isinstance(value, dict):
            if (
                isinstance(value.get("path"), str)
                and Path(value["path"]).is_absolute()
                and isinstance(value.get("sha256"), str)
            ):
                artifacts[(value["path"], value["sha256"])] = value
            for child in value.values():
                collect(child)
        elif isinstance(value, list):
            for child in value:
                collect(child)

    collect(ref)
    original = _artifact(ref)
    collect(original)
    collect(execution)
    for key in ("request", "response"):
        collect(_artifact(execution[key]))
    if execution.get("_composite_verified"):
        _require(
            original.get("schema_version") == "composite-review-receipt/v1",
            "Composite original receipt differs",
        )
        leaf_ids: set[str] = set()
        for node_ref in original["nodes"]:
            node = _artifact(node_ref)
            collect(node_ref)
            collect(node)
            leaf = _artifact(node["execution"])
            _require(
                isinstance(leaf.get("run_id"), str) and leaf["run_id"],
                "Actual component execution id is missing",
            )
            _require(
                leaf["run_id"] not in leaf_ids,
                "Composite source proposal reuses a component execution id",
            )
            leaf_ids.add(leaf["run_id"])
            ids.add(leaf["run_id"])
            collect(leaf)
            if leaf.get("request"):
                collect(_artifact(leaf["request"]))
    return ids, [artifacts[key] for key in sorted(artifacts)]


def _partition(
    children: list[dict[str, Any]], domain: tuple[Fraction, Fraction]
) -> list[dict[str, Any]]:
    from .analysis import PROTECTED_KINDS

    boundaries = {domain[0], domain[1]}
    for child in children:
        boundaries.update(_span(child["input_interval"]))
        for item in child["segments"]:
            start, end = _span(child["input_interval"])
            left, right = max(start, as_fraction(item["start"])), min(end, as_fraction(item["end"]))
            if left < right:
                boundaries.update((left, right))
    result = []
    for left, right in pairwise(sorted(boundaries)):
        covering = [
            child
            for child in children
            if _span(child["input_interval"])[0] <= left
            and _span(child["input_interval"])[1] >= right
        ]
        originals = []
        for child in covering:
            observed = [
                (index, item)
                for index, item in enumerate(child["segments"])
                if as_fraction(item["start"]) <= left
                and as_fraction(item["end"]) >= right
            ]
            _require(
                observed, "An input window has no actual observation for a partition"
            )
            for index, item in observed:
                originals.append(
                    {
                        "context": child["context"],
                        "segment_index": index,
                        "segment": item,
                        "proposer": child["proposer"],
                    }
                )
        _require(originals, "Source partition has no actual executed observation")
        originals.sort(
            key=lambda item: (item["context"]["sha256"], item["segment_index"])
        )
        kinds = {row["segment"]["kind"] for row in originals}
        protected = sorted(kinds & PROTECTED_KINDS)
        unknown = any(
            row["segment"].get("uncertain") is True
            or row["segment"].get("needs_source_comparison") is True
            or row["segment"].get("uncertainty") not in (None, False, 0, "none")
            for row in originals
        )
        conflict = len(kinds) != 1
        keep = bool(protected) or unknown or conflict or "uncertain" in kinds
        kind = protected[0] if protected else "uncertain" if keep else next(iter(kinds))
        fields = {
            key
            for row in originals
            for key in row["segment"].get("positive_evidence", {})
        }
        positive = {}
        if not keep:
            for key in fields:
                values = [
                    row["segment"].get("positive_evidence", {}).get(key)
                    for row in originals
                ]
                if all(type(value) is bool and value == values[0] for value in values):
                    positive[key] = values[0]
        refs = {}
        proposers = {}
        for row in originals:
            p = row["proposer"]
            proposers[p["run_id"]] = p
            for ref in [
                row["context"],
                p["receipt"],
                p["capability"],
                p["request"],
                p["response"],
                *row["segment"].get("evidence_refs", []),
            ]:
                refs[(ref["path"], ref["sha256"])] = ref
        result.append(
            {
                "start": str(left),
                "end": str(right),
                "kind": kind,
                "reason": "Preserved: conflicting, uncertain or protected actual source observations"
                if keep
                else "Every covering executed source observation agrees on this activity",
                "positive_evidence": positive,
                "conservative_keep": keep,
                "conflict": conflict,
                "protected_kinds": protected,
                "evidence_refs": [refs[key] for key in sorted(refs)],
                "proposers": [proposers[key] for key in sorted(proposers)],
                "original_observations": originals,
            }
        )
    return result


def verify_context_collection(
    collection: dict[str, Any],
    *,
    source_sha256: str,
    domain: Any,
    expected_dependencies: dict[str, Any],
    repo_root: Path | None = None,
) -> dict[str, Any]:
    """Revalidate each original AV execution and derive its full source coverage.

    ``domain`` and current core dependencies come from the caller's measured
    project/plan. Children may be supplied in any order; returned partitions and
    provenance are canonical. This function never invokes a model.
    """
    from .analysis import CONTEXT_KINDS
    from .review import (
        _artifact,
        _receipt,
        _uncovered,
        verify_context_execution,
        windows,
    )

    repo = (repo_root or Path.cwd()).resolve()
    measured = _span(domain)
    _require(
        isinstance(collection, dict)
        and set(collection)
        == {
            "schema_version",
            "source_sha256",
            "domain",
            "dependencies",
            "contract",
            "capability",
            "children",
        }
        and collection["schema_version"] == COLLECTION_SCHEMA,
        "Unsupported collection schema or self-attested aggregate fields",
    )
    _require(
        collection["source_sha256"] == source_sha256
        and _span(collection["domain"]) == measured,
        "Collection source/domain differs from the measured source",
    )
    deps = collection["dependencies"]
    _require(
        isinstance(deps, dict)
        and CORE_DEPENDENCIES <= set(deps)
        and CORE_DEPENDENCIES <= set(expected_dependencies),
        "Current source/code/contract dependencies are required",
    )
    _require(
        all(deps.get(key) == value for key, value in expected_dependencies.items()),
        "Collection dependencies are not current",
    )
    _require(
        isinstance(deps["source_hashes"], dict)
        and source_sha256 == deps["source_hashes"].get("screen")
        and deps["code_tree_hash"] == code_identity(repo)["code_tree_hash"],
        "Collection source or executing code identity changed",
    )
    contract = _artifact(collection["contract"])
    _require(
        collection["contract"]["sha256"] == deps["contract_hash"]
        and not verify_contract(contract, repo),
        "Collection frozen contract is stale or changed",
    )
    grid = windows(
        measured,
        contract["review"]["window_seconds"],
        contract["review"]["overlap_seconds"],
    )
    refs = collection["children"]
    _require(
        isinstance(refs, list)
        and 0 < len(refs) <= MAX_CHILDREN
        and len(refs) == len(grid),
        "Collection omits or adds required source windows",
    )
    _require(
        all(isinstance(ref, dict) for ref in refs),
        "Child context references must be hashed artifacts",
    )
    _require(
        len({ref.get("sha256") for ref in refs}) == len(refs),
        "Duplicate child context bytes",
    )
    capability = _artifact(collection["capability"])
    capability_execution = _receipt(capability.get("receipt"))
    _require(
        all(
            capability_execution.get("dependencies", {}).get(key) == deps[key]
            for key in ("code_tree_hash", "contract_hash")
        ),
        "Capability was executed under different code or contract",
    )
    children = []
    consumed_windows = set()
    used_runs: set[str] = set()
    capability_ids, final_artifacts = _execution_evidence(
        capability["receipt"], capability_execution
    )
    used_execution_ids = set(capability_ids)
    used_requests: set[tuple[str, str]] = set()
    used_receipts: set[str] = set()
    used_request_bytes: set[str] = set()
    for ref in refs:
        context = _artifact(ref)
        _require(
            context.get("schema_version") == "lecture-context/v1"
            and context.get("source_sha256") == source_sha256
            and context.get("dependencies") == deps
            and context.get("capability") == collection["capability"],
            "Child context source/dependencies/exact capability differ",
        )
        verified = verify_context_execution(context)
        _require(
            verified.get("status") == "PASS",
            "Child AV execution unavailable: " + verified.get("reason", "unverified"),
        )
        request, response, execution = (
            verified[key] for key in ("request", "response", "execution")
        )
        actual_inputs = union_intervals(
            [_span(item["interval"]) for item in request["inputs"]]
        )
        _require(len(actual_inputs) == 1, "Child must contain one complete actual input")
        observed_window = actual_inputs[0]
        window = observed_window
        if request.get("source_window") is not None:
            from .source_window import verify_source_window

            expansion = verify_source_window(request["source_window"],
                source=request["inputs"][0]["parent_media"], domain=[str(x) for x in measured])
            _require(expansion["source"]["sha256"] == source_sha256
                     and _span(expansion["observed_interval"]) == observed_window,
                     "Expanded actual source/window differs")
            window = _span(expansion["requested_interval"])
        _require(window in grid and observed_window[0] <= window[0] < window[1] <= observed_window[1],
                 "Child requested input differs from a complete required window")
        _require(
            window not in consumed_windows,
            "Repeated source window cannot replace a missing window",
        )
        consumed_windows.add(window)
        actual_ids, actual_artifacts = _execution_evidence(
            context["receipt"], execution
        )
        _require(
            not (actual_ids & used_execution_ids),
            "Provider or component execution was reused across calibration/source windows",
        )
        used_execution_ids.update(actual_ids)
        final_artifacts.extend(actual_artifacts)
        request_key = execution["model_revision"], execution["provider_request_id"]
        _require(
            execution["run_id"] not in used_runs
            and request_key not in used_requests
            and context["receipt"]["sha256"] not in used_receipts
            and execution["request"]["sha256"] not in used_request_bytes,
            "Provider execution/receipt/request was reused across source windows",
        )
        used_runs.add(execution["run_id"])
        used_requests.add(request_key)
        used_receipts.add(context["receipt"]["sha256"])
        used_request_bytes.add(execution["request"]["sha256"])
        segments = response["segments"]
        observed = []
        for item in segments:
            span = _span([item["start"], item["end"]])
            _require(
                observed_window[0] <= span[0] < span[1] <= observed_window[1]
                and item.get("kind") in CONTEXT_KINDS
                and isinstance(item.get("reason"), str)
                and item["reason"].strip()
                and isinstance(item.get("positive_evidence", {}), dict),
                "Actual child observation has invalid kind/reason/time/evidence",
            )
            for evidence in item.get("evidence_refs", []):
                _artifact(evidence, binary=True)
            observed.append(span)
        _require(
            not _uncovered(observed_window, observed),
            "Child actual observations omit part of submitted audio/video",
        )
        proposer = {
            "run_id": execution["run_id"],
            "execution_ids": sorted(actual_ids),
            "prompt_sha256": execution["prompt_sha256"],
            "provider_request_id": execution["provider_request_id"],
            "model_revision": execution["model_revision"],
            "context": ref,
            "receipt": context["receipt"],
            "capability": context["capability"],
            "request": execution["request"],
            "response": execution["response"],
        }
        children.append(
            {
                "context": ref,
                "input_interval": [str(x) for x in window],
                "observed_intervals": _strings(union_intervals([(max(a, window[0]), min(b, window[1]))
                    for a, b in observed if max(a, window[0]) < min(b, window[1])])),
                "actual_observed_input_interval": [str(x) for x in observed_window],
                "input_clips": context["input_clips"],
                "proposer": proposer,
                "execution_ids": sorted(actual_ids),
                "segments": segments,
            }
        )
    _require(
        consumed_windows == set(grid), "Required source window denominator differs"
    )
    children.sort(
        key=lambda row: (_span(row["input_interval"]), row["context"]["sha256"])
    )
    partitions = _partition(children, measured)
    # All original top-level artifacts are rehashed at the end. Child validators
    # separately reconstruct submitted media and recheck execution dependencies.
    final_refs = {
        (ref["path"], ref["sha256"]): ref
        for ref in [
            collection["contract"],
            collection["capability"],
            *refs,
            *final_artifacts,
        ]
    }
    for ref in final_refs.values():
        _artifact(ref, binary=True)
    _require(
        deps["code_tree_hash"] == code_identity(repo)["code_tree_hash"],
        "Code changed during collection validation",
    )
    return {
        "status": "PASS",
        "scope": "Executed source-context coverage only; not separate deletion review or owner acceptance",
        "source_sha256": source_sha256,
        "domain": [str(x) for x in measured],
        "dependencies": deps,
        "required_windows": _strings(grid),
        "children": children,
        "segments": partitions,
        "proposer_run_ids": sorted(used_runs),
        "proposer_prompt_sha256s": sorted(
            {row["proposer"]["prompt_sha256"] for row in children}
        ),
        "coverage": {
            "input_intervals": _strings(
                union_intervals([_span(row["input_interval"]) for row in children])
            ),
            "observed_intervals": _strings(
                union_intervals(
                    [
                        _span(span)
                        for row in children
                        for span in row["observed_intervals"]
                    ]
                )
            ),
            "uncovered_intervals": [],
        },
    }


def build_context_collection(
    children: list[dict[str, Any]],
    *,
    source_sha256: str,
    domain: Any,
    dependencies: dict[str, Any],
    contract: dict[str, Any],
    capability: dict[str, Any],
    output: Path,
    repo_root: Path | None = None,
) -> dict[str, Any]:
    """Construct a hash-bound collection only after every child actually validates."""
    collection = {
        "schema_version": COLLECTION_SCHEMA,
        "source_sha256": source_sha256,
        "domain": [str(x) for x in _span(domain)],
        "dependencies": dependencies,
        "contract": contract,
        "capability": capability,
        "children": children,
    }
    result = verify_context_collection(
        collection,
        source_sha256=source_sha256,
        domain=domain,
        expected_dependencies=dependencies,
        repo_root=repo_root,
    )
    collection["children"] = [row["context"] for row in result["children"]]
    _require(
        not output.exists(), "Refusing to overwrite an existing context collection"
    )
    output.parent.mkdir(parents=True, exist_ok=True)
    try:
        with output.open("x") as handle:
            json.dump(collection, handle, ensure_ascii=False, indent=2, allow_nan=False)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
    except FileExistsError as error:
        raise TalkCutError(
            "CONTEXT_COLLECTION_UNVERIFIED",
            "Refusing to overwrite an existing context collection",
        ) from error
    return {
        "schema_version": "context-collection-operation/v1",
        "collection": artifact_ref(output),
        "status": "VERIFIED_SOURCE_CONTEXT",
        "child_count": len(children),
        "coverage": result["coverage"],
        "proposer_run_ids": result["proposer_run_ids"],
        "owner_acceptance": "pending",
    }
