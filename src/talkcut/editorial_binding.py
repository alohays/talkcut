"""Revalidate immutable proposals and current plan decisions for editorial indexing.

A binding records a local verification command, never a provider execution. Every
actual cut still requires separate current audiovisual evidence; no-safe-cuts
requires full-source AV review and a separate audit of every original candidate.
"""

from __future__ import annotations

from fractions import Fraction
from pathlib import Path
from typing import Any

from .analysis import authorize_automatic_candidate, verify_analysis_report
from .context_collection import _execution_evidence, proposer_ids, proposer_prompts
from .contracts import code_identity, verify_contract
from .plan import compile_plan
from .project import (
    TalkCutError,
    content_hash,
    load_project,
    read_json,
    sha256,
    store_artifact,
    verified_json,
)
from .review import (
    _artifact,
    _receipt,
    _uncovered,
    authorize_candidate_review,
    verify_artifact_audit,
    verify_imported_review,
)
from .timeline import as_fraction, subtract_intervals, union_intervals


def require(value: Any, reason: str) -> None:
    if not value:
        raise TalkCutError("EDITORIAL_UNVERIFIED", reason)


def span(value: Any) -> tuple[Fraction, Fraction]:
    if isinstance(value, dict):
        value = [value["start"], value["end"]]
    require(
        isinstance(value, list) and len(value) == 2, "Editorial interval is missing"
    )
    left, right = map(as_fraction, value)
    require(left < right, "Editorial interval is empty")
    return left, right


def intervals(values: Any) -> list[list[str]]:
    return [[str(a), str(b)] for a, b in values]


def current_state(project_dir: Path, repo_root: Path) -> dict[str, Any]:
    """Recompute the complete original analysis and canonical current timeline."""
    project = load_project(project_dir)
    require(
        project.get("owner_acceptance") == "pending", "Owner acceptance is not pending"
    )
    refs = {
        key: project[key] for key in ("active_plan", "active_timeline", "active_render")
    }
    plan, timeline, render = (verified_json(refs[key]) for key in refs)
    require(
        plan.get("test_only") is False and render.get("test_only") is False,
        "Diagnostic/test plans or output cannot bind editorial acceptance",
    )
    require(
        render.get("status") == "RENDERED"
        and render.get("profile") == "master"
        and plan.get("timing", {}).get("status") == "PASS",
        "Current final master is missing",
    )
    require(
        render.get("settings", {}).get("plan") == refs["active_plan"]
        and render.get("settings", {}).get("timeline") == refs["active_timeline"],
        "Current output was rendered from another plan or timeline",
    )
    _artifact(render.get("output"), binary=True)
    require(
        compile_plan(project, plan) == timeline,
        "Current timeline differs from the measured plan",
    )
    analysis_ref = plan.get("analysis_ref")
    require(
        analysis_ref == project.get("analysis"),
        "Active plan does not use the current original analysis",
    )
    analysis = verified_json(analysis_ref)
    regenerated = verify_analysis_report(analysis_ref, plan)
    require(
        regenerated.get("status") == "ANALYZED"
        and analysis.get("source_kind") == "real"
        and not analysis.get("test_only"),
        "Complete original real-source analysis is unavailable",
    )
    require(
        proposer_ids(analysis) and proposer_prompts(analysis),
        "Original proposer identities are missing",
    )
    contract_path = project_dir / "frozen-contract.local.json"
    contract = read_json(contract_path)
    require(
        not verify_contract(contract, repo_root), "Frozen editorial contract changed"
    )
    hashes = {key: item["sha256"] for key, item in project["sources"].items()}
    for item in project["sources"].values():
        _artifact(item, binary=True)
    require(
        plan["source_hashes"] == hashes
        and plan.get("contract_hash") == sha256(contract_path),
        "Plan source or contract identity changed",
    )
    require(
        timeline.get("plan_hash") == content_hash(plan),
        "Timeline plan identity differs",
    )
    dependencies = {
        "source_hashes": hashes,
        "contract_hash": sha256(contract_path),
        "code_tree_hash": code_identity(repo_root)["code_tree_hash"],
        "plan_hash": content_hash(plan),
        "timeline_hash": refs["active_timeline"]["sha256"],
        "output_hash": render["output"]["sha256"],
    }
    original = regenerated["candidates"]
    candidates = plan.get("candidates", [])
    require(
        isinstance(candidates, list)
        and len({c.get("id") for c in candidates}) == len(candidates),
        "Plan candidates are missing or duplicated",
    )
    require(
        {c["id"] for c in candidates} == {c["id"] for c in original},
        "Plan added or dropped an original source candidate",
    )
    by_id = {c["id"]: c for c in original}
    for candidate in candidates:
        require(
            {
                k: v
                for k, v in candidate.items()
                if k not in {"decision", "decision_evidence"}
            }
            == by_id[candidate["id"]],
            "Plan changed original candidate evidence or boundaries",
        )
        require(
            candidate.get("decision") in {"proposed", "accepted", "kept", "restored"},
            "Unknown actual plan decision",
        )
    domain = (
        as_fraction(timeline["domain"]["start"]),
        as_fraction(timeline["domain"]["end"]),
    )
    require(
        span(analysis["domain"]) == domain,
        "Analysis denominator differs from current source timeline",
    )
    require(
        not subtract_intervals(domain, [span(row) for row in analysis["segments"]]),
        "Original source analysis has uncovered intervals",
    )
    retained = [
        (as_fraction(row["source_start"]), as_fraction(row["source_end"]))
        for row in timeline["retained"]
    ]
    cuts = timeline.get("cuts", [])
    accepted = {c["id"]: c for c in candidates if c["decision"] == "accepted"}
    require(
        len(cuts) == len(accepted) and {c["id"] for c in cuts} == set(accepted),
        "Actual compiled cuts do not match accepted plan candidate IDs",
    )
    applied = []
    for cut in cuts:
        candidate = accepted[cut["id"]]
        requested = (
            as_fraction(cut["requested_start"]),
            as_fraction(cut["requested_end"]),
        )
        require(
            requested == span(candidate),
            "Compiled cut requested boundaries differ from its candidate",
        )
        require(
            cut.get("status") in {"applied", "kept_below_frame_resolution"},
            "Unknown compiled cut disposition",
        )
        if cut["status"] == "applied":
            effective = span(cut)
            require(
                requested[0] <= effective[0] < effective[1] <= requested[1],
                "Effective deletion exceeds its reviewed requested boundary",
            )
            evidence = candidate.get("decision_evidence", {})
            expected_actor = (
                "delegated_policy"
                if candidate["policy_action"] == "auto_apply"
                else "delegated_ai_reviewer"
            )
            require(
                evidence.get("actor") == expected_actor
                and evidence.get("at")
                and candidate.get("reason"),
                "Actual accepted decision lacks its authorized actor or reason",
            )
            if candidate["policy_action"] != "auto_apply":
                # Historical decision inputs remain immutable. Current authority
                # is replayed separately against the final plan below.
                verified_json(evidence.get("review"))
            applied.append(cut)
    deletions = subtract_intervals(domain, retained)
    require(
        union_intervals([span(c) for c in applied]) == deletions,
        "Retained source complement differs from the candidate-linked effective cuts",
    )
    protected = [span(row) for row in regenerated["protected_intervals"]]
    require(
        all(b <= c or a >= d for a, b in deletions for c, d in protected),
        "An effective deletion removes protected source content",
    )
    snapshot = {
        "schema_version": "editorial-snapshot/v1",
        "project": str(project_dir.resolve()),
        "analysis": analysis_ref,
        "plan": refs["active_plan"],
        "timeline": refs["active_timeline"],
        "render": refs["active_render"],
        "output": render["output"],
        "dependencies": dependencies,
        "source_domain": intervals([domain])[0],
        "candidates": [
            {
                "id": c["id"],
                "requested_interval": intervals([span(c)])[0],
                "decision": c["decision"],
                "policy_action": c["policy_action"],
            }
            for c in candidates
        ],
        "cuts": cuts,
        "retained": intervals(retained),
        "protected": intervals(protected),
        "owner_acceptance": "pending",
    }
    return {
        "project": project,
        "plan": plan,
        "analysis": analysis,
        "regenerated": regenerated,
        "timeline": timeline,
        "snapshot": snapshot,
        "applied": applied,
        "deletions": deletions,
        "domain": domain,
    }


def prepare_editorial(project_dir: Path, repo_root: Path) -> dict[str, Any]:
    state = current_state(project_dir, repo_root)
    ref = store_artifact(project_dir, "editorial/snapshots", state["snapshot"])
    return {
        "schema_version": "editorial-preparation/v1",
        "status": "PREPARED",
        "snapshot": ref,
        "acceptance_status": "UNVERIFIED",
        "owner_acceptance": "pending",
    }


def proposal_executions(analysis: dict[str, Any]) -> set[str]:
    ids = set(proposer_ids(analysis))

    def collect(value: Any) -> None:
        if isinstance(value, dict):
            ids.update(value.get("execution_ids", []))
            for item in value.values():
                collect(item)
        elif isinstance(value, list):
            for item in value:
                collect(item)

    if analysis.get("context_verification"):
        collect(analysis["context_verification"])
    else:
        context = analysis.get("context") or {}
        execution = _receipt(context.get("receipt"))
        actual_ids, _ = _execution_evidence(context["receipt"], execution)
        ids.update(actual_ids)
    return ids


def verify_editorial_inputs(
    project_dir: Path,
    snapshot_ref: dict[str, Any],
    review_refs: list[dict[str, Any]],
    audit_ref: dict[str, Any] | None,
    repo_root: Path,
) -> dict[str, Any]:
    state = current_state(project_dir, repo_root)
    snapshot, analysis, plan = state["snapshot"], state["analysis"], state["plan"]
    require(
        verified_json(snapshot_ref) == snapshot,
        "Editorial snapshot is stale against current artifacts",
    )
    require(
        len({content_hash(ref) for ref in review_refs}) == len(review_refs),
        "Duplicate editorial review imports",
    )
    excluded = proposal_executions(analysis)
    current_reviews = []
    for ref in review_refs:
        proof = verify_imported_review(ref)
        record, request, receipt = (proof[k] for k in ("record", "request", "receipt"))
        require(
            record.get("reviewer_role") == "adversarial_reviewer"
            and not any(record.get(k) for k in ("test_only", "synthetic", "mock")),
            "Actual separate audiovisual review is required",
        )
        require(
            all(
                request["dependencies"].get(k) == v
                for k, v in snapshot["dependencies"].items()
            ),
            "Editorial review is stale against the final source/code/contract/plan/timeline/output",
        )
        require(
            request.get("scope") in {"analysis", "deletion"},
            "Editorial review has an unrelated scope",
        )
        require(
            request.get("inputs")
            and all(
                item.get("parent_sha256") == plan["source_hashes"]["screen"]
                for item in request["inputs"]
            ),
            "Editorial source review does not use the actual primary screen source",
        )
        observed = [span(value) for value in proof["response"]["observed_intervals"]]
        require(
            observed
            and all(
                state["domain"][0] <= a < b <= state["domain"][1] for a, b in observed
            ),
            "Editorial review observations exceed the complete source denominator",
        )
        actual_ids, _ = _execution_evidence(record["receipt"], receipt)
        require(
            not actual_ids.intersection(excluded),
            "Editorial review reuses an original proposal execution",
        )
        imported = verified_json(ref)
        current_reviews.append(
            {
                "ref": ref,
                "proof": proof,
                "record_ref": imported["artifact_refs"]["record"],
                "capability_ref": imported["artifact_refs"]["capability"],
            }
        )
    applied_ids = {cut["id"] for cut in state["applied"]}
    deletion_reviews = {}
    for row in current_reviews:
        request = row["proof"]["request"]
        if request["scope"] == "deletion":
            candidate_id = request.get("details", {}).get("candidate_id")
            require(
                candidate_id in applied_ids and candidate_id not in deletion_reviews,
                "Deletion review targets no actual cut or duplicates a candidate",
            )
            deletion_reviews[candidate_id] = row
    require(
        set(deletion_reviews) == applied_ids,
        "Every actual cut needs a separate current candidate-specific AV review",
    )
    by_id = {c["id"]: c for c in plan["candidates"]}
    for cut in state["applied"]:
        candidate = by_id[cut["id"]]
        if candidate["policy_action"] == "auto_apply":
            authorize_automatic_candidate(snapshot["analysis"], candidate, plan)
        authorize_candidate_review(
            deletion_reviews[candidate["id"]]["ref"], candidate, plan
        )
        observed = [
            span(v)
            for v in deletion_reviews[candidate["id"]]["proof"]["response"][
                "observed_intervals"
            ]
        ]
        require(
            not _uncovered(span(cut), observed),
            "Review omits an effective actual deletion",
        )
    source_reviews = [
        row for row in current_reviews if row["proof"]["request"]["scope"] == "analysis"
    ]
    disposition = "EDITED" if state["applied"] else "NO_SAFE_CUTS_VERIFIED"
    if not state["applied"]:
        require(
            audit_ref is not None and source_reviews,
            "No-safe-cuts needs complete source AV review and a separate candidate audit",
        )
        source_spans: list[tuple[Fraction, Fraction]] = []
        review_ids = set()
        for row in source_reviews:
            proof = row["proof"]
            require(
                proposer_ids(proof["record"]) == proposer_ids(analysis)
                and proposer_prompts(proof["record"]) == proposer_prompts(analysis),
                "Full-source review does not preserve all original proposer identities",
            )
            source_spans.extend(
                span(v) for v in proof["response"]["observed_intervals"]
            )
            actual_ids, _ = _execution_evidence(
                proof["record"]["receipt"], proof["receipt"]
            )
            review_ids.update(actual_ids)
        require(
            not subtract_intervals(state["domain"], source_spans),
            "No-safe-cuts AV review omits original source intervals",
        )
        inputs = [snapshot[k] for k in ("analysis", "plan", "timeline", "output")]
        inputs += [row["record_ref"] for row in source_reviews]
        assert audit_ref is not None
        audit = verify_artifact_audit(
            audit_ref,
            scope="no_safe_cuts",
            snapshot_ref=snapshot_ref,
            input_refs=inputs,
            dependencies=snapshot["dependencies"],
            excluded_run_ids=excluded | review_ids,
        )
        audit_ids, _ = _execution_evidence(
            audit["envelope"]["receipt"], audit["receipt"]
        )
        require(
            not audit_ids.intersection(excluded | review_ids),
            "No-safe-cuts audit reuses a proposal or audiovisual review execution component",
        )
        response = audit["response"]
        decisions = response.get("candidate_decisions", [])
        require(
            isinstance(decisions, list)
            and len(decisions) == len(plan["candidates"])
            and {row.get("candidate_id") for row in decisions} == set(by_id),
            "No-safe-cuts audit did not assess every original candidate",
        )
        for row in decisions:
            require(
                row.get("decision") in {"keep", "reject_deletion"}
                and span(row.get("requested_interval"))
                == span(by_id[row["candidate_id"]])
                and isinstance(row.get("reason"), str)
                and len(row["reason"].strip()) >= 30,
                "No-safe-cuts candidate decision or original boundary is unsupported",
            )
        require(
            response.get("analysis_available") is True
            and response.get("all_candidates_reviewed") is True
            and isinstance(response.get("no_safe_cuts_reason"), str)
            and len(response["no_safe_cuts_reason"].strip()) >= 30,
            "No-safe-cuts exception lacks actual all-candidate observations",
        )
    else:
        require(
            audit_ref is None,
            "Edited output cannot be relabeled using a no-safe-cuts audit",
        )
    # Stable result: replay-generated imports/authorization timestamps stay in
    # their original validators' evidence directories, not in this comparison.
    return {
        "schema_version": "editorial-verification/v1",
        "snapshot": snapshot_ref,
        "dependencies": snapshot["dependencies"],
        "analysis": snapshot["analysis"],
        "plan": snapshot["plan"],
        "timeline": snapshot["timeline"],
        "output": snapshot["output"],
        "review_imports": review_refs,
        "review_records": [r["record_ref"] for r in current_reviews],
        "capabilities": [r["capability_ref"] for r in current_reviews],
        "no_safe_cuts_audit": audit_ref,
        "edit_disposition": disposition,
        "actual_deletions": intervals(state["deletions"]),
        "applied_candidate_ids": sorted(applied_ids),
        "candidate_count": len(plan["candidates"]),
        "protected_count": len(snapshot["protected"]),
        "segment_count": len(analysis["segments"]),
        "owner_acceptance": "pending",
    }


def verify_editorial_binding(
    binding_ref: dict[str, Any], project_dir: Path, repo_root: Path
) -> dict[str, Any]:
    record = verified_json(binding_ref)
    require(
        set(record) == {"schema_version", "verification", "receipt", "owner_acceptance"}
        and record["schema_version"] == "editorial-binding/v1"
        and record["owner_acceptance"] == "pending",
        "Typed editorial command binding is missing",
    )
    recorded = verified_json(record["verification"])
    from .editorial_execution import verify_editorial_execution

    verify_editorial_execution(record, recorded, project_dir, repo_root)
    current = verify_editorial_inputs(
        project_dir,
        recorded["snapshot"],
        recorded["review_imports"],
        recorded["no_safe_cuts_audit"],
        repo_root,
    )
    require(
        recorded == current,
        "Editorial binding differs from current policy/review recomputation",
    )
    return current
