"""Executed editorial fixtures with independently observed expectations.

Authored scenario labels and policy-only tests are not audiovisual ground truth.
The nonverbal generator exercises real media/acoustics and intentionally cannot
certify speech, editorial meaning or AC06 without separate actual AV imports.
"""

from __future__ import annotations

import subprocess
from fractions import Fraction
from pathlib import Path
from typing import Any
from uuid import uuid4

from .analysis import analyze_source, detect_silence
from .contracts import CHECK_REQUIREMENTS, code_identity
from .media import inspect_source
from .project import TalkCutError, artifact_ref, atomic_json, now
from .review import (
    _artifact,
    _uncovered,
    verify_context_execution,
    verify_imported_review,
)
from .timeline import as_fraction

KINDS = {
    "preparation": "positive_preparation_pass",
    "silence": "positive_silence_pass",
    "disfluency": "positive_disfluency_pass",
    "demo": "negative_demo_pass",
    "question_wait": "negative_question_wait_pass",
    "negation": "negative_negation_pass",
    "correction": "negative_correction_pass",
    "emphasis": "negative_emphasis_pass",
}
POSITIVE = {"preparation", "silence", "disfluency"}
LEDGER_KEYS = (
    "schema_version",
    "source_kind",
    "source_hashes",
    "source_sha256",
    "domain",
    "status",
    "edit_disposition",
    "coverage",
    "proposer_run_id",
    "prompt_sha256",
    "segments",
    "protected_intervals",
    "protected",
    "candidates",
    "acoustic_ref",
    "context",
    "transcript",
    "owner_acceptance",
    "test_only",
)


def _require(value: Any, reason: str) -> None:
    if not value:
        raise TalkCutError("EDITORIAL_FIXTURE_UNVERIFIED", reason)


def _span(value: Any) -> tuple[Fraction, Fraction]:
    if isinstance(value, dict):
        span = as_fraction(value["start"]), as_fraction(value["end"])
    else:
        span = as_fraction(value[0]), as_fraction(value[1])
    _require(span[0] < span[1], "Fixture interval must be positive")
    return span


def _expected_cases(
    expectations: dict[str, Any], source_hash: str, domain: tuple[Fraction, Fraction]
) -> list[dict[str, Any]]:
    _require(
        expectations.get("schema_version") == "editorial-expectations/v1"
        and expectations.get("source_sha256") == source_hash
        and expectations.get("author_run_id")
        and expectations.get("ground_truth_claim")
        == "authored_scenarios_pending_independent_av_review",
        "Expected cases need explicit authorship and an actual source identity",
    )
    cases = expectations.get("cases", [])
    _require(
        isinstance(cases, list) and cases, "Fixture expected-case denominator is empty"
    )
    _require(
        len({item["id"] for item in cases}) == len(cases), "Duplicate fixture case ids"
    )
    for case in cases:
        a, b = _span(case)
        _require(
            case.get("kind") in KINDS
            and case.get("expected_action")
            == ("cut" if case["kind"] in POSITIVE else "keep")
            and domain[0] <= a < b <= domain[1]
            and isinstance(case.get("scenario"), str)
            and len(case["scenario"].strip()) >= 30,
            "Fixture case changes policy expectations or lies outside source media",
        )
    return cases


def _bind_fixture_review(
    proof: dict[str, Any],
    fixture: dict[str, Any],
    dependencies: dict[str, Any],
    domain: tuple[Fraction, Fraction],
) -> None:
    request, response = proof["request"], proof["response"]
    _require(
        request.get("dependencies") == dependencies
        and all(
            item.get("parent_sha256") == fixture["source"]["sha256"]
            for item in request["inputs"]
        )
        and bool(request["inputs"]),
        "Fixture review belongs to different source bytes or dependencies",
    )
    _require(
        not _uncovered(domain, [_span(span) for span in request.get("intervals", [])])
        and not _uncovered(
            domain, [_span(span) for span in response.get("observed_intervals", [])]
        ),
        "Fixture review omits part of the actual source denominator",
    )


def _audited_expectations(
    fixture: dict[str, Any],
    expected: dict[str, Any],
    context: dict[str, Any],
    dependencies: dict[str, Any],
    domain: tuple[Fraction, Fraction],
) -> dict[str, Any] | None:
    ref = fixture.get("expectations_review")
    if not ref:
        return None
    proof = verify_imported_review(ref)
    _bind_fixture_review(proof, fixture, dependencies, domain)
    request, response, receipt = proof["request"], proof["response"], proof["receipt"]
    _require(
        request.get("scope") == "analysis"
        and request.get("details", {}).get("fixture_expectations")
        == fixture["expectations"]
        and request.get("details", {}).get("fixture_provenance")
        == fixture["provenance"]
        and receipt["run_id"]
        not in {expected["author_run_id"], context["proposer_run_id"]},
        "Expected labels were not separately reviewed with their actual provenance",
    )
    # These are exact artifacts actually included in the preserved provider request.
    submitted = request.get("input_artifacts", [])
    for artifact in submitted:
        _artifact(artifact, binary=True)
    _require(
        all(
            ref in submitted for ref in [fixture["expectations"], fixture["provenance"]]
        ),
        "The expectation auditor did not receive the authored scenario and licensing artifacts",
    )
    licensing = response.get("fixture_license_observation", {})
    _require(
        licensing.get("provenance") == fixture["provenance"]
        and licensing.get("source_sha256") == fixture["source"]["sha256"]
        and licensing.get("redistributable") is True
        and len(licensing.get("reason", "").strip()) >= 30,
        "Fixture redistribution provenance has no substantive independent observation",
    )
    observations = response.get("fixture_expectations", [])
    _require(
        isinstance(observations, list)
        and {item.get("case_id") for item in observations}
        == {case["id"] for case in expected["cases"]}
        and len(observations) == len(expected["cases"]),
        "Independent expected-case coverage is incomplete or duplicated",
    )
    for case in expected["cases"]:
        observed = next(item for item in observations if item["case_id"] == case["id"])
        _require(
            all(
                observed.get(key) == case[key]
                for key in ("kind", "start", "end", "expected_action")
            )
            and observed.get("expectation_supported") is True
            and len(observed.get("observed_source_behavior", "").strip()) >= 30,
            "Independent source observation does not establish the authored case expectation",
        )
    return proof


def _case_outcome(
    case: dict[str, Any],
    report: dict[str, Any],
    fixture: dict[str, Any],
    dependencies: dict[str, Any],
    domain: tuple[Fraction, Fraction],
) -> bool | None:
    span = _span(case)
    candidates = [item for item in report["candidates"] if _span(item) == span]
    kind = case["kind"]
    if kind not in POSITIVE:
        protected = [
            _span(item)
            for item in report["protected_intervals"]
            if item.get("kind") == kind
        ]
        return not _uncovered(span, protected) and not any(
            item["policy_action"] != "keep"
            and _span(item)[0] < span[1]
            and _span(item)[1] > span[0]
            for item in report["candidates"]
        )
    matching = [item for item in candidates if item["kind"] == kind]
    if kind != "disfluency":
        return any(item["policy_action"] == "auto_apply" for item in matching)
    if not matching or not all(
        item["policy_action"] == "requires_review" for item in matching
    ):
        return False
    review_ref = fixture.get("deletion_reviews", {}).get(case["id"])
    if not review_ref:
        return None
    proof = verify_imported_review(review_ref)
    request, response, execution = proof["request"], proof["response"], proof["receipt"]
    candidate = matching[0]
    details = request.get("details", {})
    _require(
        request.get("scope") == "deletion"
        and request.get("dependencies") == dependencies
        and execution["run_id"] != report["proposer_run_id"]
        and proof["record"].get("proposer_run_id") == report["proposer_run_id"]
        and details.get("candidate_id") == candidate["id"]
        and _span(details.get("requested_interval")) == span
        and details.get("fixture_expectations") == fixture["expectations"]
        and response.get("candidate_id") == candidate["id"]
        and response.get("candidate_decision") == "approve_deletion"
        and response.get("complete_sentence_context") is True,
        "Disfluency lacks a separate actual reviewer bound to this candidate and expected case",
    )
    context = max(domain[0], span[0] - 5), min(domain[1], span[1] + 5)
    _require(
        not _uncovered(context, [_span(item) for item in request["intervals"]])
        and all(
            item["parent_sha256"] == fixture["source"]["sha256"]
            for item in request["inputs"]
        ),
        "Disfluency review omits original source or required surrounding context",
    )
    return True


def _selection_matches(
    cases: list[dict[str, Any]],
    selected: list[tuple[Fraction, Fraction]],
    *,
    complete_ledger: bool,
) -> bool:
    if not cases or not complete_ledger:
        return False
    for case in cases:
        span = _span(case)
        if case["expected_action"] == "cut":
            if _uncovered(span, selected):
                return False
        elif any(a < span[1] and b > span[0] for a, b in selected):
            return False
    return True


def verify_editorial_fixtures(
    raw: dict[str, Any], repo_root: Path, output_dir: Path
) -> dict[str, bool | None]:
    """Re-decode sources and recompute policy; missing actual AV remains null.

    Every supplied case contributes to its kind's denominator, so a passing case
    cannot hide a failed case. No fixture passes on authored labels alone.
    """
    _require(
        raw.get("schema_version") == "editorial-fixture-input/v1",
        "Typed editorial fixture inputs required",
    )
    dependencies = raw.get("dependencies", {})
    _require(
        dependencies.get("code_tree_hash")
        == code_identity(repo_root)["code_tree_hash"],
        "Editorial fixture code identity is stale",
    )
    fixtures = raw.get("fixtures", [])
    _require(
        isinstance(fixtures, list) and fixtures, "No actual editorial fixtures supplied"
    )
    _require(
        len({item["id"] for item in fixtures}) == len(fixtures),
        "Duplicate fixture identities",
    )
    directory = output_dir / uuid4().hex
    directory.mkdir(parents=True)
    all_values: dict[str, list[bool | None]] = {kind: [] for kind in KINDS}
    audits: list[bool | None] = []
    raw_results: list[dict[str, Any]] = []
    controls: list[dict[str, bool]] = []
    for index, fixture in enumerate(fixtures):
        target = directory / str(index)
        source_path = _artifact(fixture["source"], binary=True)
        provenance = _artifact(fixture["provenance"])
        _require(
            provenance.get("schema_version") == "fixture-provenance/v1"
            and provenance.get("source") == fixture["source"]
            and provenance.get("license_expression")
            in {"MIT", "Apache-2.0", "CC0-1.0", "CC-BY-4.0"}
            and provenance.get("origin")
            in {"procedurally_generated", "licensed_recording"},
            "Actual source and explicit permissive fixture provenance are required",
        )
        _require(
            _artifact(provenance.get("license"), binary=True).stat().st_size > 50,
            "Fixture license text is missing",
        )
        _artifact(provenance.get("creation_evidence"), binary=True)
        _artifact(provenance.get("scenario_script"), binary=True)
        inspected = inspect_source(source_path, target / "inspection", decode=True)
        _require(
            inspected["status"] == "PASS",
            "Whole fixture A/V decode or PTS inventory failed",
        )
        origin = as_fraction(fixture.get("screen_origin", "0"))
        domain = tuple(as_fraction(x) - origin for x in inspected["video"]["coverage"])
        assert len(domain) == 2
        actual_domain = domain[0], domain[1]
        _require(
            _span(fixture["domain"]) == actual_domain,
            "Fixture truncates the actual source denominator",
        )
        expected = _artifact(fixture["expectations"])
        cases = _expected_cases(expected, fixture["source"]["sha256"], actual_domain)
        recorded = _artifact(fixture["analysis"])
        acoustic_ref = recorded.get("acoustic_ref")
        acoustic = _artifact(acoustic_ref)
        acoustic["artifact_ref"] = acoustic_ref
        source = {**fixture["source"], "role": "screen"}
        _require(
            acoustic.get("source_sha256") == source["sha256"]
            and Path(acoustic["source_path"]).resolve() == source_path.resolve()
            and acoustic.get("stream_index") == inspected["audio"]["index"]
            and as_fraction(acoustic.get("offset")) == -origin,
            "Acoustic execution uses a different source, stream or common clock",
        )
        measured = detect_silence(
            source,
            inspected["audio"]["index"],
            fixture["domain"],
            target,
            noise_db=acoustic["noise_db"],
            min_seconds=acoustic["min_seconds"],
            offset=-origin,
        )
        for key in ("completed", "status", "intervals", "coverage", "domain"):
            _require(
                acoustic.get(key) == measured[key],
                f"Recorded acoustic {key} differs from actual full-source execution",
            )
        context = recorded.get("context")
        _require(
            not recorded.get("test_only") and recorded.get("source_kind") == "real",
            "Policy-only mocked fixture context cannot establish actual editorial evidence",
        )
        _require(
            not context or not context.get("test_only"),
            "Mock context cannot establish actual editorial expectations",
        )
        report = analyze_source(
            source,
            fixture["domain"],
            acoustic,
            context,
            transcript=recorded.get("transcript"),
        )
        _require(
            all(recorded.get(key) == report.get(key) for key in LEDGER_KEYS),
            "Recorded full analysis ledger differs from current source policy",
        )
        available = report["status"] == "ANALYZED"
        audited: dict[str, Any] | None = None
        if available:
            assert isinstance(context, dict)
            _require(
                verify_context_execution(context)["status"] == "PASS",
                "Actual AV context execution is unavailable",
            )
            _require(
                context.get("dependencies")
                == {**dependencies, "source_hashes": {"screen": source["sha256"]}},
                "Context source/code/contract dependency identity differs",
            )
            fixture_deps = context["dependencies"]
            audited = _audited_expectations(
                fixture, expected, context, fixture_deps, actual_domain
            )
        else:
            fixture_deps = {
                **dependencies,
                "source_hashes": {"screen": source["sha256"]},
            }
            _require(
                not fixture.get("expectations_review"),
                "Expectation PASS cannot replace missing full actual context analysis",
            )
        audits.append(True if audited else None)
        outcomes = {}
        for case in cases:
            outcome = (
                _case_outcome(case, report, fixture, fixture_deps, actual_domain)
                if audited
                else None
            )
            all_values[case["kind"]].append(outcome)
            outcomes[case["id"]] = outcome
        if audited and all(value is True for value in outcomes.values()):
            selected = [
                _span(case) for case in cases if case["expected_action"] == "cut"
            ]
            _require(
                _selection_matches(cases, selected, complete_ledger=True),
                "Actual policy positive control does not match the independently observed cases",
            )
            controls.append(
                {
                    "always_keep_rejected": not _selection_matches(
                        cases, [], complete_ledger=True
                    ),
                    "always_cut_rejected": not _selection_matches(
                        cases, [actual_domain], complete_ledger=True
                    ),
                    "empty_analysis_rejected": not _selection_matches(
                        cases, selected, complete_ledger=False
                    ),
                }
            )
        raw_results.append(
            {
                "fixture_id": fixture["id"],
                "source": fixture["source"],
                "inspection": artifact_ref(target / "inspection" / "inspection.json"),
                "acoustic": measured["artifact_ref"],
                "analysis_status": report["status"],
                "case_outcomes": outcomes,
                "independent_expectations": bool(audited),
            }
        )
    result: dict[str, bool | None] = {
        key: None for key in CHECK_REQUIREMENTS["editorial_fixture"]
    }
    for kind, values in all_values.items():
        if values:
            result[KINDS[kind]] = (
                False
                if False in values
                else (True if all(value is True for value in values) else None)
            )
    complete_positive = all(result[KINDS[kind]] is True for kind in POSITIVE)
    complete_negative = all(
        result[KINDS[kind]] is True for kind in set(KINDS) - POSITIVE
    )
    result["independently_reviewed_expectations"] = (
        True
        if all(value is True for value in audits) and all(all_values.values())
        else None
    )
    # Compare degenerate selectors only after the complete independent real-media
    # positive/negative expectations are established. A labels-only test cannot
    # make the missing positive AV control disappear.
    if complete_positive and complete_negative:
        for key in (
            "always_keep_rejected",
            "always_cut_rejected",
            "empty_analysis_rejected",
        ):
            result[key] = any(control[key] for control in controls)
    atomic_json(
        directory / "result.json",
        {
            "schema_version": "editorial-fixture-validation/v1",
            "dependencies": dependencies,
            "measurements": result,
            "fixtures": raw_results,
            "test_only": True,
            "status": "PASS"
            if all(value is True for value in result.values())
            else "UNVERIFIED",
            "owner_acceptance": "pending",
            "scope": "Only supplied actual editorial fixtures; never DGIST acceptance",
        },
    )
    return result


def generate_nonverbal_fixture(output_dir: Path, repo_root: Path) -> dict[str, Any]:
    """Create actual procedural A/V and run acoustics; semantic checks stay open."""
    directory = output_dir / f"editorial-nonverbal-{uuid4().hex}"
    directory.mkdir(parents=True)
    source_path = directory / "source.mp4"
    argv = [
        "ffmpeg",
        "-nostdin",
        "-v",
        "error",
        "-n",
        "-f",
        "lavfi",
        "-i",
        "color=c=black:s=320x180:r=25:d=18",
        "-f",
        "lavfi",
        "-i",
        "testsrc2=s=320x180:r=25:d=18",
        "-f",
        "lavfi",
        "-i",
        "aevalsrc=if(between(t\\,4\\,6)+between(t\\,10\\,11)+between(t\\,15\\,18)\\,0.15*sin(2*PI*440*t)\\,0):s=48000:d=18",
        "-filter_complex",
        "[0:v][1:v]overlay=enable='gte(t,11)':shortest=1[v]",
        "-map",
        "[v]",
        "-map",
        "2:a",
        "-c:v",
        "libx264",
        "-preset",
        "ultrafast",
        "-pix_fmt",
        "yuv420p",
        "-c:a",
        "aac",
        str(source_path),
    ]
    started = now()
    process = subprocess.run(argv, capture_output=True, timeout=90, check=False)
    (directory / "generation.stdout.log").write_bytes(process.stdout)
    (directory / "generation.stderr.log").write_bytes(process.stderr)
    execution = {
        "argv": argv,
        "started_at": started,
        "finished_at": now(),
        "exit_code": process.returncode,
        "stdout": artifact_ref(directory / "generation.stdout.log"),
        "stderr": artifact_ref(directory / "generation.stderr.log"),
        "producer": artifact_ref(Path(__file__).resolve()),
        "code_identity": code_identity(repo_root),
    }
    atomic_json(directory / "generation.json", execution)
    _require(process.returncode == 0, "Actual procedural A/V fixture generation failed")
    source = artifact_ref(source_path)
    script = directory / "scenario.txt"
    script.write_text(
        "Procedural mathematical fixture, no external media, speech or people. Black screen initially; a moving test pattern begins at 11 seconds. Generated sine tone occurs at 4-6, 10-11 and 15-18 seconds; intervening PCM samples are zero before AAC encoding. The planned preparation/pause/demo labels need independent actual audiovisual observation. This is not human-labelled lecture ground truth.\n"
    )
    provenance = {
        "schema_version": "fixture-provenance/v1",
        "source": source,
        "origin": "procedurally_generated",
        "license_expression": "MIT",
        "license": artifact_ref(repo_root / "LICENSE"),
        "creation_evidence": artifact_ref(directory / "generation.json"),
        "scenario_script": artifact_ref(script),
    }
    atomic_json(directory / "provenance.json", provenance)
    domain = ["0", "18"]
    acoustic = detect_silence({**source, "role": "screen"}, 1, domain, directory)
    report = analyze_source({**source, "role": "screen"}, domain, acoustic)
    atomic_json(directory / "analysis.json", report)
    expected = {
        "schema_version": "editorial-expectations/v1",
        "source_sha256": source["sha256"],
        "author_run_id": directory.name,
        "ground_truth_claim": "authored_scenarios_pending_independent_av_review",
        "cases": [
            {
                "id": "preparation",
                "kind": "preparation",
                "start": "0",
                "end": "4",
                "expected_action": "cut",
                "scenario": "Authored initial blank nonverbal preparation interval; real AV reviewer must establish whether it is disposable.",
            },
            {
                "id": "pause",
                "kind": "silence",
                "start": "6",
                "end": "10",
                "expected_action": "cut",
                "scenario": "Authored blank silent interval between generated tones; requires independent actual complete context inspection.",
            },
            {
                "id": "demo",
                "kind": "demo",
                "start": "11",
                "end": "15",
                "expected_action": "keep",
                "scenario": "Silent moving test pattern represents an authored demonstration; silence alone must not remove visual activity.",
            },
        ],
    }
    atomic_json(directory / "expectations.json", expected)
    raw = {
        "schema_version": "editorial-fixture-input/v1",
        "dependencies": {"code_tree_hash": code_identity(repo_root)["code_tree_hash"]},
        "fixtures": [
            {
                "id": directory.name,
                "source": source,
                "domain": domain,
                "screen_origin": "0",
                "provenance": artifact_ref(directory / "provenance.json"),
                "expectations": artifact_ref(directory / "expectations.json"),
                "analysis": artifact_ref(directory / "analysis.json"),
                "deletion_reviews": {},
            }
        ],
    }
    atomic_json(directory / "input.json", raw)
    measurements = verify_editorial_fixtures(raw, repo_root, directory / "verification")
    result = {
        "input": artifact_ref(directory / "input.json"),
        "status": "UNVERIFIED",
        "measurements": measurements,
        "test_only": True,
        "ai_review": "UNVERIFIED",
        "missing": [
            "Actual audiovisual analysis and independent expectation review",
            "Licensed speech fixtures for disfluency, negation, correction and emphasis",
            "Question-wait scenario with actual observed context",
        ],
        "owner_acceptance": "pending",
    }
    atomic_json(directory / "result.json", result)
    return {**result, "artifact_ref": artifact_ref(directory / "result.json")}
