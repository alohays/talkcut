"""Frozen, non-negotiable acceptance requirements for the first lecture.

Document digests are deliberately part of the evaluator, not supplied by an
evidence author. Changing this contract requires code review and a new version.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any

CONTRACT_VERSION = "dgist-first-lecture/v1"
DOCUMENT_HASHES = {
    "docs/plans/0001-dgist-first-lecture.md": "b4e5441f0ea29bc133eaf30378fa4ab4d0899fa0dfada47207bdc96b63c6f1b8",
    "docs/plans/0002-autonomous-goal-contract.md": "83a53a7b17bb0c5b026ae6365cb2a4e47d0d64227eed913b4db0f00408af6c64",
    "docs/validation/lecture-review-protocol.md": "85066fd2b3da676c8f252e0362f675546a774e974bdb7aa0d64326e462db97dc",
}
CRITERIA = {
    "AC01": "Execution contract and identified tools/reviewers",
    "AC02": "Preserved real DGIST inputs and complete decode/PTS",
    "AC03": "Implemented and executed M1–M7 workflow",
    "AC04": "Common timeline, verified synchronization and boundaries",
    "AC05": "Full-frame composition and single-source audio quality",
    "AC06": "Full-source analysis and effective conservative editing",
    "AC07": "Cut, restore, reapply and restart preserve history and timing",
    "AC08": "Separate, traceable multimodal review with complete coverage",
    "AC09": "Complete final master and G0–G5",
    "AC10": "Failure, forgery, stale evidence and corruption defenses",
    "AC11": "Reproducible installation, public fixtures and package",
    "AC12": "Independent audit and complete private handoff",
    "AC13": "Verified public CI, merged PR and alpha code release",
}

# Each value is a deterministic measurement predicate, not an accepted verdict.
# Artifacts also require a completed execution receipt, dependencies, and logs.
CHECK_REQUIREMENTS: dict[str, dict[str, Any]] = {
    "workflow_e2e": {
        "steps_completed": [
            "inspect",
            "sync",
            "analysis",
            "plan",
            "review",
            "render",
            "qc",
            "prepare-release",
        ],
        "real_media": True,
        "mock_provider": False,
    },
    "baseline": {
        "whole_source": True,
        "full_resolution": True,
        "complete_decode": True,
    },
    "sync": {
        "max_audio_residual_with_uncertainty_ms": {"max": 20},
        "max_lip_residual_with_uncertainty_ms": {"max": 80},
        "max_lip_uncertainty_ms": {"max": 40},
        "max_drift_change_ms": {"max": 40},
        "drift_within_local_frame": True,
        "max_anchor_gap_seconds": {"max": 600},
        "start_middle_end_holdouts": True,
        "output_anchors_checked": True,
        "uncertainty_method": {"nonempty": True},
    },
    "boundaries": {
        "video_error_local_frames": {"max": 1},
        "audio_error_samples": {"max": 1},
        "fixture_cut_count": {"min": 100},
        "actual_pts_verified": True,
        "aac_padding_separated": True,
    },
    "geometry_audio": {
        "screen_full_frame": True,
        "screen_canvas_preserved": True,
        "screen_dar_preserved": True,
        "speaker_full_frame": True,
        "speaker_dar_preserved": True,
        "speaker_top_right": True,
        "important_occlusions": 0,
        "output_audio_streams": 1,
        "new_audio_defects": 0,
        "all_visual_states_checked": True,
    },
    "editorial_fixture": {
        "positive_preparation_pass": True,
        "positive_silence_pass": True,
        "positive_disfluency_pass": True,
        "negative_demo_pass": True,
        "negative_question_wait_pass": True,
        "negative_negation_pass": True,
        "negative_correction_pass": True,
        "negative_emphasis_pass": True,
        "always_keep_rejected": True,
        "always_cut_rejected": True,
        "empty_analysis_rejected": True,
        "independently_reviewed_expectations": True,
    },
    "recovery": {
        "real_dgist_cut_restore_reapply": True,
        "fixture_roundtrip": True,
        "reopen": True,
        "unchanged_rerun": True,
        "timing_preserved": True,
        "history_preserved": True,
        "review_invalidated_and_regenerated": True,
        "owner_event_fabricated": False,
    },
    "output_technical": {
        "complete_decode": True,
        "actual_pts_verified": True,
        "retained_mapping_verified": True,
        "new_drop_freeze_black_silence": 0,
        "audio_streams": 1,
        "video_streams": 1,
        "full_resolution": True,
    },
    "failure_injection": {
        "sigint": True,
        "subprocess_failure": True,
        "timeout": True,
        "disk_full": True,
        "corrupt_json": True,
        "source_replacement": True,
        "stale_cache": True,
        "concurrent_revision": True,
        "provider_timeout": True,
        "modality_missing": True,
        "invalid_review_timestamp": True,
        "empty_review": True,
        "truncated_review": True,
        "budget_exhaustion": True,
        "partial_not_promoted": True,
        "previous_success_preserved": True,
        "source_unchanged": True,
        "resume_verified": True,
    },
    "evaluator_negative": {
        "transcript_only": True,
        "duplicate_coverage": True,
        "wrong_hashes": True,
        "hidden_deletion": True,
        "sample_export": True,
        "always_keep": True,
        "fabricated_pass": True,
        "threshold_tamper": True,
        "error_exit_nonzero": True,
        "renamed_partial": True,
    },
    "reproducibility": {
        "clean_install": True,
        "locked_dependencies": True,
        "tests": True,
        "package_build": True,
        "synthetic_e2e": True,
        "recovery_documentation_executed": True,
        "support_claims_match_tests": True,
        "public_fixture_license_checked": True,
    },
    "release_privacy": {
        "tracked_content_scanned": True,
        "assets_scanned": True,
        "body_scanned": True,
        "private_media_count": 0,
        "private_transcript_count": 0,
        "credentials_count": 0,
    },
}


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode()


def object_hash(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def file_hash(path: str | Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_schema(name: str) -> dict[str, Any]:
    """Load the same published JSON Schema shipped inside the wheel."""
    from importlib.resources import files

    return json.loads(files("talkcut").joinpath("schemas", name).read_text())


def validate_project(value: Any) -> None:
    from jsonschema import Draft202012Validator

    errors = sorted(
        Draft202012Validator(load_schema("project-v1.schema.json")).iter_errors(value),
        key=lambda error: str(error.path),
    )
    if errors:
        raise ValueError(
            "Invalid talkcut-project/v1: "
            + "; ".join(error.message for error in errors)
        )


def expected_contract() -> dict[str, Any]:
    # Return a fresh object so callers cannot mutate the evaluator's requirements.
    return json.loads(
        canonical_bytes(
            {
                "schema_version": CONTRACT_VERSION,
                "document_hashes": DOCUMENT_HASHES,
                "criteria": [
                    {"id": key, "required": True, "description": value}
                    for key, value in CRITERIA.items()
                ],
                "requirements": [f"R{i:02}" for i in range(1, 15)],
                "checks": CHECK_REQUIREMENTS,
                "coverage": {
                    "deleted_source": 1,
                    "seams": 1,
                    "output_audio": 1,
                    "output_video": 1,
                    "source_analysis": 1,
                },
                "review": {
                    "window_seconds": 30,
                    "overlap_seconds": 5,
                    "deletion_context_seconds": 5,
                    "required_modalities": ["audio", "video"],
                    "separate_proposer_run": True,
                },
                "unresolved_P0_P1": 0,
                "owner_acceptance": "pending",
                "release_repository": "https://github.com/alohays/talkcut",
                "new_paid_api_requires_authorization": True,
                "private_media_publication": False,
                "codex_token_budget": None,
            }
        )
    )


def verify_contract(contract: dict[str, Any], repo_root: str | Path) -> list[str]:
    errors = []
    if contract != expected_contract():
        errors.append(
            "Frozen machine contract differs from evaluator's approved requirements"
        )
    for name, digest in DOCUMENT_HASHES.items():
        path = Path(repo_root) / name
        if not path.is_file() or file_hash(path) != digest:
            errors.append(f"Approved contract document missing or changed: {name}")
    return errors


def freeze_contract(repo_root: str | Path, output_path: str | Path) -> dict[str, Any]:
    contract = expected_contract()
    errors = verify_contract(contract, repo_root)
    if errors:
        raise ValueError("; ".join(errors))
    path = Path(output_path)
    data = json.dumps(contract, indent=2, ensure_ascii=False, allow_nan=False) + "\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        if path.read_text() != data:
            raise ValueError("Refusing to replace a different frozen contract")
    else:
        # Exclusive creation: a concurrent freeze never silently overwrites.
        with path.open("x") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    return {
        "path": str(path.resolve()),
        "sha256": file_hash(path),
        "contract": contract,
    }


def code_identity(repo_root: str | Path) -> dict[str, Any]:
    """Hash runtime, evaluator, schema, lock, tests and CI, never local evidence."""
    import subprocess

    root = Path(repo_root).resolve()
    names: set[str] = set()
    for directory in ("src", "tests", "schemas", ".github"):
        base = root / directory
        if base.exists():
            names.update(
                str(p.relative_to(root))
                for p in base.rglob("*")
                if p.is_file()
                and "__pycache__" not in p.parts
                and p.suffix not in (".pyc", ".pyo")
            )
    for name in (
        "pyproject.toml",
        "uv.lock",
        ".python-version",
        "pytest.ini",
        "mypy.ini",
        "ruff.toml",
        ".ruff.toml",
    ):
        if (root / name).is_file():
            names.add(name)
    files = {name: file_hash(root / name) for name in sorted(names)}
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=root,
        capture_output=True,
        text=True,
        check=False,
    )
    return {
        "code_revision": result.stdout.strip() if result.returncode == 0 else None,
        "code_tree_hash": object_hash(files),
        "files": files,
    }
