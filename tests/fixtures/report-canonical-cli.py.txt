"""CLI for inspectable, reversible lecture workflows."""

import argparse
import json
import subprocess
import sys
from importlib.metadata import version
from pathlib import Path

from .project import (
    TalkCutError,
    artifact_ref,
    atomic_json,
    init_project,
    load_project,
    project_lock,
    read_json,
    save_revision,
)
from .render import RenderError


def parser_for_cli() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="talkcut",
        description="Reversible lecture editing with explicit evidence gates",
    )
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {version('talkcut')}"
    )
    commands = parser.add_subparsers(dest="command")
    doctor = commands.add_parser(
        "doctor", help="Check local media tools; AI capability remains separate"
    )
    doctor.add_argument("--json", action="store_true")
    verify = commands.add_parser(
        "verify",
        help="Run and preserve locked tests, build, isolated installation and synthetic recovery",
    )
    verify.add_argument("--output", type=Path, required=True)
    verify.add_argument("--json", action="store_true")
    init = commands.add_parser("init", help="Register and preserve source bytes")
    init.add_argument("project", type=Path)
    init.add_argument("--screen", type=Path, required=True)
    init.add_argument("--speaker", type=Path, required=True)
    init.add_argument("--json", action="store_true")
    inspect = commands.add_parser(
        "inspect", help="Inventory all decoded frame PTS and optionally full decode"
    )
    inspect.add_argument("project", type=Path)
    inspect.add_argument("--full-decode", action="store_true")
    inspect.add_argument("--json", action="store_true")
    status = commands.add_parser(
        "status", help="Reopen project and verify registered source identity"
    )
    status.add_argument("project", type=Path)
    status.add_argument("--json", action="store_true")
    acceptance = commands.add_parser(
        "acceptance", help="Evaluate frozen acceptance contract"
    )
    actions = acceptance.add_subparsers(dest="action", required=True)
    evaluate = actions.add_parser("evaluate")
    evaluate.add_argument("project", type=Path)
    evaluate.add_argument("--render", required=True)
    evaluate.add_argument("--contract", type=Path, required=True)
    evaluate.add_argument("--json", action="store_true")
    freeze = actions.add_parser("freeze")
    freeze.add_argument("output", type=Path)
    freeze.add_argument("--json", action="store_true")
    for action in ("measure", "measure-worker"):
        measure = actions.add_parser(
            action,
            help="Execute a typed raw measurement; zero exit means execution, not acceptance",
        )
        measure.add_argument("project", type=Path)
        measure.add_argument("--check", required=True)
        measure.add_argument("--input", type=Path, required=True)
        measure.add_argument("--contract", type=Path, required=True)
        measure.add_argument("--json", action="store_true")
    sync = commands.add_parser(
        "sync", help="Measure audio offset and drift without asserting video alignment"
    )
    sync_actions = sync.add_subparsers(dest="action", required=True)
    analyze = sync_actions.add_parser("analyze")
    analyze.add_argument("project", type=Path)
    analyze.add_argument("--json", action="store_true")
    import_sync = sync_actions.add_parser(
        "import",
        help="Adopt separately verified source anchors and invalidate derived plans",
    )
    import_sync.add_argument("project", type=Path)
    import_sync.add_argument("--model", type=Path, required=True)
    import_sync.add_argument("--expected-revision", type=int, required=True)
    import_sync.add_argument("--json", action="store_true")
    plan = commands.add_parser(
        "plan", help="Build, decide and restore immutable source-time plans"
    )
    plans = plan.add_subparsers(dest="action", required=True)
    build = plans.add_parser("build")
    build.add_argument("project", type=Path)
    build.add_argument("--diagnostic", action="store_true")
    build.add_argument("--analysis", type=Path)
    build.add_argument("--json", action="store_true")
    audio_profile = plans.add_parser("set-audio-profile", help="Revise the shared plan audio attenuation and invalidate renders/reviews")
    audio_profile.add_argument("project", type=Path)
    audio_profile.add_argument("--gain-db", required=True)
    audio_profile.add_argument("--reason", required=True)
    audio_profile.add_argument("--expected-revision", type=int, required=True)
    audio_profile.add_argument("--json", action="store_true")
    test = plans.add_parser("add-test-cut")
    test.add_argument("project", type=Path)
    test.add_argument("--start", required=True)
    test.add_argument("--end", required=True)
    test.add_argument("--expected-revision", type=int, required=True)
    test.add_argument("--json", action="store_true")
    for name in ("decide", "restore"):
        decision = plans.add_parser(name)
        decision.add_argument("project", type=Path)
        decision.add_argument("--candidate", required=True)
        if name == "decide":
            decision.add_argument(
                "--decision", choices=("accept", "keep"), required=True
            )
        decision.add_argument("--review", type=Path)
        decision.add_argument("--expected-revision", type=int, required=True)
        decision.add_argument("--json", action="store_true")
    for action in ("render", "render-worker"):
        render = commands.add_parser(action, help="Render the active measured timeline")
        render.add_argument("project", type=Path)
        render.add_argument(
            "--profile",
            choices=("diagnostic", "review", "master"),
            default="diagnostic",
        )
        render.add_argument("--preset", default="medium")
        render.add_argument("--crf", type=int, default=18)
        render.add_argument("--json", action="store_true")
    editorial = commands.add_parser(
        "editorial",
        help="Bind immutable original analysis and current reviewed edit decisions",
    )
    editorials = editorial.add_subparsers(dest="action", required=True)
    prepare = editorials.add_parser("prepare")
    prepare.add_argument("project", type=Path)
    prepare.add_argument("--json", action="store_true")
    for binding in (
        editorials.add_parser("bind"),
        commands.add_parser("editorial-worker"),
    ):
        binding.add_argument("project", type=Path)
        binding.add_argument("--snapshot", type=Path, required=True)
        binding.add_argument("--review-import", type=Path, action="append", default=[])
        binding.add_argument("--no-safe-cuts-audit", type=Path)
        binding.add_argument("--json", action="store_true")
    qc = commands.add_parser(
        "qc", help="Re-decode and compare output to the active timeline"
    )
    qc.add_argument("project", type=Path)
    qc.add_argument(
        "--compare-source",
        action="store_true",
        help="Compare every retained frame outside PiP and every valid audio sample to source",
    )
    qc.add_argument(
        "--render-manifest",
        type=Path,
        help="Explicit saved workflow render for source comparison; defaults to active render",
    )
    qc.add_argument("--json", action="store_true")
    analyze = commands.add_parser(
        "analyze",
        help="Measure full-source acoustic candidates and import audiovisual context",
    )
    analyze.add_argument("project", type=Path)
    analyze.add_argument("--context", type=Path)
    analyze.add_argument("--transcript", type=Path)
    analyze.add_argument("--profile", choices=("lecture",), default="lecture")
    analyze.add_argument("--json", action="store_true")
    context = commands.add_parser(
        "context", help="Collect original executed source context windows"
    )
    contexts = context.add_subparsers(dest="action", required=True)
    collect = contexts.add_parser(
        "collect", help="Validate every original child before constructing a collection"
    )
    collect.add_argument("project", type=Path)
    collect.add_argument("--child", type=Path, action="append", required=True)
    collect.add_argument("--contract", type=Path, required=True)
    collect.add_argument("--capability", type=Path, required=True)
    collect.add_argument("--output", type=Path, required=True)
    collect.add_argument("--json", action="store_true")
    review = commands.add_parser(
        "review",
        help="Materialize actual media clips and verify separate provider executions",
    )
    reviews = review.add_subparsers(dest="action", required=True)
    build_review = reviews.add_parser("build")
    build_review.add_argument("project", type=Path)
    build_review.add_argument("--json", action="store_true")
    import_review = reviews.add_parser("import")
    import_review.add_argument("project", type=Path)
    import_review.add_argument("--response", type=Path, required=True)
    import_review.add_argument("--request", type=Path, required=True)
    import_review.add_argument("--capability", type=Path, required=True)
    import_review.add_argument("--json", action="store_true")
    prepare = commands.add_parser(
        "prepare-release", help="Prepare a private owner handoff only after G0–G5"
    )
    prepare.add_argument("project", type=Path)
    prepare.add_argument("--contract", type=Path, required=True)
    prepare.add_argument("--json", action="store_true")
    return parser


def execute(args: argparse.Namespace) -> tuple[dict, int]:
    if args.command == "doctor":
        from .media import doctor

        return doctor(), 0
    if args.command == "verify":
        from .verification import run_verification

        result = run_verification(Path.cwd(), args.output)
        return result, 0 if result["technical_execution_pass"] else 1
    if args.command == "init":
        return init_project(args.project, args.screen, args.speaker), 0
    if args.command == "status":
        project = load_project(args.project)
        return {
            "schema_version": "talkcut-status/v1",
            "project_revision": project["revision"],
            "source_hashes": {k: v["sha256"] for k, v in project["sources"].items()},
            "active_plan": project["active_plan"],
            "active_render": project["active_render"],
            "owner_acceptance": project["owner_acceptance"],
            "status": "RENDERED" if project["active_render"] else "DRAFT",
            "acceptance": "UNVERIFIED",
        }, 0
    if args.command == "inspect":
        from .media import inspect_source, inspection_is_current, inspector_hash

        with project_lock(args.project):
            project = load_project(args.project)
            refs = {}
            for role, source in project["sources"].items():
                directory = (
                    args.project
                    / "evidence"
                    / f"inspect-{source['sha256']}-{inspector_hash()}"
                )
                destination = directory / "inspection.json"
                cached = read_json(destination) if destination.exists() else None
                if not (
                    cached
                    and inspection_is_current(
                        cached, source["sha256"], args.full_decode
                    )
                ):
                    print(
                        f"Inspecting all {role} frame timestamps and streams",
                        file=sys.stderr,
                        flush=True,
                    )
                    inspect_source(source["path"], directory, args.full_decode)
                refs[role] = artifact_ref(destination)
            project["inspections"] = refs
            save_revision(
                args.project,
                project,
                project["revision"],
                "inspect",
                {"inspections": refs},
            )
            statuses = {
                role: read_json(ref["path"])["status"] for role, ref in refs.items()
            }
            passed = all(value == "PASS" for value in statuses.values())
            return {
                "schema_version": "talkcut-inspect/v1",
                "status": "PASS" if passed else "UNVERIFIED",
                "sources": statuses,
                "artifact_refs": refs,
            }, 0 if passed else 1
    if args.command == "acceptance":
        if args.action == "freeze":
            from .contracts import freeze_contract

            return freeze_contract(Path.cwd(), args.output), 0
        if args.action in ("measure", "measure-worker"):
            from .acceptance import EvidenceError
            from .measurements import compute, run_measurement

            try:
                if args.action == "measure-worker":
                    return compute(
                        args.project.resolve(),
                        args.check,
                        args.input.resolve(),
                        args.contract.resolve(),
                        Path.cwd(),
                    ), 0
                result = run_measurement(
                    args.project, args.check, args.input, args.contract, Path.cwd()
                )
                return result, 130 if result["interrupted"] else (
                    0 if result["status"] == "MEASURED" else 1
                )
            except EvidenceError as exc:
                raise TalkCutError("MEASUREMENT_UNVERIFIED", str(exc)) from exc
        from .acceptance import evaluate, exit_code

        report = evaluate(
            args.project, args.render, args.contract, repo_root=Path.cwd()
        )
        atomic_json(args.project / "reports" / "acceptance-latest.local.json", report)
        return report, exit_code(report)
    if args.command == "sync":
        if args.action == "import":
            from .sync import import_sync_model

            return import_sync_model(
                args.project, args.model, args.expected_revision
            ), 0
        from .sync import analyze_project as analyze_sync_project

        return analyze_sync_project(args.project), 1
    if args.command == "plan":
        if args.action == "set-audio-profile":
            from .plan import set_audio_profile

            return set_audio_profile(args.project, args.gain_db, args.reason, args.expected_revision), 0
        from .plan import add_test_cut, build_plan, decide

        if args.action == "build":
            return build_plan(
                args.project,
                diagnostic=args.diagnostic,
                analysis_ref=artifact_ref(args.analysis) if args.analysis else None,
            ), 0
        if args.action == "add-test-cut":
            return add_test_cut(
                args.project, args.start, args.end, args.expected_revision
            ), 0
        return decide(
            args.project,
            args.candidate,
            "restore" if args.action == "restore" else args.decision,
            args.expected_revision,
            artifact_ref(args.review) if args.review else None,
        ), 0
    if args.command == "render":
        from .render_execution import run_render

        return run_render(
            args.project,
            args.profile,
            preset=args.preset,
            crf=args.crf,
            repo_root=Path.cwd(),
        )
    if args.command == "render-worker":
        from .workflow import render_project

        return render_project(
            args.project, args.profile, preset=args.preset, crf=args.crf
        ), 0
    if args.command in {"editorial", "editorial-worker"}:
        from .editorial_binding import prepare_editorial, verify_editorial_inputs
        from .editorial_execution import run_editorial

        if args.command == "editorial" and args.action == "prepare":
            return prepare_editorial(args.project, Path.cwd()), 0
        arguments = (
            args.project,
            artifact_ref(args.snapshot),
            [artifact_ref(path) for path in args.review_import],
            artifact_ref(args.no_safe_cuts_audit) if args.no_safe_cuts_audit else None,
            Path.cwd(),
        )
        if args.command == "editorial-worker":
            return verify_editorial_inputs(*arguments), 0
        return run_editorial(*arguments)
    if args.command == "qc":
        if args.compare_source:
            from .workflow import compare_source

            return compare_source(args.project, args.render_manifest), 1
        if args.render_manifest:
            raise TalkCutError(
                "INVALID_ARGUMENT", "--render-manifest requires --compare-source"
            )
        from .workflow import qc_project

        return qc_project(args.project), 1
    if args.command == "analyze":
        from .workflow import analyze_project

        result = analyze_project(args.project, args.context, args.transcript)
        return result, 0 if result["status"] == "ANALYZED" else 1
    if args.command == "context":
        from .workflow import collect_contexts

        return collect_contexts(
            args.project, args.child, args.contract, args.capability, args.output
        ), 0
    if args.command == "review":
        if args.action == "build":
            from .workflow import build_reviews

            return build_reviews(args.project), 0
        from .review import import_review, register_review_import

        result = import_review(
            args.response, args.request, args.capability, args.project / "review"
        )
        if result["status"] == "PASS":
            result["registration"] = register_review_import(
                args.project, result["artifact_ref"], Path.cwd()
            )
        return result, 0 if result["status"] == "PASS" else 1
    if args.command == "prepare-release":
        from .workflow import prepare_release

        result = prepare_release(args.project, args.contract)
        return result, 0 if result["status"] == "READY_FOR_OWNER" else 1
    raise TalkCutError("UNKNOWN_COMMAND", str(args.command))


def main() -> None:
    parser = parser_for_cli()
    args = parser.parse_args()
    if args.command is None:
        parser.print_help()
        return
    try:
        result, code = execute(args)
    except (
        TalkCutError,
        RenderError,
        subprocess.SubprocessError,
        OSError,
        ValueError,
        KeyError,
        TypeError,
        AttributeError,
        IndexError,
        ArithmeticError,
    ) as exc:
        result, code = (
            {
                "schema_version": "talkcut-error/v1",
                "status": "FAIL",
                "code": getattr(
                    exc,
                    "code",
                    "RENDER_FAILED"
                    if isinstance(exc, RenderError)
                    else "EXECUTION_ERROR",
                ),
                "message": str(exc),
                "retryable": False,
                "manifest_path": str(exc.manifest_path)
                if isinstance(exc, RenderError) and exc.manifest_path
                else None,
            },
            2,
        )
    except KeyboardInterrupt:
        result, code = (
            {
                "schema_version": "talkcut-error/v1",
                "status": "FAIL",
                "code": "CANCELLED",
            },
            130,
        )
    print(json.dumps(result, ensure_ascii=False, allow_nan=False, indent=2))
    raise SystemExit(code)


if __name__ == "__main__":
    main()
