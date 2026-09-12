# CLI reference

Run these commands from the repository root with `uv run --locked talkcut`.
Examples use `PROJECT` for a private project directory and `REVISION` for the
integer returned by `status`. Replace uppercase placeholders before running.
Every user-facing command below accepts `--json`; without it, the CLI currently
also prints JSON.

```sh
uv run --locked talkcut --help
uv run --locked talkcut draft build --help
uv run --locked talkcut --version
```

For a complete first edit, follow [getting started](getting-started.md). The
[strict workflow](acceptance.md) explains the evidence needed after technical
rendering.

## Project and environment

| Command | Purpose and useful options |
| --- | --- |
| `doctor` | Check local FFmpeg/ffprobe availability and versions. AI capability remains separate. |
| `init PROJECT --screen SCREEN_MP4 --speaker SPEAKER_MP4` | Preserve hash-verified source copies in a new project. |
| `inspect PROJECT --full-decode` | Inspect complete source streams and inventory actual frame timestamps. Required before drafting. |
| `status PROJECT` | Verify registered sources and return the current revision, active plan and render references. |
| `verify --output DIRECTORY` | Run locked checks, build and isolated installation, then execute the generated-media recovery example. Preserve logs and artifacts in the output directory. |

`init` returns `revision`; `status` and plan changes return `project_revision`.
Read `status` before commands requiring `--expected-revision`. A stale revision
is rejected, and other operations, including rendering, can advance it.

## First-edit drafts

```sh
uv run --locked talkcut draft build PROJECT \
  --audio-source screen --audio-offset 0 --speaker-offset 0 \
  --trim-start 0 --trim-end 0 \
  --reason "Preserve the complete recording for the first composition" \
  --expected-revision REVISION --json
uv run --locked talkcut render PROJECT --profile draft --json
uv run --locked talkcut draft evaluate PROJECT --json
```

All `draft build` options shown are required. `--audio-source` accepts `screen`
or `speaker`. Timing uses seconds as integers, decimals or fractions; pass
negative fractions as `--speaker-offset=-1/2`. A positive offset places that
track later on the screen clock. Trims are durations removed from the edges.
See [timing examples](getting-started.md#3-choose-the-timing-and-build-a-draft).

`draft evaluate` checks the active draft render and returns its `output.path`
and a saved report reference. `DRAFT_TECHNICALLY_READY` reports technical checks;
the report keeps AI review and owner approval separate.

## Rendering and comparison

| Option or command | Behavior |
| --- | --- |
| `render PROJECT --profile draft` | Render an explicit first-edit draft. |
| `render PROJECT --profile diagnostic` | Render with the diagnostic profile, which is the default. A diagnostic plan remains test-only. |
| `render PROJECT --profile review` | Render with the review profile; rendering itself supplies no review judgment. |
| `render PROJECT --profile master` | Require a non-test plan whose synchronization status is `PASS`. A draft cannot render as a master. |
| `--preset PRESET` | FFmpeg encoder preset; default `medium`. |
| `--crf INTEGER` | H.264 quality setting; default `18`. |
| `qc PROJECT` | Re-decode output and check it against the active timeline. |
| `qc PROJECT --compare-source` | Compare all retained screen pixels outside the speaker rectangle and valid audio samples to their source mapping. |
| `qc PROJECT --compare-source --render-manifest SUCCESS_JSON` | Compare an explicitly saved workflow render instead of the active one. |

Use `output.path` from the render result to open the MP4. Its `render_id`
identifies the request; `execution.path` leads to the worker logs. A repeated
successful request reuses only matching, verified artifacts. Failed encodes keep
their logs and partial files, and retries start a new encode.

QC findings need separate review. Both QC modes currently return exit code `1`
even when technical measurement succeeds.

## Plan decisions

| Command | Required inputs and effect |
| --- | --- |
| `plan build PROJECT --diagnostic` | Build a test-only plan under explicit diagnostic timing assumptions. |
| `plan build PROJECT --analysis ANALYSIS_JSON` | Build from analysis and current source/synchronization evidence. See the strict workflow. |
| `plan add-test-cut PROJECT --start START --end END --expected-revision REVISION` | Add a source-time test candidate to a diagnostic plan; it remains excluded from real acceptance. |
| `plan decide PROJECT --candidate CANDIDATE_ID --decision accept --expected-revision REVISION` | Accept a candidate. `--decision keep` preserves it. `--review REVIEW_JSON` supplies a review artifact when required. |
| `plan restore PROJECT --candidate CANDIDATE_ID --expected-revision REVISION` | Restore a candidate's source interval. Also accepts `--review REVIEW_JSON`. |
| `plan set-audio-profile PROJECT --gain-db=-1 --reason REASON --expected-revision REVISION` | Revise constant attenuation and invalidate the active render. See [audio processing](audio-processing.md). |

Read the plan file referenced by `plan.path` in a plan operation's result, or by
`active_plan.path` in `status`. Its `candidates` array contains the candidate IDs.
The `start` and `end` of a test cut are source timestamps, unlike draft trim
durations. Decisions preserve older plans and timelines and invalidate derived
output review.

## Synchronization, analysis and review

These commands form the [strict review workflow](acceptance.md). Reading their
JSON schemas and evidence requirements is necessary before preparing imports.

| Command family | Main inputs |
| --- | --- |
| `sync analyze PROJECT` | Measure audio correlation anchors, a constant offset and residuals. A completed diagnostic returns `1`; video and lip alignment remain unverified. |
| `sync import PROJECT` | `--model MODEL_JSON --expected-revision REVISION`; adopt separately verified source anchors and invalidate derived plans. |
| `analyze PROJECT` | Optional `--context CONTEXT_JSON`, `--transcript TRANSCRIPT_JSON`; the only `--profile` is `lecture`. Missing audiovisual context leaves analysis unavailable. |
| `context collect PROJECT` | Repeat `--child CHILD_JSON`; also require `--contract`, `--capability` and `--output` paths. Validate executed source context windows. |
| `review build PROJECT` | Extract source, deletion, seam and output review clips. Clip creation does not perform review. |
| `review import PROJECT` | Require `--response`, `--request` and `--capability` JSON paths. Validate the actual reviewer execution and its scope. |
| `editorial prepare PROJECT` | Capture current analysis, plan, timeline and rendered output; return a snapshot path. |
| `editorial bind PROJECT` | Require `--snapshot SNAPSHOT_JSON`; repeat `--review-import REVIEW_IMPORT_JSON`. A keep-all result also needs `--no-safe-cuts-audit AUDIT_JSON`. |

## Acceptance and handoff

| Command | Purpose |
| --- | --- |
| `acceptance freeze PROJECT/frozen-contract.local.json` | Freeze the repository's acceptance contract at the path used by plan construction. |
| `acceptance measure PROJECT --check CHECK_ID --input INPUT_JSON --contract CONTRACT_JSON` | Run a typed measurement in a separate process and preserve the execution receipt. |
| `acceptance evaluate PROJECT --render RENDER_ID --contract CONTRACT_JSON` | Recompute the frozen contract's evidence checks for that render. |
| `prepare-release PROJECT --contract CONTRACT_JSON` | Prepare a private owner handoff only after the required acceptance gates pass. |

The current first-lecture evaluator is specific to the privately registered DGIST
dataset and AC01 through AC13. It does not certify arbitrary projects. See
[acceptance](acceptance.md) and the [evidence reference](evidence-reference.md)
for the required artifacts, independent audits and negative controls.

## Exit codes and automation

| Code | Meaning |
| --- | --- |
| `0` | The requested operation succeeded. Its scope may be only inspection, encoding, import or measurement execution. |
| `1` | The operation reports failed or unverified checks. `sync analyze` and both `qc` modes use this for their outstanding audiovisual obligations. |
| `2` | Invalid arguments, invalid input or an execution error. Read `code` and `message`, or the render worker result and logs. |
| `130` | Interrupted operation, including a keyboard cancellation. |

Read each command's `status` and evidence fields along with its exit code. A
completed acceptance measurement can still contain unknown values. Avoid an
unconditional `&&` chain through `sync analyze` or `qc` when you intend to inspect
their reports and continue.

`render-worker`, `editorial-worker` and `acceptance measure-worker` are internal
process entry points. Use their parent commands to retain execution records and
perform the normal registration steps.
