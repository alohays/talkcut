# Review and acceptance

The strict workflow requires verified synchronization, separate audiovisual
reviews and a final evaluation against a frozen contract. This guide describes
those requirements; a recording's own evaluation report records whether it passes.

For a practical first edit, start with the [README](../README.md). Provider
receipts, typed measurements and failure controls are covered in the
[evidence reference](evidence-reference.md). All guides are listed in the
[documentation index](README.md).

## Understand the readiness states

| Result | What it establishes | What is still separate |
| --- | --- | --- |
| `DRAFT_TECHNICALLY_READY` | The draft passes complete decode, source/plan/timeline, geometry and frame/sample schedule checks. | Audiovisual certification and owner approval. Timing assumptions remain in the draft report. |
| Diagnostic render | A test-only plan produced media for investigation. | It cannot render a strict master or satisfy strict `READY_FOR_OWNER`. |
| `READY_FOR_OWNER` with `acceptance_profile: first-edit-mvp/v1` | A private handoff meets the six criteria in [RFC 0003](plans/0003-first-edit-mvp.md), including separate review and release evidence. | Strict AC01 through AC13 / G0 through G5 certification and owner approval. The draft CLI alone does not award this status. |
| Strict `media_state: READY_FOR_OWNER` | The evaluator finds the final output's required G0 through G5 evidence complete. | Independent handoff/release obligations can remain; inspect every AC result. |
| `OWNER_ACCEPTED` | The owner accepted the identified final output. | Owner acceptance does not establish general editing accuracy or a public code release. |
| Strict `goal_achieved: true` | All AC01 through AC13 pass, including independent audit, reproducibility and verified public release. | The evaluator still records owner acceptance as pending. |

The strict evaluator targets the privately registered DGIST first lecture and
the frozen `dgist-first-lecture/v1` contract. It is not a generic certificate for
arbitrary recordings. Missing, stale, incomplete or unsupported evidence leaves
the affected checks unverified or failed.

The [first-lecture plan](plans/0001-dgist-first-lecture.md),
[autonomous acceptance contract](plans/0002-autonomous-goal-contract.md) and
[lecture review protocol](validation/lecture-review-protocol.md) are frozen
contract snapshots. Their historical implementation-status statements describe
when they were written. [Implementation decisions](implementation-decisions.md)
record subsequent constraints and technical choices. RFC 0003 changes the first
edit's completion scope; it does not rewrite the strict evaluator or past results.

## 1. Preserve the inputs and establish a baseline

Run these examples from the repository root after installation. Replace the
source paths with your recordings. Keep the project under the Git-ignored
`projects/` directory.

```sh
uv run --locked talkcut init projects/my-lecture --screen /path/to/screen.mp4 --speaker /path/to/speaker.mp4 --json
uv run --locked talkcut inspect projects/my-lecture --full-decode --json
uv run --locked talkcut sync analyze projects/my-lecture --json
uv run --locked talkcut acceptance freeze projects/my-lecture/frozen-contract.local.json --json
uv run --locked talkcut plan build projects/my-lecture --diagnostic --json
uv run --locked talkcut render projects/my-lecture --profile diagnostic --json
uv run --locked talkcut qc projects/my-lecture --json
uv run --locked talkcut qc projects/my-lecture --compare-source --json
```

`init` makes durable copies with verified hashes and retains the originals.
`inspect` decodes the selected streams completely and inventories their actual
presentation timestamps (PTS), durations and samples. A reported frame rate alone
cannot establish the timeline. Unknown display geometry is rejected unless the
MP4 track dimensions and transforms provide explicit compatible evidence.

`sync analyze` measures audio correlation with fit and holdout anchors. Its current
anchor profile requires measured zero source origins and at least 45 seconds.
Audio correlation does not verify video alignment or lip synchronization. The
diagnostic composition lets you investigate these issues before strict review.

## 2. Import verified timing and analyze the source

A strict master needs a source mapping backed by executed audio, visual and
lip-sync anchor reviews. After obtaining that evidence, import its model:

```sh
uv run --locked talkcut status projects/my-lecture --json
# Replace REVISION with the current project_revision.
uv run --locked talkcut sync import projects/my-lecture --model verified-sync.json --expected-revision REVISION --json
```

Import checks the exact source bytes and measurements. It preserves previous
artifacts and invalidates derived plans and output reviews. The final output
will still need its own synchronization anchors.

Analyze the complete screen-recording audio with versioned transcript and executed
audiovisual context evidence:

```sh
uv run --locked talkcut analyze projects/my-lecture --transcript transcript.json --context lecture-context.json --json
uv run --locked talkcut plan build projects/my-lecture --analysis ANALYSIS_JSON --json
```

Use the analysis artifact path returned by `analyze`. Prepare the input files in
their versioned evidence formats; see the [schema map](evidence-reference.md#find-the-input-format).
Without executed audiovisual context, analysis returns `ANALYSIS_UNAVAILABLE`.
An empty transcript or a long silence does not authorize deletion. Demonstrations,
questions, reading time and meaningful corrections remain protected. Removing a
disfluency requires a separate reviewer execution tied to that candidate.

Decisions are reversible. Read `status` before a change and supply its revision
to `plan decide` or `plan restore`. Each change preserves an immutable plan and
timeline and invalidates dependent output review; stale revisions are rejected.
See the [cut/restore recovery guide](recovery.md) for an executable roundtrip.
Explicit test cuts remain excluded from real acceptance.

## 3. Render and collect actual reviews

After completing the supported timing and plan requirements, render the master
and extract its review clips:

```sh
uv run --locked talkcut render projects/my-lecture --profile master --json
uv run --locked talkcut review build projects/my-lecture --json
```

`review build` extracts every deletion with source context, every seam from the
actual output, and overlapping source/output windows. It does not review those
clips. Execute the required reviews with a provider whose audiovisual capability
has been demonstrated, then import each result:

```sh
uv run --locked talkcut review import projects/my-lecture --response REVIEW_RECORD_JSON --request REVIEW_REQUEST_JSON --capability CAPABILITY_JSON --json
```

The importer validates execution receipts, clip identity, modalities, observed
intervals and capability evidence. Successful imports register their verified
execution and capability references for acceptance. Registration alone does not
approve a lecture. Cloud analysis is disabled by default; no cloud SDK, paid API
or automatic provider fallback is configured. Local speech recognition also
cannot replace audiovisual review.

The [provider and composite review reference](evidence-reference.md#provider-and-composite-review)
explains execution provenance and the current motion/lip-sync limits.

## 4. Bind editorial decisions to the final output

After rendering the final master and importing its separate candidate reviews,
capture the current state and bind the evidence:

```sh
uv run --locked talkcut editorial prepare projects/my-lecture --json
# Use the snapshot and review-import artifact paths returned by those commands.
uv run --locked talkcut editorial bind projects/my-lecture --snapshot SNAPSHOT_JSON --review-import REVIEW_IMPORT_JSON --json
```

Repeat `--review-import` for each applicable review. Binding rechecks the original
proposals, distinct reviewer executions and prompts, current cut boundaries and
source/output hashes. It records the local verification command and indexes its
result. Every applied cut needs current candidate-specific audiovisual evidence,
including automatically selected preparation or silence cuts.

For a plan with no applied cuts, supply the full-source review imports and
`--no-safe-cuts-audit AUDIT_JSON`. That separate audit must assess every original
candidate and explain why no safe deletion remains. A diagnostic output or a
keep-all plan without analysis cannot bind. Changes to code, media or decisions
require a fresh binding.

## 5. Resolve output findings and evaluate

```sh
uv run --locked talkcut qc projects/my-lecture --json
uv run --locked talkcut qc projects/my-lecture --compare-source --json
uv run --locked talkcut acceptance evaluate projects/my-lecture --render RENDER_ID --contract projects/my-lecture/frozen-contract.local.json --json
```

Use the final render's `render_id`. Source comparison streams every retained
full-resolution screen frame outside the speaker rectangle and every valid PCM
sample against the measured source mapping. It records differences and possible
new black, freeze, silence, clipping and discontinuity intervals. Detector
thresholds identify places to investigate; review must resolve the findings and
check important-content visibility and listening quality.

The evaluator recomputes source conservation, deletion/seam/output coverage and
typed measurements from their artifacts. Overlapping review windows count once.
Read the per-criterion results, `uncovered_intervals`, `invalid_evidence` and
`open_findings` to find the next unresolved obligation. A successful technical
comparison does not complete the audiovisual gates.

| Command result | Exit code |
| --- | --- |
| `acceptance evaluate`: all AC01 through AC13 pass | `0` |
| `acceptance evaluate`: failed or unverified acceptance | `1` |
| `acceptance measure`: measurement execution completed, even if values remain `null` | `0` |
| `acceptance measure`: worker did not produce a verified measurement result | `1` |
| `sync analyze`: diagnostic audio measurements produced | `1` |
| `qc`, including source comparison: technical report produced, audiovisual obligations remain separate | `1` |
| Invalid input or raised execution error in the main CLI | `2` |
| Interrupted render or measurement worker | `130` |

## 6. Prepare the private handoff

```sh
uv run --locked talkcut prepare-release projects/my-lecture --contract projects/my-lecture/frozen-contract.local.json --json
```

`prepare-release` creates a private owner handoff. Publication is a separate
operation. It evaluates the current render, requires G0 through G5, and
then requires the private `checkpoint.local.json`. The handoff records the exact
output, dependencies, measurements, restore/rerun commands, cost availability and
any unmet AC obligations. Missing media evidence yields `UNVERIFIED` with exit
code `1`; a prepared handoff returns `READY_FOR_OWNER` with exit code `0`.

The owner must accept the identified output before anyone records
`OWNER_ACCEPTED`. Code release has its own independent audit, reproducibility,
privacy, passing CI, reviewed merge and alpha-release requirements. Recordings,
transcripts, review evidence and credentials belong in private storage and must
stay out of public commits, packages, PRs and release assets.
