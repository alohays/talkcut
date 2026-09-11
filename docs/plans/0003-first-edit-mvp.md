# RFC 0003 — First edit MVP

Status: active scope amendment, authorized by the owner on 2026-09-11.

The owner requested that the resumed goal finish a reasonable first editing
result and discard requirements that were excessive for a first version. This
amendment defines that smaller deliverable. It supersedes RFC 0002's requirement
that all AC01–AC13 and G0–G5 pass before completing this particular goal or
publishing the tested alpha code. It does not change historical evaluation
results, the frozen contract, or the strict acceptance evaluator.

## Completion criteria

| ID | Required result |
| --- | --- |
| MVP01 | The actual screen and speaker recordings remain in durable private storage with matching hashes and complete decode/PTS inspection. Earlier successful outputs remain available. |
| MVP02 | A complete private MP4 uses the full screen canvas/aspect ratio, a small full-frame speaker overlay in the upper-right, and exactly one selected audio stream. All trims use the same rational source-to-output timeline. |
| MVP03 | Editing is limited to justified leading/trailing preparation or silence. Actual boundary frames and audio measurements inform the decision. Uncertain material, internal pauses, demos, questions, repetitions and corrections stay. The report identifies the evidence and its limits. Zero edge trims are permissible when their safety is uncertain; that result must be called composition-only. |
| MVP04 | The final MP4 passes complete decode, frame/PTS/sample scheduling and geometry checks. Audio and representative visual comparisons are recorded. Known technical faults that prevent ordinary viewing are fixed; lack of formal perceptual certification is disclosed separately. |
| MVP05 | A separate agent reviews the scoped code and media evidence. A private handoff records output/source/plan hashes, actual trims, limitations, commands to reproduce and restore, and owner acceptance pending. |
| MVP06 | The final code passes relevant regression, lint/type, package installation and recovery checks. Public code/package content is inspected for private data, required CI passes, and a PR is merged with an alpha release. Only code and public-safe fixtures/documentation are published. |

The media handoff may state `READY_FOR_OWNER` only with
`acceptance_profile: first-edit-mvp/v1`. This means ready for the owner's first
view under these six criteria. It does not assert G0–G5, whole-output AI review,
certified lip synchronization, or `OWNER_ACCEPTED`. The CLI's narrower
`DRAFT_TECHNICALLY_READY` result covers technical validation only; the handoff
also needs the separate review and release evidence above.

## Deferred work

Formal AI audio/video capability calibration, exhaustive semantic review of
every output window, quantified lip-sync uncertainty, automatic disfluency
removal, whole-history evidence-origin reconstruction, and the remaining strict
AC01–AC13 proof obligations are follow-up work. Existing failures and unverified
results remain intact. A measured audio correlation is not relabelled as a lip
sync measurement. Sampled visual review is not reported as complete viewing.

The draft workflow explicitly chooses one audio source and records assumed
common source clocks or a supplied constant offset. It does not silently infer
verified synchronization. Its plans cannot pass the strict master gate. Existing
cut/restore, source preservation and failure handling continue to apply.

## Execution boundaries

No source or successful output is deleted or overwritten. No uncertain internal
deletion is introduced to meet a cut-count target. No captions, chapters, GUI,
podcast or new cloud service is added. Paid API use or signup still requires
separate owner authorization. Repository protection and required CI remain in
force. Intermediate decisions are delegated; final owner viewing remains pending.

Results belong in a private project report, with the final source, plan, output,
code and release identities. This document specifies scope and is not itself
evidence that any completion criterion has passed.
