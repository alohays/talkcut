# TalkCut documentation

Start with [your first edit](getting-started.md) to turn two recordings into a
technically checked MP4. The guides below separate everyday editing from the
stricter audiovisual evidence process.

## Edit a lecture

| Guide | What you will find |
| --- | --- |
| [Getting started](getting-started.md) | Installation, input requirements, offsets, edge trims, rendering and finding the output. |
| [CLI reference](cli-reference.md) | Command groups, render profiles, revision handling and exit codes. |
| [Audio processing](audio-processing.md) | Apply or reverse a constant attenuation and check the encoded result. |
| [Recovery](recovery.md) | Run a generated-media example, restore a cut and retry a failed render. |

## Understand and develop TalkCut

| Guide | What you will find |
| --- | --- |
| [Architecture](architecture.md) | The shared time mapping, project artifacts, evidence dependencies and source modules. |
| [Contributing](../CONTRIBUTING.md) | Development setup, regression checks and review expectations. |
| [Implementation decisions](implementation-decisions.md) | Reasons behind timing, transport, privacy and schema policies. |
| [Documentation guide](documentation.md) | Writing conventions, visual sources and checks for documentation changes. |
| [Security](../SECURITY.md) | Private data handling and reporting a security issue. |

## Review and accept an edit

| Guide | What you will find |
| --- | --- |
| [Acceptance](acceptance.md) | Draft, diagnostic and strict workflows; what each readiness status establishes. |
| [Evidence reference](evidence-reference.md) | Review receipts, composite/native provenance, typed measurements and failure controls. |
| [Lecture review protocol](validation/lecture-review-protocol.md) | The detailed review rubric and evidence required by the original contract. |

## Plans and contract history

These records explain scope and acceptance obligations. A plan specifies what
must be done; it does not show that the work passed.

| Record | Role |
| --- | --- |
| [RFC 0003: First edit MVP](plans/0003-first-edit-mvp.md) | Active scope amendment for the first-edit deliverable. |
| [RFC 0001: DGIST first lecture](plans/0001-dgist-first-lecture.md) | Frozen original first-lecture plan. |
| [RFC 0002: Autonomous goal contract](plans/0002-autonomous-goal-contract.md) | Frozen strict acceptance and release contract. |
| [Autonomous goal prompt](prompts/dgist-autonomous-goal.md) | Historical execution prompt tied to that strict contract. |

RFC 0003 changes the scoped first-edit completion criteria. It leaves the frozen
strict evaluator and its historical results intact. Use the current guides for
commands, and the linked contracts when interpreting a particular acceptance profile.
