# Maintaining the documentation

[Documentation index](README.md) · [Contributing](../CONTRIBUTING.md)

Write for someone who has a recording to edit or a concrete change to make.
The root README explains the product and gives a short first run. Task guides
carry the full procedure; reference pages carry the details needed to check it.

## Choose a home for the information

| Content | Location |
| --- | --- |
| First run and timing choices | [Getting started](getting-started.md) |
| Flags, profiles and exit behavior | [CLI reference](cli-reference.md) |
| Time mapping, artifacts and module responsibilities | [Architecture](architecture.md) |
| Readiness states and strict procedure | [Acceptance](acceptance.md) |
| Measurement inputs and review provenance | [Evidence reference](evidence-reference.md) |
| Rationale for a technical policy | [Implementation decisions](implementation-decisions.md) |

Link to the full explanation from shorter pages. Keep frozen plans and review
contracts intact; record a scope change as an explicit amendment.

## Write and verify the claims

Use plain English, concrete verbs and sentence-case headings. Explain an
unfamiliar term where it first affects a decision. Keep the same name for each
artifact and status throughout the docs. Scope statements matter here: retain
facts such as which checks ran, which evidence is missing and what a status allows.

For a command change, compare the example with `talkcut COMMAND --help` and the
CLI implementation. Run executable workflows on generated media. Use clearly
named placeholders for personal paths, identifiers and the current revision;
avoid hard-coded revisions that invite a stale update. Identify the returned
field that points to the result, along with any expected nonzero exit.

The prose pass used the public
[humanizer skill, version 3.0.0](https://github.com/blader/humanizer/blob/9862685f575c65a8247f90369951df1b3416e3d6/SKILL.md).
Its review process is useful for later edits: read the whole page, remove filler
and repetitive staging, then check that the rewrite preserved every supported
claim. Keep technical text neutral. Do not change commands, status identifiers
or evidence requirements just to make the prose smoother.

## Maintain the figures

The [asset notes](assets/README.md) record each figure's purpose, source and the
prompt for the generated cover. The workflow and timeline diagrams use SVG so
labels stay sharp and contributors can update them without an image service.
Regenerate them from the repository root with Python's standard library:

```sh
python3 docs/figures/generate.py
```

Add useful alt text and a caption when a diagram makes an assumption. A numeric
illustration must say that its values are illustrative. Use generated fixtures
for actual media examples. A conceptual illustration cannot establish a feature,
measurement or acceptance result.

## Check the rendered result

Before submitting a documentation change:

1. Follow relative links and section anchors from the README and documentation index.
2. Preview changed Markdown in a renderer with GitHub-flavored tables and Mermaid support. Read the figures at a normal README width and on a narrow screen; open detailed figures at full size if needed.
3. Check for clipped text, missing image files, unreadable labels and horizontal overflow outside code blocks or tables. Every image needs meaningful alt text.
4. Run the documented commands affected by the change with generated inputs. Retain the commands and results in the review notes.
5. Inspect the diff for private paths or media. Keep figures and their source together in the change.

Documentation edits do not need tests that merely assert wording. If a command
example reveals a behavior change, validate that behavior with the relevant
regression tests described in [Contributing](../CONTRIBUTING.md).
