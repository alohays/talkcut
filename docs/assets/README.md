# Documentation assets

All figures in this directory use public-safe, invented examples. None contains
private lecture frames, transcripts, review receipts or measurements.

| Asset | Purpose and source |
| --- | --- |
| [talkcut-hero.png](talkcut-hero.png) | AI-generated conceptual cover, created with the built-in image generation tool on 2026-09-11. It illustrates lecture composition and reversible editing. It is not a screenshot or a measured result. |
| [workflow.svg](workflow.svg) | First-edit workflow, generated from [the diagram source](../figures/generate.py). Commands and behavior correspond to `__main__.py`, `draft.py` and `workflow.py`. |
| [workflow-mobile.svg](workflow-mobile.svg) | The same workflow arranged vertically. The README selects it on screens at most 600 pixels wide. |
| [timeline.svg](timeline.svg) | Illustrative 12-second source with a 3-second internal cut and a 9-second output. The intervals explain the general cut/restore model in `timeline.py`; first-edit drafts allow edge trims only. Generated from the same diagram source. |

The SVG files include accessible titles and descriptions, an opaque light
background for consistent contrast, and labels that explain the color coding.
Edit their source and regenerate with `python3 docs/figures/generate.py`.

## Cover prompt

The built-in tool generated the cover without reference images. The PNG is
preserved as generated, including its provenance metadata. The final prompt was:

```text
Use case: illustration-story
Asset type: wide illustration for the README of TalkCut, an open-source local lecture editing command-line tool.
Primary request: a refined editorial paper-cut illustration that communicates keeping a complete lecture screen recording and placing the speaker's complete frame in its upper-right corner, with one shared audio timeline below. Show a large rectangular lecture slide with abstract, unreadable mathematical marks, a small full-frame human lecturer portrait rectangle inset at its upper right, and tactile strips of film and a restrained waveform beneath. Suggest an original film strip continuing intact behind the composed frame, conveying reversible editing. It should feel carefully composed for technical documentation, with ample breathing room and crisp shapes, subtle print texture and soft depth. Avoid resembling a screenshot or promising a GUI.
Composition: very wide landscape banner, approximately 1536 by 512 pixels, main objects centered, generous clear margin.
Text: none. No words, letters, numbers, labels, logos or watermark. All slide contents abstract.
Constraints: no real personal media or recognizable people. Keep the complete screen rectangle and complete speaker portrait rectangle visible. No scissors cutting a face. Use a restrained visual treatment that remains legible at 800px width.
```
