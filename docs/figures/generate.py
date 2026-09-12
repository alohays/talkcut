"""Regenerate the public documentation diagrams using only the standard library."""
from html import escape
from pathlib import Path

ASSETS = Path(__file__).resolve().parents[1] / "assets"
INK = "#172b3a"
MUTED = "#465c6c"
TEAL = "#d7eee7"
BLUE = "#dfeafb"
RED = "#f9e2dc"


def start(title, description, width, height):
    return [f'''<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}" role="img" aria-labelledby="title desc">
<title id="title">{escape(title)}</title><desc id="desc">{escape(description)}</desc>
<defs><marker id="arrow" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto"><path d="M0 0L8 4L0 8Z" fill="{MUTED}"/></marker>
<pattern id="hatch" width="10" height="10" patternUnits="userSpaceOnUse" patternTransform="rotate(35)"><rect width="10" height="10" fill="{RED}"/><path d="M0 0V10" stroke="#dfada0" stroke-width="2"/></pattern></defs>
<rect width="100%" height="100%" rx="18" fill="#f7fafb"/>
<g font-family="Arial, Helvetica, sans-serif" fill="{INK}">''']


def text(svg, x, y, value, size=22, fill=INK, weight=400, anchor="start"):
    svg.append(f'<text x="{x}" y="{y}" font-size="{size}" fill="{fill}" font-weight="{weight}" text-anchor="{anchor}">{escape(value)}</text>')


def rect(svg, x, y, width, height, fill, stroke="none", radius=10):
    svg.append(f'<rect x="{x}" y="{y}" width="{width}" height="{height}" rx="{radius}" fill="{fill}" stroke="{stroke}"/>')


def line(svg, x1, y1, x2, y2, arrow=False, dashed=False):
    end = ' marker-end="url(#arrow)"' if arrow else ""
    dash = ' stroke-dasharray="6 6"' if dashed else ""
    svg.append(f'<path d="M{x1} {y1}L{x2} {y2}" fill="none" stroke="{MUTED}" stroke-width="2"{end}{dash}/>')


def finish(name, svg):
    ASSETS.mkdir(parents=True, exist_ok=True)
    (ASSETS / name).write_text("\n".join([*svg, "</g></svg>\n"]), encoding="utf-8")


def workflow():
    svg = start("From recordings to a first edit", "Preserve and inspect both sources, build an explicit draft, render its timeline, then evaluate and watch the output. Previous plans and successful renders remain available.", 1200, 342)
    text(svg, 36, 50, "From recordings to a first edit", 29, weight=700)
    text(svg, 36, 82, "A local workflow with explicit timing and reversible decisions.", 21, MUTED)
    steps = [
        ("01", "Preserve + inspect", "Screen and speaker", "Hash-verified copies", "Complete PTS inventory", TEAL),
        ("02", "Build a draft", "Choose one audio source", "Set constant offsets", "Review any edge trims", BLUE),
        ("03", "Render", "Full screen canvas", "Full-frame speaker inset", "One shared cut timeline", TEAL),
        ("04", "Evaluate + watch", "Check decode and timing", "Open the actual MP4", "Owner review is pending", BLUE),
    ]
    for i, (number, title, a, b, c, color) in enumerate(steps):
        x = 36 + 291 * i
        rect(svg, x, 108, 255, 163, "#ffffff", "#cbd8df")
        rect(svg, x + 16, 122, 37, 30, color, radius=7)
        text(svg, x + 34.5, 144, number, 19, weight=700, anchor="middle")
        text(svg, x + 16, 181, title, 22, weight=700)
        for j, value in enumerate((a, b, c)):
            text(svg, x + 16, 208 + j * 24, value, 18, MUTED)
        if i < 3:
            line(svg, x + 260, 190, x + 283, 190, arrow=True)
    text(svg, 36, 313, "Earlier plans and successful outputs stay available when you revise the edit.", 21, MUTED)
    finish("workflow.svg", svg)


def timeline():
    svg = start("One cut, one shared output clock", "Illustrative 12-second timeline: remove source interval [4,7). Screen, speaker and selected audio all retain [0,4) and [7,12), producing a 9-second output. Draft editing is limited to edge trims; this internal cut illustrates the general timeline model.", 1200, 594)
    text(svg, 36, 49, "One cut, one shared output clock", 29, weight=700)
    text(svg, 36, 82, "Illustrative cut/restore example. First-edit drafts trim edges only.", 21, MUTED)
    x0, unit = 263, 68
    ticks = (0, 4, 7, 12)
    text(svg, 36, 125, "Source time (s)", 21, MUTED)
    for t in ticks:
        x = x0 + t * unit
        text(svg, x, 125, str(t), 21, MUTED, anchor="middle")
        line(svg, x, 137, x, 337, dashed=True)
    for y, label in ((153, "Screen"), (213, "Speaker"), (273, "Selected audio")):
        text(svg, 36, y + 29, label, 22, weight=700)
        rect(svg, x0, y, 4 * unit, 44, TEAL, radius=4)
        rect(svg, x0 + 4 * unit, y, 3 * unit, 44, "url(#hatch)", radius=0)
        rect(svg, x0 + 7 * unit, y, 5 * unit, 44, BLUE, radius=4)
        text(svg, x0 + 2 * unit, y + 29, "A · keep 4 s", 21, anchor="middle")
        text(svg, x0 + 5.5 * unit, y + 29, "remove 3 s", 21, anchor="middle")
        text(svg, x0 + 9.5 * unit, y + 29, "B · keep 5 s", 21, anchor="middle")
    line(svg, x0, 341, x0, 411, arrow=True)
    line(svg, x0 + 7 * unit, 341, x0 + 4 * unit, 411, arrow=True)
    line(svg, x0 + 12 * unit, 341, x0 + 9 * unit, 411, arrow=True)
    text(svg, 36, 456, "Shared output", 22, weight=700)
    rect(svg, x0, 428, 4 * unit, 48, TEAL, radius=4)
    rect(svg, x0 + 4 * unit, 428, 5 * unit, 48, BLUE, radius=4)
    text(svg, x0 + 2 * unit, 459, "A · [0, 4)", 22, anchor="middle")
    text(svg, x0 + 6.5 * unit, 459, "B · [4, 9)", 22, anchor="middle")
    for t in (0, 4, 9):
        text(svg, x0 + t * unit, 507, str(t) + " s", 21, MUTED, anchor="middle")
    text(svg, 36, 554, "For B: output time = source time − 3 s. The original 12 s of media stays intact.", 22, MUTED)
    finish("timeline.svg", svg)


def workflow_mobile():
    svg = start("From recordings to a first edit", "The same first-edit workflow as the wide diagram, arranged vertically for narrow screens.", 440, 878)
    text(svg, 24, 42, "From recordings", 29, weight=700)
    text(svg, 24, 77, "to a first edit", 29, weight=700)
    steps = [
        ("01", "Preserve + inspect", "Screen and speaker", "Hash-verified copies", "Complete PTS inventory", TEAL),
        ("02", "Build a draft", "Choose one audio source", "Set constant offsets", "Review any edge trims", BLUE),
        ("03", "Render", "Full screen canvas", "Full-frame speaker inset", "One shared cut timeline", TEAL),
        ("04", "Evaluate + watch", "Check decode and timing", "Open the actual MP4", "Owner review is pending", BLUE),
    ]
    for i, (number, title, a, b, c, color) in enumerate(steps):
        y = 103 + 179 * i
        rect(svg, 24, y, 392, 148, "#ffffff", "#cbd8df")
        rect(svg, 40, y + 16, 37, 30, color, radius=7)
        text(svg, 58.5, y + 38, number, 19, weight=700, anchor="middle")
        text(svg, 90, y + 39, title, 23, weight=700)
        for j, value in enumerate((a, b, c)):
            text(svg, 40, y + 75 + j * 26, value, 21, MUTED)
        if i < 3:
            line(svg, 220, y + 154, 220, y + 172, arrow=True)
    text(svg, 24, 829, "Earlier plans and successful outputs", 21, MUTED)
    text(svg, 24, 857, "stay available when you revise.", 21, MUTED)
    finish("workflow-mobile.svg", svg)


if __name__ == "__main__":
    workflow()
    workflow_mobile()
    timeline()
