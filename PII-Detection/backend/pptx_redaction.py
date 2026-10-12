"""Redact PII from PowerPoint (.pptx) files."""

from __future__ import annotations

from pptx import Presentation
from pptx.enum.shapes import MSO_SHAPE_TYPE

from .analyzer import analyze


def _redact_runs(paragraph) -> None:
    """Redact PII within a single paragraph's runs (preserves formatting)."""
    full_text = "".join(run.text for run in paragraph.runs)
    if not full_text.strip():
        return

    results = analyze(full_text)
    if not results:
        return

    # Apply replacements right-to-left so offsets stay valid
    results = sorted(results, key=lambda r: r.start, reverse=True)
    for result in results:
        replacement = f"<{result.entity_type}>"
        current_pos = 0

        for run in paragraph.runs:
            run_start = current_pos
            run_end = current_pos + len(run.text)
            current_pos = run_end

            # No overlap
            if result.end <= run_start or result.start >= run_end:
                continue

            # Entirely within this run
            if result.start >= run_start and result.end <= run_end:
                s = result.start - run_start
                e = result.end - run_start
                run.text = run.text[:s] + replacement + run.text[e:]
                break

            # Partial overlap — trim the run
            if result.start >= run_start:
                run.text = run.text[: result.start - run_start] + replacement
            elif result.end <= run_end:
                run.text = run.text[result.end - run_start :]
            else:
                run.text = ""


def _redact_text_frame(text_frame) -> None:
    for paragraph in text_frame.paragraphs:
        _redact_runs(paragraph)


def _redact_table(table) -> None:
    for row in table.rows:
        for cell in row.cells:
            _redact_text_frame(cell.text_frame)


def _redact_shape(shape) -> None:
    if shape.shape_type == MSO_SHAPE_TYPE.GROUP:
        for child in shape.shapes:
            _redact_shape(child)
        return
    if shape.has_text_frame:
        _redact_text_frame(shape.text_frame)
    if shape.has_table:
        _redact_table(shape.table)


def process_pptx(input_file, output_file) -> int:
    """Redact PII from a PPTX file. Returns total redaction count."""
    prs = Presentation(input_file)
    count = 0

    for slide in prs.slides:
        # Regular slide shapes
        for shape in slide.shapes:
            _redact_shape(shape)

        # Speaker notes
        if slide.has_notes_slide:
            notes_tf = slide.notes_slide.notes_text_frame
            for paragraph in notes_tf.paragraphs:
                before = "".join(r.text for r in paragraph.runs)
                _redact_runs(paragraph)
                after = "".join(r.text for r in paragraph.runs)
                if before != after:
                    count += 1

    prs.save(output_file)
    return count
