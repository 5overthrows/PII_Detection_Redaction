"""Redact PII from DOCX, PPTX, PDF, raster images, and plain-text files.

Run from the project root with:
    python -m backend.file_redaction path\\to\\input.pdf
"""

from __future__ import annotations

import argparse
import io
import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

import numpy as np
import pymupdf
from PIL import Image, ImageDraw
from presidio_anonymizer import AnonymizerEngine

from .analyzer import analyze as _analyze
from .docx_text import process_docx
from .pptx_redaction import process_pptx

IMAGE_EXTENSIONS = {".bmp", ".gif", ".jpeg", ".jpg", ".png", ".tif", ".tiff", ".webp"}
TEXT_EXTENSIONS = {".csv", ".text", ".txt"}
SUPPORTED_EXTENSIONS = IMAGE_EXTENSIONS | TEXT_EXTENSIONS | {".docx", ".pdf", ".pptx"}


@dataclass(frozen=True)
class OCRLine:
    text: str
    polygon: tuple[tuple[float, float], ...]

@lru_cache(maxsize=1)
def _get_anonymizer() -> AnonymizerEngine:
    return AnonymizerEngine()


@lru_cache(maxsize=1)
def _get_ocr_engine() -> Any:
    try:
        from rapidocr_onnxruntime import RapidOCR
    except ImportError as exc:
        raise RuntimeError(
            "RapidOCR is required for image and PDF redaction. "
            "Install the project dependencies from requirements.txt."
        ) from exc

    return RapidOCR()


def _ocr_lines(image: Image.Image) -> list[OCRLine]:
    pixels = np.asarray(image.convert("RGB"))
    result, _ = _get_ocr_engine()(pixels)
    lines: list[OCRLine] = []

    if result is None:
        return lines

    for bbox, text, _score in result:
        text = str(text).strip()
        points = tuple((float(point[0]), float(point[1])) for point in bbox)
        if text and len(points) >= 4:
            lines.append(OCRLine(text=text, polygon=points))

    return lines


def _normalize_ocr_text(text: str) -> str:
    """Split concatenated camelCase words and fix punctuation spacing from OCR."""
    s = re.sub(r"([a-z])([A-Z])", r"\1 \2", text)
    s = re.sub(r":([^\s])", r": \1", s)
    return s


def _pii_line_indexes(lines: list[OCRLine]) -> set[int]:
    if not lines:
        return set()

    redacted_indexes: set[int] = set()

    # 1. Check each line individually with normalized text (e.g. split camelCase names, 12-digit Aadhaar)
    for index, line in enumerate(lines):
        norm_line = _normalize_ocr_text(line.text)
        if _analyze(norm_line):
            redacted_indexes.add(index)

    # 2. Also check combined document text for context-boosted PII
    norm_texts = [_normalize_ocr_text(line.text) for line in lines]
    combined_text = "\n".join(norm_texts)
    results = _analyze(combined_text)

    offset = 0
    for index, n_text in enumerate(norm_texts):
        line_start = offset
        line_end = line_start + len(n_text)
        if any(result.start < line_end and result.end > line_start for result in results):
            redacted_indexes.add(index)
        offset = line_end + 1

    # 3. ID Card field label heuristic: line following "Name:" is guaranteed to be a name
    for i, line in enumerate(lines):
        clean_lower = line.text.strip().lower().rstrip(":")
        if clean_lower in ("name", "father's name", "husband's name", "c/o", "s/o", "d/o", "w/o"):
            if i + 1 < len(lines):
                redacted_indexes.add(i + 1)

    return redacted_indexes


def _redact_image(image: Image.Image) -> tuple[Image.Image, int]:
    lines = _ocr_lines(image)
    indexes = _pii_line_indexes(lines)
    redacted = image.convert("RGB")
    draw = ImageDraw.Draw(redacted)

    for index in indexes:
        draw.polygon(lines[index].polygon, fill="black")
    return redacted, len(indexes)


def _redact_image_file(input_path: Path, output_path: Path) -> int:
    with Image.open(input_path) as source:
        redacted, count = _redact_image(source)
    redacted.save(output_path)
    return count


def _redact_image_part(image_part: Any, processed_parts: set[str], file_type: str) -> int:
    part_name = str(image_part.partname)
    if part_name in processed_parts:
        return 0
    processed_parts.add(part_name)

    with Image.open(io.BytesIO(image_part.blob)) as source:
        original_format = source.format
        redacted, count = _redact_image(source)
    if not count:
        return 0
    if original_format not in Image.SAVE:
        raise RuntimeError(
            f"Cannot preserve the embedded image format {original_format!r} in this {file_type}."
        )

    buffer = io.BytesIO()
    redacted.save(buffer, format=original_format)
    image_part._blob = buffer.getvalue()
    return count


def _redact_docx_images(file_path: Path) -> int:
    from docx import Document

    document = Document(file_path)
    processed_parts: set[str] = set()
    redacted_count = 0

    for shape in document.inline_shapes:
        picture = shape._inline.graphic.graphicData.pic
        relationship_id = picture.blipFill.blip.embed
        if not relationship_id:
            raise RuntimeError("Linked external images in DOCX files cannot be OCR-redacted.")
        image_part = document.part.related_parts[relationship_id]
        redacted_count += _redact_image_part(image_part, processed_parts, "DOCX")

    document.save(file_path)
    return redacted_count


def _redact_pptx_images(file_path: Path) -> int:
    from pptx import Presentation
    from pptx.enum.shapes import MSO_SHAPE_TYPE

    presentation = Presentation(file_path)
    processed_parts: set[str] = set()
    redacted_count = 0

    def redact_shape(shape: Any) -> None:
        nonlocal redacted_count
        if shape.shape_type == MSO_SHAPE_TYPE.GROUP:
            for child in shape.shapes:
                redact_shape(child)
            return
        if shape.shape_type != MSO_SHAPE_TYPE.PICTURE:
            return

        blip = shape._element.blipFill.blip
        relationship_id = blip.rEmbed
        if not relationship_id:
            if blip.rLink:
                raise RuntimeError("Linked external images in PPTX files cannot be OCR-redacted.")
            return

        image_part = shape.part.related_part(relationship_id)
        redacted_count += _redact_image_part(image_part, processed_parts, "PPTX")

    for slide in presentation.slides:
        for shape in slide.shapes:
            redact_shape(shape)

    if redacted_count:
        presentation.save(file_path)
    return redacted_count


def _redact_pdf_page_native(page: Any) -> int:
    """Redact PII from a text-based PDF page using native text extraction (fast)."""
    text = page.get_text()
    if not text.strip():
        return -1  # signal: no native text, caller should use OCR

    results = _analyze(text)
    if not results:
        return 0

    redaction_count = 0
    for result in results:
        entity_text = text[result.start:result.end]
        areas = page.search_for(entity_text)
        for rect in areas:
            page.add_redact_annot(rect, fill=(0, 0, 0))
            redaction_count += 1

    if redaction_count:
        page.apply_redactions(images=0, graphics=0, text=2)
    return redaction_count


def _redact_pdf(input_path: Path, output_path: Path) -> int:
    document = pymupdf.open(input_path)
    total_redactions = 0
    try:
        for page in document:
            # Try fast native text extraction first
            count = _redact_pdf_page_native(page)
            if count >= 0:
                total_redactions += count
                continue

            # Fallback to OCR for scanned / image-only pages
            pixmap = page.get_pixmap(matrix=pymupdf.Matrix(2, 2), alpha=False)
            page_image = Image.frombytes("RGB", (pixmap.width, pixmap.height), pixmap.samples)
            lines = _ocr_lines(page_image)
            indexes = _pii_line_indexes(lines)
            scale_x = pixmap.width / page.rect.width
            scale_y = pixmap.height / page.rect.height

            for index in indexes:
                points = lines[index].polygon
                rectangle = pymupdf.Rect(
                    min(point[0] for point in points) / scale_x,
                    min(point[1] for point in points) / scale_y,
                    max(point[0] for point in points) / scale_x,
                    max(point[1] for point in points) / scale_y,
                )
                rectangle &= page.rect
                if not rectangle.is_empty and rectangle.is_valid:
                    page.add_redact_annot(rectangle, fill=(0, 0, 0))
                    total_redactions += 1

            page.apply_redactions(images=2, graphics=0, text=0)

        document.save(output_path, garbage=4, deflate=True)
    finally:
        document.close()
    return total_redactions


def _redact_text_file(input_path: Path, output_path: Path) -> int:
    text = input_path.read_text(encoding="utf-8")
    results = _analyze(text)
    redacted = _get_anonymizer().anonymize(text=text, analyzer_results=results).text
    output_path.write_text(redacted, encoding="utf-8")
    return len(results)


def redact_file(input_file: str | Path, output_file: str | Path | None = None) -> Path:
    """Redact a supported file and return the output path."""
    source = Path(input_file)
    if not source.is_file():
        raise FileNotFoundError(f"Input file does not exist: {source}")

    extension = source.suffix.lower()
    if extension not in SUPPORTED_EXTENSIONS:
        supported = ", ".join(sorted(SUPPORTED_EXTENSIONS))
        raise ValueError(f"Unsupported file type {extension!r}. Supported types: {supported}")

    destination = (
        Path(output_file)
        if output_file is not None
        else source.with_name(f"{source.stem}_redacted{source.suffix}")
    )
    destination.parent.mkdir(parents=True, exist_ok=True)

    if extension == ".docx":
        process_docx(source, destination)
        _redact_docx_images(destination)
    elif extension == ".pptx":
        process_pptx(source, destination)
        _redact_pptx_images(destination)
    elif extension == ".pdf":
        _redact_pdf(source, destination)
    elif extension in IMAGE_EXTENSIONS:
        _redact_image_file(source, destination)
    else:
        _redact_text_file(source, destination)

    return destination


def main() -> None:
    parser = argparse.ArgumentParser(description="Redact PII from supported files.")
    parser.add_argument("input_file", type=Path, help="Path to the file to redact")
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        help="Output file path (defaults to <name>_redacted.<extension>)",
    )
    arguments = parser.parse_args()
    output = redact_file(arguments.input_file, arguments.output)
    print(f"Redaction complete: {output}")


if __name__ == "__main__":
    main()
