"""
PyMuPDF-Powered Enterprise PDF Extractor.
Extracts vector text, headings, tabular structures, annotations, and embedded images.
Performs QR/barcode analysis, EXIF inspection, and OCR text recovery on embedded graphics.
Falls back to pdfplumber/pypdf if necessary.
"""
import os
from typing import List, Dict, Any
from extractors.models import DocumentContent, ContentBlock
from extractors.pdf_image_processor import PDFImageProcessor, EmbeddedImageRecord


class PdfExtractor:
    @staticmethod
    def extract(file_path: str) -> DocumentContent:
        file_name = os.path.basename(file_path)
        blocks: List[ContentBlock] = []
        raw_text_parts: List[str] = []
        block_counter = 0
        total_pages = 0
        image_records: List[EmbeddedImageRecord] = []
        annotation_count = 0
        fallback_warning = ""

        try:
            import pymupdf

            doc = pymupdf.open(file_path)
            total_pages = len(doc)

            # 1. Process Embedded Images across all pages using PyMuPDF (skip for already-redacted verification outputs)
            if not file_name.startswith("redacted_"):
                image_records, _ = PDFImageProcessor.process_pdf_images(doc)
            else:
                image_records = []

            # Locate local tessdata for native PyMuPDF OCR
            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            tessdata_dir = os.path.join(base_dir, "tessdata")
            has_tessdata = os.path.exists(os.path.join(tessdata_dir, "eng.traineddata"))
            scanned_pages_count = 0
            ocr_performed = False

            for page_idx, page in enumerate(doc, start=1):
                # Count and inspect annotations
                page_annots = list(page.annots() or [])
                annotation_count += len(page_annots)
                for annot_idx, annot in enumerate(page_annots):
                    annot_text = (annot.info.get("content") or "").strip()
                    if annot_text:
                        block = ContentBlock(
                            block_id=f"pdf_p{page_idx}_annot{annot_idx}",
                            block_type="annotation",
                            text=annot_text,
                            location={"page": page_idx, "annot_index": annot_idx, "type": annot.type[1]},
                            style_metadata={"author": annot.info.get("title", "")}
                        )
                        blocks.append(block)
                        raw_text_parts.append(annot_text)
                        block_counter += 1

                # 2. Extract structured tables using PyMuPDF table finder
                tables = page.find_tables()
                table_bboxes = []
                for t_idx, tbl in enumerate(tables):
                    table_bboxes.append(tbl.bbox)
                    for r_idx, row in enumerate(tbl.extract()):
                        cleaned_row = [str(c).strip() if c is not None else "" for c in row]
                        if any(cleaned_row):
                            row_str = " | ".join(cleaned_row)
                            block = ContentBlock(
                                block_id=f"pdf_p{page_idx}_tbl{t_idx}_r{r_idx}",
                                block_type="table_row",
                                text=row_str,
                                location={"page": page_idx, "table": t_idx, "row": r_idx},
                                style_metadata={"is_header": (r_idx == 0)}
                            )
                            blocks.append(block)
                            raw_text_parts.append(row_str)
                            block_counter += 1

                # 3. Extract text blocks using PyMuPDF (with automatic OCR for scanned/image-only pages)
                raw_page_text = page.get_text().strip()
                if not raw_page_text and has_tessdata:
                    try:
                        tp = page.get_textpage_ocr(tessdata=tessdata_dir, dpi=200)
                        text_blocks = page.get_text("blocks", textpage=tp)
                        scanned_pages_count += 1
                        ocr_performed = True
                    except Exception:
                        text_blocks = page.get_text("blocks")
                else:
                    text_blocks = page.get_text("blocks")

                page_candidates = []
                for b_idx, b in enumerate(text_blocks):
                    # block_type 0 is text, 1 is image
                    if b[6] != 0:
                        continue
                    b_rect = pymupdf.Rect(b[:4])
                    # Avoid duplicate extraction if block overlaps an already-extracted table
                    in_table = any(b_rect.intersects(t_bbox) for t_bbox in table_bboxes)
                    if in_table:
                        continue

                    raw_b_text = b[4].strip()
                    if not raw_b_text:
                        continue

                    clean_lines = [l.strip() for l in raw_b_text.splitlines() if l.strip()]
                    if not clean_lines:
                        continue

                    first_line = clean_lines[0]
                    is_heading = len(clean_lines) == 1 and len(first_line) < 70 and (
                        first_line.isupper() or first_line.startswith(("1.", "2.", "3.", "4.", "5.", "6.", "7.", "8.", "9.", "Section", "CADENCE", "POLICY", "APPENDIX"))
                    )
                    is_bullet = first_line.startswith(("-", "•", "*", "▪", "◦"))
                    b_type = "heading" if is_heading else ("bullet" if is_bullet else "paragraph")
                    joined_text = " ".join(clean_lines)
                    page_candidates.append({
                        "type": b_type,
                        "text": joined_text,
                        "lines_count": len(clean_lines),
                        "bbox": [round(x, 2) for x in b[:4]],
                        "is_heading": is_heading
                    })

                # Aggregate contiguous paragraph lines/fragments into coherent paragraphs
                aggregated_blocks = []
                for item in page_candidates:
                    if aggregated_blocks:
                        prev = aggregated_blocks[-1]
                        # Merge if both are standard paragraphs and vertical distance is small (<= 16pt)
                        vert_gap = item["bbox"][1] - prev["bbox"][3]
                        if prev["type"] == "paragraph" and item["type"] == "paragraph" and 0 <= vert_gap <= 16:
                            prev["text"] = prev["text"] + " " + item["text"]
                            prev["bbox"][2] = max(prev["bbox"][2], item["bbox"][2])
                            prev["bbox"][3] = item["bbox"][3]
                            prev["lines_count"] += item["lines_count"]
                            continue
                    aggregated_blocks.append(item)

                for agg_idx, agg in enumerate(aggregated_blocks):
                    block = ContentBlock(
                        block_id=f"pdf_p{page_idx}_b{agg_idx}",
                        block_type=agg["type"],
                        text=agg["text"],
                        location={"page": page_idx, "block": agg_idx, "bbox": agg["bbox"]},
                        style_metadata={"heading": agg.get("is_heading", False), "lines_count": agg.get("lines_count", 1)}
                    )
                    blocks.append(block)
                    raw_text_parts.append(agg["text"])
                    block_counter += 1

            # 4. Integrate extracted image text (Barcodes, QR codes, OCR, EXIF) as ContentBlocks
            for rec in image_records:
                if rec.extracted_text and not rec.is_duplicate and rec.classification != "Scanned Page":
                    img_block = ContentBlock(
                        block_id=rec.image_id,
                        block_type="image_text",
                        text=rec.extracted_text,
                        location={
                            "page": rec.page_number,
                            "image_xref": rec.xref,
                            "bbox": rec.bbox,
                            "source_type": "embedded_image"
                        },
                        style_metadata={
                            "classification": rec.classification,
                            "format": rec.format,
                            "dimensions": rec.dimensions_str,
                            "has_pii": rec.has_pii
                        }
                    )
                    blocks.append(img_block)
                    raw_text_parts.append(rec.extracted_text)
                    block_counter += 1

            doc.close()

        except Exception as e:
            # Fallback to pdfplumber / pypdf
            fallback_warning = f"PyMuPDF primary parser exception: {type(e).__name__} ({str(e)})"
            try:
                import pdfplumber
                with pdfplumber.open(file_path) as pdf:
                    total_pages = len(pdf.pages)
                    for page_idx, page in enumerate(pdf.pages, start=1):
                        text = page.extract_text() or ""
                        for p_idx, line in enumerate(text.splitlines()):
                            if line.strip():
                                blocks.append(ContentBlock(
                                    block_id=f"pdf_fb_p{page_idx}_l{p_idx}",
                                    block_type="paragraph",
                                    text=line.strip(),
                                    location={"page": page_idx, "line": p_idx}
                                ))
                                raw_text_parts.append(line.strip())
            except Exception:
                import pypdf
                reader = pypdf.PdfReader(file_path)
                total_pages = len(reader.pages)
                for page_idx, page in enumerate(reader.pages, start=1):
                    text = page.extract_text() or ""
                    for p_idx, line in enumerate(text.splitlines()):
                        if line.strip():
                            blocks.append(ContentBlock(
                                block_id=f"pdf_fb2_p{page_idx}_l{p_idx}",
                                block_type="paragraph",
                                text=line.strip(),
                                location={"page": page_idx, "line": p_idx}
                            ))
                            raw_text_parts.append(line.strip())

        full_raw_text = "\n".join(raw_text_parts)

        # Image summary metadata for reporting and UI
        images_summary = [
            {
                "image_id": rec.image_id,
                "page": rec.page_number,
                "xref": rec.xref,
                "dimensions": rec.dimensions_str,
                "format": rec.format.upper(),
                "size_kb": rec.size_kb,
                "bbox": rec.bbox,
                "classification": rec.classification,
                "barcode_count": len(rec.barcode_data),
                "has_ocr": bool(rec.ocr_text),
                "has_pii": rec.has_pii,
                "is_duplicate": rec.is_duplicate,
                "extracted_text": rec.extracted_text[:120] + ("..." if len(rec.extracted_text) > 120 else "")
            }
            for rec in image_records
        ]

        ocr_performed = ocr_performed or any(bool(rec.ocr_text) for rec in image_records)
        barcodes_count = sum(len(rec.barcode_data) for rec in image_records)
        images_with_pii = sum(1 for rec in image_records if rec.has_pii)

        metadata = {
            "page_count": total_pages,
            "source_type": "pdf",
            "embedded_images": images_summary,
            "image_records": image_records,
            "coverage": {
                "text_extracted": bool(full_raw_text.strip()),
                "ocr_performed": ocr_performed,
                "scanned_pages_ocr_processed": scanned_pages_count,
                "image_count": len(image_records),
                "barcodes_decoded": barcodes_count,
                "images_with_pii": images_with_pii,
                "annotation_count": annotation_count,
                "warnings": ([fallback_warning] if fallback_warning else []) +
                    ([f"{scanned_pages_count} scanned page(s) OCR-processed at 200 DPI via PyMuPDF."] if scanned_pages_count else []) +
                    ([f"{len(image_records)} embedded image(s) processed via PyMuPDF ({barcodes_count} barcodes/QRs decoded, {images_with_pii} with PII)."] if image_records else []) +
                    (["No text layer detected; scanned/image-only pages require OCR before release."] if not full_raw_text.strip() and total_pages else [])
            }
        }

        return DocumentContent(
            file_name=file_name,
            file_type="pdf",
            raw_text=full_raw_text,
            blocks=blocks,
            metadata=metadata
        )
