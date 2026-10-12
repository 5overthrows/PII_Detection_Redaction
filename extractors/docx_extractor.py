"""
DOCX extractor preserving document structure, headings, lists, and tables.
"""
import os
from typing import List, Dict, Any
from docx import Document
from extractors.models import DocumentContent, ContentBlock

class DocxExtractor:
    @staticmethod
    def extract(file_path: str) -> DocumentContent:
        doc = Document(file_path)
        file_name = os.path.basename(file_path)
        blocks: List[ContentBlock] = []
        raw_text_parts: List[str] = []
        block_counter = 0

        # 1. Process paragraphs
        for p_idx, p in enumerate(doc.paragraphs):
            text = p.text.strip()
            if not text:
                continue

            style_name = p.style.name.lower() if p.style else ""
            block_type = "paragraph"
            heading_level = 2

            if "heading 1" in style_name or "title" in style_name:
                block_type = "heading"
                heading_level = 1
            elif "heading 2" in style_name:
                block_type = "heading"
                heading_level = 2
            elif "heading 3" in style_name:
                block_type = "heading"
                heading_level = 3
            elif "list" in style_name or "bullet" in style_name or text.startswith(("•", "-", "*")):
                block_type = "bullet"

            block = ContentBlock(
                block_id=f"docx_p_{block_counter}",
                block_type=block_type,
                text=p.text,
                location={"paragraph_index": p_idx, "section": "body"},
                style_metadata={"style_name": p.style.name if p.style else "", "level": heading_level}
            )
            blocks.append(block)
            raw_text_parts.append(p.text)
            block_counter += 1

        # 2. Process tables
        for t_idx, table in enumerate(doc.tables):
            for r_idx, row in enumerate(table.rows):
                row_cells_text = [cell.text.strip() for cell in row.cells]
                row_str = " | ".join(row_cells_text)
                
                block = ContentBlock(
                    block_id=f"docx_tbl_{t_idx}_r_{r_idx}",
                    block_type="table_row",
                    text=row_str,
                    location={"table_index": t_idx, "row": r_idx, "cell_count": len(row.cells)},
                    style_metadata={"is_header": (r_idx == 0)}
                )
                blocks.append(block)
                raw_text_parts.append(row_str)
                block_counter += 1

        # Headers and footers are visible document content and must enter the
        # same detection path as body text. Drawing/text-box content is flagged
        # because python-docx does not reliably expose all Word drawing text.
        for s_idx, section in enumerate(doc.sections):
            for part_name in ("header", "first_page_header", "even_page_header", "footer", "first_page_footer", "even_page_footer"):
                part = getattr(section, part_name, None)
                if part is None or part.is_linked_to_previous:
                    continue
                for p_idx, paragraph in enumerate(part.paragraphs):
                    if not paragraph.text.strip():
                        continue
                    blocks.append(ContentBlock(
                        block_id=f"docx_{part_name}_{s_idx}_{p_idx}", block_type="metadata",
                        text=paragraph.text, location={"section": s_idx, "part": part_name, "paragraph_index": p_idx}
                    ))
                    raw_text_parts.append(paragraph.text)
                for t_idx, table in enumerate(part.tables):
                    for r_idx, row in enumerate(table.rows):
                        row_str = " | ".join(cell.text.strip() for cell in row.cells)
                        blocks.append(ContentBlock(
                            block_id=f"docx_{part_name}_{s_idx}_tbl{t_idx}_r{r_idx}", block_type="table_row",
                            text=row_str, location={"section": s_idx, "part": part_name, "table_index": t_idx, "row": r_idx}
                        ))
                        raw_text_parts.append(row_str)

        full_raw_text = "\n".join(raw_text_parts)
        image_parts = set()
        for part in [doc.part] + [getattr(s, name, None) for s in doc.sections for name in
                                  ("header", "first_page_header", "even_page_header", "footer", "first_page_footer", "even_page_footer")]:
            target_part = getattr(part, 'part', part)
            if hasattr(target_part, 'rels'):
                for rel in target_part.rels.values():
                    if rel.reltype.endswith("/image"):
                        image_parts.add(rel.target_ref)
        textbox_count = len(doc.element.xpath(".//w:txbxContent"))

        metadata = {
            "paragraph_count": len(doc.paragraphs),
            "table_count": len(doc.tables),
            "source_type": "docx",
            "coverage": {
                "text_extracted": bool(full_raw_text.strip()),
                "ocr_performed": False,
                "image_count": len(image_parts),
                "text_box_count": textbox_count,
                "warnings": ([f"{len(image_parts)} embedded image(s) were not OCR-scanned."] if image_parts else []) +
                    ([f"{textbox_count} Word text box(es) were not extracted."] if textbox_count else [])
            }
        }

        return DocumentContent(
            file_name=file_name,
            file_type="docx",
            raw_text=full_raw_text,
            blocks=blocks,
            metadata=metadata
        )
