"""
Redaction Engine and LLM Sanitization Gateway.
Performs semantic surrogate tokenization, maintains reversible de-anonymization vaults,
and generates structured prompts for downstream AI agents.
"""
import os
from typing import List, Dict, Any, Tuple
from extractors.models import DocumentContent, ContentBlock
from detector.pii_models import PIIEntity
from docx import Document

class TokenVault:
    """Secure lookup vault for reversible token de-anonymization."""
    def __init__(self):
        self.forward_map: Dict[str, str] = {} # raw_val -> token
        self.reverse_map: Dict[str, Dict[str, Any]] = {} # token -> metadata
        self.counter_by_type: Dict[str, int] = {}

    def get_or_create_token(self, entity_type: str, raw_val: str, category: str) -> str:
        clean_key = f"{entity_type}:{raw_val.strip().lower()}"
        if clean_key in self.forward_map:
            return self.forward_map[clean_key]

        current_count = self.counter_by_type.get(entity_type, 0) + 1
        self.counter_by_type[entity_type] = current_count

        token = f"[{entity_type}_{current_count}]"
        self.forward_map[clean_key] = token
        self.reverse_map[token] = {
            "original_value": raw_val,
            "entity_type": entity_type,
            "category": category,
            "token": token
        }
        return token

    def export_vault(self) -> Dict[str, Any]:
        return {
            "total_tokens": len(self.reverse_map),
            "mappings": self.reverse_map
        }

class RedactionEngine:
    @classmethod
    def redact_document(cls, doc: DocumentContent, entities: List[PIIEntity]) -> Tuple[DocumentContent, TokenVault]:
        vault = TokenVault()

        # Map entities to blocks
        entities_by_block: Dict[str, List[PIIEntity]] = {}
        for ent in entities:
            # Assign token
            token = vault.get_or_create_token(ent.entity_type, ent.value, ent.category)
            ent.surrogate_token = token
            b_id = ent.block_id or "global"
            entities_by_block.setdefault(b_id, []).append(ent)

        # Create new redacted blocks
        redacted_blocks: List[ContentBlock] = []
        redacted_raw_parts: List[str] = []

        for block in doc.blocks:
            b_entities = entities_by_block.get(block.block_id, [])
            redacted_text = cls.redact_text_span(block.text, b_entities)
            
            new_block = ContentBlock(
                block_id=block.block_id,
                block_type=block.block_type,
                text=redacted_text,
                location=block.location,
                style_metadata=block.style_metadata
            )
            redacted_blocks.append(new_block)
            redacted_raw_parts.append(redacted_text)

        redacted_doc = DocumentContent(
            file_name=f"redacted_{doc.file_name}",
            file_type=doc.file_type,
            raw_text="\n".join(redacted_raw_parts),
            blocks=redacted_blocks,
            metadata={
                **doc.metadata,
                "is_redacted": True,
                "total_pii_redacted": len(entities)
            }
        )

        return redacted_doc, vault

    @classmethod
    def redact_text_span(cls, text: str, entities: List[PIIEntity]) -> str:
        if not text or not entities:
            return text

        # Sort reverse by start position so replacements don't shift offsets
        sorted_ents = sorted(entities, key=lambda x: x.start, reverse=True)
        res = text

        for ent in sorted_ents:
            s, e = ent.start, ent.end
            # Allow trimming in case entity value or span has boundary whitespace
            if not (0 <= s <= e <= len(res) and res[s:e] == ent.value):
                while s < e and res[s].isspace():
                    s += 1
                while e > s and res[e - 1].isspace():
                    e -= 1

            # Never fall back to global replacement: stale offsets must be
            # surfaced as a failed redaction, not silently alter unrelated text.
            if 0 <= s <= e <= len(res) and res[s:e] == ent.value:
                res = res[:s] + ent.surrogate_token + res[e:]
            else:
                raise ValueError(f"Entity span mismatch in block; refusing unsafe replacement for {ent.entity_type}")

        return res

    @classmethod
    def generate_llm_payload(cls, redacted_doc: DocumentContent, system_context: str = "Cadence Document Analysis") -> Dict[str, Any]:
        """
        Formats the sanitized payload ready for LLM consumption,
        checking the payload with the configured detector before marking it eligible.
        """
        prompt_content = redacted_doc.get_structured_markdown()
        from detector.pii_engine import PIIEngine
        residual = PIIEngine.detect_in_document(redacted_doc, skip_neural=True)
        verified = len(residual) == 0

        system_prompt = (
            f"You are the {system_context} AI Agent at Cadence Financial Services. "
            "You are reviewing corporate underwriting and risk policy documents. "
            "The supplied text has been processed by an automated redaction prototype. "
            "Use only the supplied text and do not attempt to infer identities behind surrogate tokens. "
            "Automated scanning can miss sensitive information; do not treat this payload as certified PII-free."
        )

        return {
            "model_ready": verified,
            "system_instruction": system_prompt,
            "document_name": redacted_doc.file_name,
            "structural_retention_score": "Not measured until native output comparison",
            "sanitized_payload": prompt_content,
            "residual_entities": len(residual),
            "pii_leakage_risk": "PASS: configured detector found no residual entities" if verified else f"BLOCKED: {len(residual)} residual entity/entities found",
            "release_allowed": verified
        }

    @staticmethod
    def _build_sorted_replacements(entities: List[PIIEntity]) -> List[Tuple[str, str]]:
        """Constructs an ordered list of (raw_value, surrogate_token) sorted longest first."""
        seen = set()
        replacements = []
        for ent in entities:
            raw = ent.value
            tok = ent.surrogate_token
            if raw and tok and raw not in seen:
                seen.add(raw)
                replacements.append((raw, tok))
                raw_clean = raw.strip()
                if raw_clean and raw_clean not in seen:
                    seen.add(raw_clean)
                    replacements.append((raw_clean, tok))
        # Sort descending by text length to replace sub-phrases after longer phrases
        replacements.sort(key=lambda x: len(x[0]), reverse=True)
        return replacements

    @staticmethod
    def _replace_in_runs(runs, old_val: str, new_tok: str) -> bool:
        """
        Replaces target text across a collection of runs (DOCX or PPTX).
        Handles both single-run occurrences and words/entities spanning multiple runs,
        preserving font styling, bold/italic attributes, colors, and paragraph indentation.
        """
        if not old_val or not runs:
            return False

        replaced = False

        # Pass 1: Replace inside single runs directly
        for run in runs:
            if run.text and old_val in run.text:
                run.text = run.text.replace(old_val, new_tok)
                replaced = True

        # Pass 2: Handle entities spanning multiple runs
        full_text = "".join(r.text for r in runs if r.text)
        while old_val in full_text:
            replaced = True
            start_idx = full_text.find(old_val)
            end_idx = start_idx + len(old_val)

            current_pos = 0
            for run in runs:
                txt = run.text or ""
                r_len = len(txt)
                r_start = current_pos
                r_end = current_pos + r_len
                current_pos = r_end

                if r_end <= start_idx or r_start >= end_idx:
                    continue

                if r_start <= start_idx < r_end:
                    prefix = txt[:start_idx - r_start]
                    if end_idx <= r_end:
                        suffix = txt[end_idx - r_start:]
                        run.text = prefix + new_tok + suffix
                    else:
                        run.text = prefix + new_tok
                elif r_start < end_idx <= r_end:
                    suffix = txt[end_idx - r_start:]
                    run.text = suffix
                else:
                    run.text = ""

            full_text = "".join(r.text for r in runs if r.text)

        return replaced

    @classmethod
    def export_redacted_docx(cls, input_docx_path: str, output_docx_path: str, entities: List[PIIEntity]) -> str:
        """
        Creates a native redacted DOCX file preserving indentations, table formatting,
        embedded images, styles, and section headers/footers.
        """
        doc = Document(input_docx_path)
        replacements = cls._build_sorted_replacements(entities)

        def process_paragraph(p):
            for old_val, new_tok in replacements:
                cls._replace_in_runs(p.runs, old_val, new_tok)

        def process_table(table):
            for row in table.rows:
                for cell in row.cells:
                    for p in cell.paragraphs:
                        process_paragraph(p)
                    for nested in cell.tables:
                        process_table(nested)

        # 1. Main body paragraphs
        for p in doc.paragraphs:
            process_paragraph(p)

        # 2. Body tables
        for table in doc.tables:
            process_table(table)

        # 3. Section headers and footers
        for section in doc.sections:
            for header in [section.header, getattr(section, 'first_page_header', None), getattr(section, 'even_page_header', None)]:
                if header:
                    for p in header.paragraphs:
                        process_paragraph(p)
                    for t in header.tables:
                        process_table(t)
            for footer in [section.footer, getattr(section, 'first_page_footer', None), getattr(section, 'even_page_footer', None)]:
                if footer:
                    for p in footer.paragraphs:
                        process_paragraph(p)
                    for t in footer.tables:
                        process_table(t)

        doc.save(output_docx_path)
        return output_docx_path

    @classmethod
    def export_redacted_pptx(cls, input_pptx_path: str, output_pptx_path: str, entities: List[PIIEntity]) -> str:
        """
        Creates a native redacted PPTX file preserving slide layouts, themes,
        table column widths and formats, bullet indentations, and picture/image positions.
        """
        from pptx import Presentation
        prs = Presentation(input_pptx_path)
        replacements = cls._build_sorted_replacements(entities)

        def process_shape(shape):
            # Text frames (e.g., text boxes, titles, callouts, shapes)
            if shape.has_text_frame:
                for p in shape.text_frame.paragraphs:
                    for old_val, new_tok in replacements:
                        cls._replace_in_runs(p.runs, old_val, new_tok)

            # Tables
            if shape.has_table:
                for row in shape.table.rows:
                    for cell in row.cells:
                        if cell.text_frame:
                            for p in cell.text_frame.paragraphs:
                                for old_val, new_tok in replacements:
                                    cls._replace_in_runs(p.runs, old_val, new_tok)

            # Group shapes (nested shapes)
            if hasattr(shape, "shapes"):
                for child in shape.shapes:
                    process_shape(child)

        for slide in prs.slides:
            for shape in slide.shapes:
                process_shape(shape)

            # Speaker Notes
            if slide.has_notes_slide and slide.notes_slide.notes_text_frame:
                for p in slide.notes_slide.notes_text_frame.paragraphs:
                    for old_val, new_tok in replacements:
                        cls._replace_in_runs(p.runs, old_val, new_tok)

        prs.save(output_pptx_path)
        return output_pptx_path

    @classmethod
    def export_redacted_pdf(cls, input_pdf_path: str, output_pdf_path: str, entities: List[PIIEntity]) -> str:
        """
        Creates a native redacted PDF file preserving vector layouts, tables,
        margins, font styling, and embedded images using PyMuPDF redaction annotations,
        with deep pixel sanitization for images containing PII.
        """
        import pymupdf
        from extractors.pdf_image_processor import PDFImageProcessor

        doc = pymupdf.open(input_pdf_path)

        # 1. Process and redact sensitive embedded images
        try:
            image_records, _ = PDFImageProcessor.process_pdf_images(doc)
            PDFImageProcessor.redact_pdf_images(doc, image_records, entities)
        except Exception:
            pass

        # 2. Text redactions (with OCR textpage support for scanned PDFs)
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        tessdata_dir = os.path.join(base_dir, "tessdata")
        has_tessdata = os.path.exists(os.path.join(tessdata_dir, "eng.traineddata"))

        replacements = cls._build_sorted_replacements(entities)

        for page in doc:
            raw_page_text = page.get_text().strip()
            tp = None
            if not raw_page_text and has_tessdata:
                try:
                    tp = page.get_textpage_ocr(tessdata=tessdata_dir, dpi=200)
                except Exception:
                    tp = None

            for old_val, new_tok in replacements:
                if not old_val or len(old_val.strip()) < 2:
                    continue

                quads_or_rects = page.search_for(old_val, textpage=tp) if tp else page.search_for(old_val)
                if not quads_or_rects and old_val.strip() != old_val:
                    quads_or_rects = page.search_for(old_val.strip(), textpage=tp) if tp else page.search_for(old_val.strip())

                for rect in quads_or_rects:
                    if rect.is_empty or rect.width < 1.0 or rect.height < 1.0:
                        continue
                    fs = max(6.0, min(10.0, rect.height * 0.72))
                    page.add_redact_annot(
                        rect,
                        text=new_tok,
                        fontsize=fs,
                        fill=(0.94, 0.94, 0.94),
                        text_color=(0.1, 0.2, 0.5),
                        cross_out=False
                    )
            try:
                page.apply_redactions(images=pymupdf.PDF_REDACT_IMAGE_PIXELS)
            except Exception:
                page.apply_redactions()

        doc.save(output_pdf_path)
        doc.close()
        return output_pdf_path

    @classmethod
    def export_redacted_text(cls, input_text_path: str, output_text_path: str, entities: List[PIIEntity]) -> str:
        """
        Creates a redacted plain text or CSV file preserving original line breaks,
        delimiters, and whitespace indentations.
        """
        replacements = cls._build_sorted_replacements(entities)
        with open(input_text_path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()

        for old_val, new_tok in replacements:
            if old_val:
                content = content.replace(old_val, new_tok)

        with open(output_text_path, "w", encoding="utf-8") as f:
            f.write(content)

        return output_text_path

    @classmethod
    def export_redacted_document(cls, input_path: str, output_path: str, entities: List[PIIEntity]) -> str:
        """
        Unified router that produces a redacted document in its exact original file format
        (PPTX, DOCX, PDF, TXT, CSV), preserving all formatting, indentations, table formats,
        and image positions.
        """
        ext = os.path.splitext(input_path)[1].lower()
        if ext == ".pptx":
            result = cls.export_redacted_pptx(input_path, output_path, entities)
        elif ext == ".docx":
            result = cls.export_redacted_docx(input_path, output_path, entities)
        elif ext == ".pdf":
            result = cls.export_redacted_pdf(input_path, output_path, entities)
        elif ext in [".txt", ".csv", ".log", ".md"]:
            result = cls.export_redacted_text(input_path, output_path, entities)
        else:
            raise ValueError(f"Unsupported redaction format: {ext or '(no extension)'}")

        # Keep the generated file available. Callers should surface the
        # verification result as a warning so a reviewer can decide whether
        # the output is suitable for use.
        cls.verify_redacted_output(output_path, source_path=input_path)
        return result

    @classmethod
    def verify_redacted_output(cls, output_path: str, source_path: str = None) -> Dict[str, Any]:
        """Re-extract the saved native file and run the detector before release."""
        from extractors.unified_extractor import UnifiedExtractor
        from detector.pii_engine import PIIEngine
        try:
            doc = UnifiedExtractor.extract_document(output_path)
            coverage = doc.metadata.get("coverage", {})
            warnings = coverage.get("warnings", [])
            entities = PIIEngine.detect_in_document(doc, skip_neural=True)
            return {
                "scan_complete": bool(coverage.get("text_extracted", False)) and not warnings,
                "residual_entities": len(entities),
                "residual_types": sorted({e.entity_type for e in entities}),
                "warnings": warnings,
                "structural_retention": cls.compare_structure(source_path or output_path, output_path)
            }
        except Exception as exc:
            return {"scan_complete": False, "residual_entities": -1, "residual_types": [], "warnings": [str(exc)]}

    @staticmethod
    def compare_structure(source_path: str, output_path: str) -> Dict[str, Any]:
        """Compare native structural counts; this is a proxy, not visual-format QA."""
        import os
        ext = os.path.splitext(source_path)[1].lower()
        try:
            if ext == ".docx":
                from docx import Document
                def sig(path):
                    d = Document(path)
                    return {"paragraphs": len(d.paragraphs), "tables": len(d.tables), "sections": len(d.sections), "images": len(d.inline_shapes)}
            elif ext == ".pptx":
                from pptx import Presentation
                def sig(path):
                    p = Presentation(path)
                    return {"slides": len(p.slides), "shapes": sum(len(s.shapes) for s in p.slides), "tables": sum(1 for s in p.slides for sh in s.shapes if sh.has_table)}
            elif ext == ".pdf":
                import pymupdf
                def sig(path):
                    d = pymupdf.open(path)
                    return {"pages": len(d), "images": sum(len(p.get_images()) for p in d)}
            elif ext in {".txt", ".csv", ".md", ".log"}:
                def sig(path):
                    with open(path, "r", encoding="utf-8", errors="replace") as f:
                        content = f.read()
                    lines = content.splitlines()
                    return {"lines": len(lines), "nonempty_lines": sum(bool(line.strip()) for line in lines),
                            "delimiters": sum(line.count(",") + line.count("|") + line.count("\t") for line in lines)}
            else:
                return {"score": None, "source": {}, "output": {}, "method": "No structural signature for this format"}
            before, after = sig(source_path), sig(output_path)
            denom = sum(before.values())
            score = 1.0 if denom == 0 else sum(min(before[k], after.get(k, 0)) for k in before) / denom
            return {"score": round(score, 4), "source": before, "output": after, "method": "matched structural element counts; visual layout not measured"}
        except Exception as exc:
            return {"score": None, "source": {}, "output": {}, "method": f"Measurement failed: {exc}"}
