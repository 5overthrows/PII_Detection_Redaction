"""
Text, CSV and Markdown extractor preserving structure and line positions.
"""
import os
import csv
from typing import List
from extractors.models import DocumentContent, ContentBlock

class TextExtractor:
    @staticmethod
    def extract(file_path: str) -> DocumentContent:
        file_name = os.path.basename(file_path)
        ext = os.path.splitext(file_path)[1].lower()
        blocks: List[ContentBlock] = []
        raw_text_parts: List[str] = []

        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()

        if ext == ".csv":
            reader = csv.reader(lines)
            for r_idx, row in enumerate(reader):
                row_str = " | ".join(row)
                block = ContentBlock(
                    block_id=f"csv_r{r_idx}",
                    block_type="table_row",
                    text=row_str,
                    location={"line": r_idx + 1, "type": "csv_row"},
                    style_metadata={"is_header": (r_idx == 0)}
                )
                blocks.append(block)
                raw_text_parts.append(row_str)
        else:
            for l_idx, line in enumerate(lines, start=1):
                clean = line.strip()
                if not clean:
                    continue
                
                is_heading = clean.startswith(("#", "CADENCE", "MEMORANDUM", "SUBJECT:", "DATE:"))
                is_bullet = clean.startswith(("-", "*", "•", "1.", "2.", "3."))

                block = ContentBlock(
                    block_id=f"txt_l{l_idx}",
                    block_type="heading" if is_heading else ("bullet" if is_bullet else "paragraph"),
                    text=clean,
                    location={"line": l_idx}
                )
                blocks.append(block)
                raw_text_parts.append(clean)

        full_raw_text = "\n".join(raw_text_parts)
        metadata = {
            "line_count": len(lines),
            "source_type": ext.replace(".", "")
        }

        return DocumentContent(
            file_name=file_name,
            file_type=ext.replace(".", ""),
            raw_text=full_raw_text,
            blocks=blocks,
            metadata=metadata
        )
