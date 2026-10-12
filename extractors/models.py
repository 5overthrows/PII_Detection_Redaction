"""
Data models for document extraction and structural integrity retention.
"""
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional

@dataclass
class ContentBlock:
    """Represents a discrete structural unit (paragraph, heading, table row/cell, slide text)."""
    block_id: str
    block_type: str  # 'heading', 'paragraph', 'table_row', 'table_cell', 'bullet', 'slide_title', 'metadata'
    text: str
    location: Dict[str, Any] = field(default_factory=dict) # e.g. {'page': 1, 'slide': 2, 'table_index': 0, 'row': 1, 'col': 2}
    style_metadata: Dict[str, Any] = field(default_factory=dict) # bold, font_size, heading_level, etc.

@dataclass
class DocumentContent:
    """Standardized representation of an ingested business artifact."""
    file_name: str
    file_type: str  # 'docx', 'pptx', 'pdf', 'txt', 'csv'
    raw_text: str
    blocks: List[ContentBlock] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    @property
    def total_words(self) -> int:
        return len(self.raw_text.split())

    @property
    def total_blocks(self) -> int:
        return len(self.blocks)

    def get_structured_markdown(self) -> str:
        """
        Reconstructs the document with structural formatting (headings, markdown tables, bullets).
        Produces a readable text representation; this does not measure native-format preservation.
        """
        lines = []
        current_table_id = None
        table_rows = []

        for block in self.blocks:
            b_type = block.block_type
            text = block.text.strip()
            if not text:
                continue

            if b_type == 'heading':
                level = block.style_metadata.get('level', 2)
                lines.append(f"\n{'#' * level} {text}\n")
            elif b_type == 'slide_title':
                lines.append(f"\n## Slide: {text}\n")
            elif b_type == 'bullet':
                lines.append(f"- {text}")
            elif b_type == 'table_row':
                lines.append(f"| {text} |")
            else:
                lines.append(f"\n{text}\n")

        return "\n".join(lines).strip()
