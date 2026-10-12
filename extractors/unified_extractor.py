"""
Unified Document Ingestion and Extraction Gateway.
Coordinates format-specific extractors and evaluates structural retention score.
"""
import os
from extractors.models import DocumentContent
from extractors.docx_extractor import DocxExtractor
from extractors.pptx_extractor import PptxExtractor
from extractors.pdf_extractor import PdfExtractor
from extractors.text_extractor import TextExtractor

class UnifiedExtractor:
    SUPPORTED_EXTENSIONS = {
        ".docx": DocxExtractor,
        ".pptx": PptxExtractor,
        ".pdf": PdfExtractor,
        ".txt": TextExtractor,
        ".csv": TextExtractor,
        ".md": TextExtractor,
    }

    @classmethod
    def extract_document(cls, file_path: str) -> DocumentContent:
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")

        ext = os.path.splitext(file_path)[1].lower()
        extractor_cls = cls.SUPPORTED_EXTENSIONS.get(ext)

        if not extractor_cls:
            # Fallback to TextExtractor
            doc = TextExtractor.extract(file_path)
        else:
            doc = extractor_cls.extract(file_path)

        # Extraction coverage is not output-format retention. Measure and label
        # what was actually observed; output retention is measured after export.
        doc.metadata.setdefault("coverage", {"text_extracted": bool(doc.raw_text.strip()), "warnings": []})
        doc.metadata["structural_retention_score"] = None
        doc.metadata["structural_retention_pct"] = "Not measured"
        doc.metadata["structure_valid"] = None

        return doc

    @staticmethod
    def evaluate_structural_retention(doc: DocumentContent) -> float:
        """Return None: preservation cannot be measured before a native export exists."""
        return None
