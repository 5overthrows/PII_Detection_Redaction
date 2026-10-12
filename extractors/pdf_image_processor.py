"""
PyMuPDF-Powered Embedded Image Extraction, Analysis & Redaction Processor.
Provides:
1. High-fidelity embedded image extraction from PDF streams
2. Spatial coordinate & layout mapping (page, bbox rects, resolutions)
3. Cryptographic deduplication (MD5) to isolate recurring assets (logos/headers)
4. Barcode & QR Code detection/decoding (extracts hidden credentials/PII)
5. OCR text recovery pipeline (with robust graceful degradation)
6. EXIF metadata scanning (detects embedded author/device/GPS metadata)
7. Cross-referencing with PII Detection Engine (tags PII to exact image rects)
8. Visual & stream-level image redaction (pixel masking & placeholder replacement)
"""
import io
import os
import hashlib
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, field
from PIL import Image, ImageDraw, ImageFont
import pymupdf

from detector.pii_models import PIIEntity


@dataclass
class EmbeddedImageRecord:
    """Detailed record of an image embedded within a PDF document."""
    image_id: str                      # e.g., "pdf_p1_img0"
    xref: int                          # PyMuPDF xref object number
    page_number: int                   # 1-indexed
    width: int
    height: int
    format: str                        # "png", "jpeg", etc.
    colorspace: str
    size_bytes: int
    bbox: List[float]                  # [x0, y0, x1, y1] on page
    md5_hash: str
    image_bytes: bytes
    classification: str                # "QR / Barcode", "Document / ID Scan", "Logo / Graphic", "Photo / Figure"
    barcode_data: List[Dict[str, str]] = field(default_factory=list)
    ocr_text: str = ""
    exif_data: Dict[str, Any] = field(default_factory=list)
    extracted_text: str = ""           # Aggregated textual content
    detected_entities: List[PIIEntity] = field(default_factory=list)
    has_pii: bool = False
    is_duplicate: bool = False

    @property
    def dimensions_str(self) -> str:
        return f"{self.width}x{self.height}"

    @property
    def size_kb(self) -> float:
        return round(self.size_bytes / 1024, 2)


class PDFImageProcessor:
    """Specialized engine for processing, analyzing, and redacting images embedded in PDFs."""

    @classmethod
    def process_pdf_images(cls, doc: pymupdf.Document) -> Tuple[List[EmbeddedImageRecord], List[PIIEntity]]:
        """
        Extracts all embedded images across all pages in the PDF,
        inspects them for barcodes/QR codes, OCR text, and EXIF,
        runs PII detection on any recovered text, and maps entities back to image coordinates.
        """
        from detector.pii_engine import PIIEngine

        image_records: List[EmbeddedImageRecord] = []
        all_image_entities: List[PIIEntity] = []
        seen_md5: Dict[str, str] = {}  # md5 -> first image_id
        cache_by_md5: Dict[str, Dict[str, Any]] = {}
        img_counter = 0

        for page_idx, page in enumerate(doc, start=1):
            image_list = page.get_images(full=True)
            for img_info in image_list:
                xref = img_info[0]
                try:
                    base_image = doc.extract_image(xref)
                except Exception:
                    continue

                if not base_image or "image" not in base_image:
                    continue

                img_bytes = base_image["image"]
                ext = base_image.get("ext", "png").lower()
                width = base_image.get("width", 0)
                height = base_image.get("height", 0)
                colorspace = str(base_image.get("colorspace", "RGB"))
                size_bytes = len(img_bytes)

                # Compute MD5
                md5_hash = hashlib.md5(img_bytes).hexdigest()
                is_duplicate = md5_hash in seen_md5

                # Spatial bounding boxes
                rects = page.get_image_rects(xref)
                bbox = [round(rects[0].x0, 2), round(rects[0].y0, 2), round(rects[0].x1, 2), round(rects[0].y1, 2)] if rects else [0.0, 0.0, 0.0, 0.0]

                image_id = f"pdf_p{page_idx}_img{img_counter}"
                img_counter += 1

                is_full_page_scan = (width >= 800 and height >= 1000 and len(image_list) == 1)

                if is_duplicate and md5_hash in cache_by_md5:
                    cached = cache_by_md5[md5_hash]
                    barcode_results = cached["barcodes"]
                    exif_results = cached["exif"]
                    ocr_text = cached["ocr"]
                    classification = cached["classification"]
                    combined_text = cached["text"]
                else:
                    seen_md5[md5_hash] = image_id

                    # 1. Barcode / QR Code Scanning (skip if tiny icon or full-page scanned background)
                    if width >= 32 and height >= 32 and not is_full_page_scan:
                        barcode_results = cls.scan_barcodes(img_bytes)
                    else:
                        barcode_results = []

                    # 2. EXIF Metadata Inspection
                    exif_results = cls.scan_exif(img_bytes)

                    # 3. Optical Character Recognition (OCR)
                    # Skip full-page scan backgrounds: page-level OCR in pdf_extractor handles them natively
                    if is_full_page_scan:
                        ocr_text = ""
                    elif width >= 32 and height >= 32:
                        ocr_text = cls.run_ocr_if_available(img_bytes, page=page, rect=rects[0] if rects else None)
                    else:
                        ocr_text = ""

                    # 4. Aggregate extracted textual content
                    extracted_lines = []
                    for bc in barcode_results:
                        extracted_lines.append(f"Barcode/QR [{bc.get('type', 'CODE')}]: {bc.get('data', '')}")
                    if ocr_text:
                        extracted_lines.append(f"OCR Extracted: {ocr_text}")
                    for k, v in exif_results.items():
                        if any(term in k.lower() for term in ["artist", "author", "user", "comment", "title", "description", "serial"]):
                            extracted_lines.append(f"EXIF {k}: {v}")

                    combined_text = "\n".join(extracted_lines).strip()

                    # 5. Image Classification
                    if is_full_page_scan:
                        classification = "Scanned Page"
                    else:
                        classification = cls.classify_image(width, height, bool(barcode_results), bool(ocr_text), is_duplicate)

                    cache_by_md5[md5_hash] = {
                        "barcodes": barcode_results,
                        "exif": exif_results,
                        "ocr": ocr_text,
                        "classification": classification,
                        "text": combined_text
                    }

                # 6. PII Detection on recovered text (lightweight regex pass; full document scan runs later)
                image_entities: List[PIIEntity] = []
                if combined_text:
                    image_location = {
                        "page": page_idx,
                        "image_id": image_id,
                        "image_xref": xref,
                        "bbox": bbox,
                        "source_type": "embedded_image",
                        "image_format": ext,
                        "classification": classification
                    }
                    detected = PIIEngine.detect_in_text(combined_text, block_id=image_id, location=image_location, skip_neural=True)
                    for ent in detected:
                        ent.source = f"{ent.source}+PyMuPDF_Image"
                        image_entities.append(ent)
                        all_image_entities.append(ent)

                record = EmbeddedImageRecord(
                    image_id=image_id,
                    xref=xref,
                    page_number=page_idx,
                    width=width,
                    height=height,
                    format=ext,
                    colorspace=colorspace,
                    size_bytes=size_bytes,
                    bbox=bbox,
                    md5_hash=md5_hash,
                    image_bytes=img_bytes,
                    classification=classification,
                    barcode_data=barcode_results,
                    ocr_text=ocr_text,
                    exif_data=exif_results,
                    extracted_text=combined_text,
                    detected_entities=image_entities,
                    has_pii=bool(image_entities),
                    is_duplicate=is_duplicate
                )
                image_records.append(record)

        return image_records, all_image_entities

    @classmethod
    def scan_barcodes(cls, image_bytes: bytes) -> List[Dict[str, str]]:
        """Scans image for 1D and 2D barcodes (QR codes, PDF417, Code128) using pyzbar."""
        results = []
        try:
            from pyzbar.pyzbar import decode as pyzbar_decode
            pil_img = Image.open(io.BytesIO(image_bytes))
            decoded_objects = pyzbar_decode(pil_img)
            for obj in decoded_objects:
                data_str = obj.data.decode("utf-8", errors="replace").strip()
                if data_str:
                    results.append({
                        "type": str(obj.type),
                        "data": data_str,
                        "rect": [obj.rect.left, obj.rect.top, obj.rect.width, obj.rect.height] if hasattr(obj, "rect") else []
                    })
        except Exception:
            pass
        return results

    @classmethod
    def scan_exif(cls, image_bytes: bytes) -> Dict[str, Any]:
        """Extracts EXIF metadata tags that may contain author or location information."""
        exif_info: Dict[str, Any] = {}
        try:
            pil_img = Image.open(io.BytesIO(image_bytes))
            raw_exif = pil_img.getexif()
            if raw_exif:
                from PIL.ExifTags import TAGS
                for tag_id, value in raw_exif.items():
                    tag_name = TAGS.get(tag_id, str(tag_id))
                    # Ignore binary thumbnails or giant raw bytes
                    if isinstance(value, (str, int, float)) and len(str(value)) < 256:
                        exif_info[tag_name] = str(value)
        except Exception:
            pass
        return exif_info

    @classmethod
    def run_ocr_if_available(cls, image_bytes: bytes, page: Optional[pymupdf.Page] = None, rect: Optional[Any] = None) -> str:
        """
        Attempts OCR text recovery using PyMuPDF get_textpage_ocr or pytesseract if installed.
        Gracefully returns empty string if OCR engine/tessdata is not installed.
        """
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        tessdata_dir = os.path.join(base_dir, "tessdata")
        has_tessdata = os.path.exists(os.path.join(tessdata_dir, "eng.traineddata"))

        # 1. Check if PyMuPDF page-level OCR is available
        if page is not None and rect is not None and has_tessdata:
            try:
                ocr_tp = page.get_textpage_ocr(tessdata=tessdata_dir, clip=rect, dpi=200)
                text = page.get_text("text", textpage=ocr_tp)
                if text and text.strip():
                    return text.strip()
            except Exception:
                pass

        # 2. Check pytesseract if installed
        try:
            import pytesseract
            pil_img = Image.open(io.BytesIO(image_bytes))
            text = pytesseract.image_to_string(pil_img)
            if text and text.strip():
                return text.strip()
        except Exception:
            pass

        return ""

    @classmethod
    def classify_image(cls, width: int, height: int, has_barcode: bool, has_ocr: bool, is_duplicate: bool) -> str:
        """Heuristically classifies the functional role of an embedded image."""
        if has_barcode:
            return "QR / Barcode (Encoded Data)"
        if is_duplicate or (width < 180 and height < 180):
            return "Brand / Logo / Icon"
        if has_ocr or (width >= 250 and height >= 150 and 1.2 <= (width / max(1, height)) <= 1.8):
            return "Document / ID Scan"
        if width > 400 and height > 200:
            return "Chart / Technical Diagram"
        return "Embedded Graphic / Photo"

    @classmethod
    def generate_redacted_placeholder(cls, width: int, height: int, entity_label: str = "PII PROTECTED") -> bytes:
        """
        Generates a clean, professional sanitized placeholder image using Pillow
        to completely mask underlying sensitive pixels in the PDF stream.
        """
        w = max(120, width)
        h = max(60, height)
        img = Image.new("RGB", (w, h), color=(241, 245, 249)) # Light slate
        draw = ImageDraw.Draw(img)

        # Border
        draw.rectangle([0, 0, w - 1, h - 1], outline=(220, 80, 40), width=max(2, int(min(w, h) * 0.02)))

        # Header banner
        banner_h = max(24, int(h * 0.35))
        draw.rectangle([0, 0, w, banner_h], fill=(14, 43, 92)) # Cadence Navy

        # Text banner
        banner_text = "🛡️ OPTIV // REDACTED"
        info_text = f"[{entity_label}]"
        sub_text = "Cadence AI Directive 2026-R4"

        try:
            # Simple default font rendering
            draw.text((8, 4), banner_text, fill=(255, 255, 255))
            draw.text((8, banner_h + 4), info_text, fill=(220, 80, 40))
            if h >= 100:
                draw.text((8, banner_h + 22), sub_text, fill=(100, 116, 139))
        except Exception:
            pass

        out_io = io.BytesIO()
        img.save(out_io, format="PNG")
        return out_io.getvalue()

    @classmethod
    def redact_pdf_images(
        cls,
        doc: pymupdf.Document,
        image_records: List[EmbeddedImageRecord],
        entities_to_redact: List[PIIEntity]
    ) -> int:
        """
        Applies both PyMuPDF visual vector redaction annotations and binary pixel
        replacements for embedded images flagged as containing sensitive PII.
        Returns the number of images redacted.
        """
        redacted_count = 0
        sensitive_xrefs = set()

        # Find xrefs of images associated with any redacted entity
        for ent in entities_to_redact:
            if ent.location and "image_xref" in ent.location:
                sensitive_xrefs.add(ent.location["image_xref"])

        for rec in image_records:
            if rec.has_pii or rec.xref in sensitive_xrefs:
                page_idx = rec.page_number - 1
                if 0 <= page_idx < len(doc):
                    page = doc[page_idx]
                    rects = page.get_image_rects(rec.xref)
                    for r in rects:
                        # 1. Native PyMuPDF Redaction annotation
                        page.add_redact_annot(
                            r,
                            text="[CONFIDENTIAL // EMBEDDED IMAGE PII REDACTED]",
                            fontsize=max(7.0, min(11.0, r.height * 0.15)),
                            fill=(0.94, 0.94, 0.96),
                            text_color=(0.85, 0.20, 0.15),
                            cross_out=False
                        )

                    # 2. Binary stream replacement for deep privacy security
                    try:
                        placeholder_bytes = cls.generate_redacted_placeholder(
                            rec.width, rec.height, entity_label="SENSITIVE IDENTIFIER MASKED"
                        )
                        page.replace_image(rec.xref, stream=placeholder_bytes)
                    except Exception:
                        pass

                    redacted_count += 1

        return redacted_count
