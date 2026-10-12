
"""
OpenAI Privacy Filter Integration Engine
========================================
Features:
- Local inference using openai/privacy-filter
- Targeted regex detection for structured PII
- Token-aware chunking with overlap
- Batched model inference
- Optiv taxonomy mapping
- Selective redaction using original character offsets
- Duplicate and overlapping span resolution
- Explicit scan status and fail-closed behaviour

Install:
    pip install torch transformers accelerate safetensors

Run:
    python privacy_filter_engine.py
"""

import re
import logging
from typing import Any, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------
# Configuration
# ---------------------------------------------------------

MODEL_ID = "openai/privacy-filter"

CONFIDENCE_THRESHOLD = 0.40

# Tune these according to available RAM / VRAM.
MAX_CHUNK_TOKENS = 400
CHUNK_OVERLAP_TOKENS = 50
BATCH_SIZE = 8

# True: don't return unverified text if model inference fails.
FAIL_CLOSED = True


# ---------------------------------------------------------
# Taxonomy mapping
# ---------------------------------------------------------

OPENAI_TO_OPTIV_TAXONOMY = {
    "account_number": "BANK_ACCOUNT",
    "private_address": "STREET_ADDRESS",
    "private_email": "EMAIL_ADDRESS",
    "private_person": "PERSON",
    "private_phone": "PHONE_NUMBER",
    "private_url": "URL_ADDRESS",
    "private_date": "DATE_OF_BIRTH",
    "secret": "SECRET_KEY",
}

# Exact-match exclusions only. Avoid adding sensitive values
# or generic words that could suppress real PII.
FALSE_POSITIVE_WHITELIST = {
    "checking",
    "savings",
    "escrow",
    "settlement",
    "balance",
    "balance usd",
    "operating checking",
    "escrow reserve",
    "visa infinite",
    "corporate card",
    "institution",
    "underwriting",
    "assessment",
    "policy",
    "cadence",
    "cadence financial services",
    "cadence commercial",
    "citibank",
    "citibank n.a.",
    "jpmorgan chase",
    "jpmorgan chase ny",
    "department",
    "division",
    "strictly confidential",
    "confidential",
    "incident review",
    "lead contractor",
    "senior risk manager",
    "senior underwriter",
    "table",
    "n/a",
    "na",
    "date",
    "subject",
    "memo",
    "memorandum",
    "optiv",
    "optiv consulting",
    "optiv automated pii gateway",
    "pii gateway",
    "gateway",
    "automated pii gateway",
    "tprm",
    "ai governance committee",
    "vendor api",
    "security incident review",
    "recommendation",
    "continuous",
    "reference pack",
}


# ---------------------------------------------------------
# Structured PII detection
# ---------------------------------------------------------

# These patterns are deliberately conservative. Validate
# them against your real documents and identifier formats.

STRUCTURED_PATTERNS = {
    "EMAIL_ADDRESS": re.compile(
        r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b",
        re.IGNORECASE,
    ),

    "EMPLOYEE_ID": re.compile(
        r"\b(?:EMP|EID)-[A-Z0-9-]+\b",
        re.IGNORECASE,
    ),

    "US_PASSPORT": re.compile(
        r"\bP\d{8}\b",
        re.IGNORECASE,
    ),

    "US_SSN": re.compile(
        r"\b(?!000|666|9\d{2})\d{3}"
        r"-(?!00)\d{2}-(?!0000)\d{4}\b"
    ),

    "INDIAN_PAN": re.compile(
        r"\b[A-Z]{5}\d{4}[A-Z]\b",
        re.IGNORECASE,
    ),

    "INDIAN_AADHAAR": re.compile(
        r"(?<!\d)(?:\d{4}[ -]){2}\d{4}(?!\d)"
    ),

    # API keys and tokens: generic patterns can produce
    # false positives, so validate against your use case.
    "SECRET_KEY": re.compile(
        r"\b(?:AKIA[0-9A-Z]{16}|"
        r"gh[pousr]_[A-Za-z0-9_]{20,}|"
        r"sk-[A-Za-z0-9_-]{20,})\b"
    ),
}


# ---------------------------------------------------------
# Exceptions
# ---------------------------------------------------------

class PrivacyFilterError(RuntimeError):
    """The PII scan could not be completed reliably."""


# ---------------------------------------------------------
# Main engine
# ---------------------------------------------------------

class OpenAIPrivacyFilterEngine:

    MODEL_ID = MODEL_ID

    _pipeline = None
    _tokenizer = None
    _model_load_error: Optional[str] = None

    # -----------------------------------------------------
    # Model loading
    # -----------------------------------------------------

    @classmethod
    def get_pipeline(cls):
        """
        Load the locally cached model once.
        No download is attempted because local_files_only=True.
        """
        if cls._pipeline is not None:
            return cls._pipeline

        try:
            import torch
            try:
                from transformers import (
                    AutoTokenizer,
                    AutoModelForTokenClassification,
                    pipeline,
                )
            except ImportError:
                from transformers.models.auto import (
                    AutoTokenizer,
                    AutoModelForTokenClassification,
                )
                from transformers.pipelines import pipeline

            tokenizer = AutoTokenizer.from_pretrained(
                cls.MODEL_ID,
                local_files_only=True,
            )

            model = AutoModelForTokenClassification.from_pretrained(
                cls.MODEL_ID,
                local_files_only=True,
                low_cpu_mem_usage=True,
            )

            # Avoid assuming CUDA exists.
            device = 0 if torch.cuda.is_available() else -1

            cls._pipeline = pipeline(
                task="token-classification",
                model=model,
                tokenizer=tokenizer,
                aggregation_strategy="simple",
                device=device,
            )

            cls._tokenizer = tokenizer

            logger.info(
                "Privacy Filter loaded on %s",
                "CUDA" if device == 0 else "CPU",
            )

            return cls._pipeline

        except Exception as exc:
            cls._model_load_error = (
                f"Privacy Filter model load failed: {exc}"
            )
            logger.exception(cls._model_load_error)
            raise PrivacyFilterError(
                cls._model_load_error
            ) from exc

    # -----------------------------------------------------
    # Text chunking
    # -----------------------------------------------------

    @classmethod
    def make_chunks(
        cls,
        text: str,
        max_tokens: int = MAX_CHUNK_TOKENS,
        overlap_tokens: int = CHUNK_OVERLAP_TOKENS,
    ) -> list[dict[str, Any]]:
        """
        Split text on tokenizer boundaries.

        Every chunk retains its original character offsets.
        Overlap helps preserve context around boundaries.
        """
        cls.get_pipeline()
        tokenizer = cls._tokenizer

        if max_tokens <= 0:
            raise ValueError("max_tokens must be positive")

        if not 0 <= overlap_tokens < max_tokens:
            raise ValueError(
                "overlap_tokens must be >= 0 and < max_tokens"
            )

        if not text:
            return []

        encoded = tokenizer(
            text,
            add_special_tokens=False,
            return_offsets_mapping=True,
            truncation=False,
        )

        offsets = encoded["offset_mapping"]
        if not offsets:
            return []

        chunks = []
        step = max_tokens - overlap_tokens

        for token_start in range(0, len(offsets), step):
            token_end = min(
                token_start + max_tokens,
                len(offsets),
            )

            char_start = offsets[token_start][0]
            char_end = offsets[token_end - 1][1]

            if char_end <= char_start:
                continue

            chunks.append({
                "text": text[char_start:char_end],
                "start": char_start,
                "end": char_end,
            })

            if token_end == len(offsets):
                break

        return chunks

    # -----------------------------------------------------
    # Candidate normalisation and filtering
    # -----------------------------------------------------

    @staticmethod
    def _make_entity(
        text: str,
        start: int,
        end: int,
        entity_type: str,
        confidence: float,
        source: str,
        raw_label: Optional[str] = None,
    ) -> Optional[dict[str, Any]]:

        if not (0 <= start < end <= len(text)):
            return None

        value = text[start:end]

        # Preserve exact original offsets. Do not strip the
        # value without also adjusting its boundaries.
        left_trim = len(value) - len(value.lstrip())
        right_trimmed = value.rstrip()

        start += left_trim
        end = start + len(right_trimmed) - left_trim

        if end <= start:
            return None

        value = text[start:end]

        if len(value.strip()) < 2:
            return None

        if value.strip().casefold() in FALSE_POSITIVE_WHITELIST:
            return None

        entity = {
            "entity_type": entity_type,
            "value": value,
            "start": start,
            "end": end,
            "confidence": round(float(confidence), 3),
            "source": source,
        }

        if raw_label:
            entity["raw_label"] = raw_label

        return entity

    # -----------------------------------------------------
    # Regex-based PII detection
    # -----------------------------------------------------

    @classmethod
    def detect_structured_pii(
        cls,
        text: str,
    ) -> list[dict[str, Any]]:

        candidates = []

        for entity_type, pattern in STRUCTURED_PATTERNS.items():
            for match in pattern.finditer(text):
                entity = cls._make_entity(
                    text=text,
                    start=match.start(),
                    end=match.end(),
                    entity_type=entity_type,
                    confidence=1.0,
                    source="Regex",
                )

                if entity:
                    candidates.append(entity)

        return candidates

    # -----------------------------------------------------
    # Model-based PII detection
    # -----------------------------------------------------

    @classmethod
    def detect_in_text(
        cls,
        text: str,
        confidence_threshold: float = CONFIDENCE_THRESHOLD,
    ) -> list[dict[str, Any]]:
        """
        Detect PII in one complete text.

        Raises PrivacyFilterError if model inference fails.
        Does not silently report a failed scan as clean.
        """
        if not text or len(text.strip()) < 4:
            return []

        classifier = cls.get_pipeline()

        chunks = cls.make_chunks(text)
        if not chunks:
            return cls.detect_structured_pii(text)

        candidates = cls.detect_structured_pii(text)

        # Batched inference avoids one model call per paragraph.
        chunk_texts = [chunk["text"] for chunk in chunks]

        try:
            predictions = classifier(
                chunk_texts,
                batch_size=BATCH_SIZE,
            )
        except Exception as exc:
            logger.exception("Model inference failed")
            raise PrivacyFilterError(
                f"Model inference failed: {exc}"
            ) from exc

        if len(predictions) != len(chunks):
            raise PrivacyFilterError(
                "Model output count did not match input chunks"
            )

        for chunk, results in zip(chunks, predictions):
            chunk_text = chunk["text"]
            base_offset = chunk["start"]

            for item in results:
                label = str(
                    item.get("entity_group", "")
                ).lower()

                score = float(item.get("score", 0.0))

                if score < confidence_threshold:
                    continue

                start = item.get("start")
                end = item.get("end")

                if start is None or end is None:
                    continue

                if not (0 <= start < end <= len(chunk_text)):
                    continue

                entity_type = OPENAI_TO_OPTIV_TAXONOMY.get(label)

                if not entity_type:
                    continue

                value = chunk_text[start:end]

                # Contextual date handling.
                if label == "private_date":
                    if re.fullmatch(r"20\d{2}", value.strip()):
                        continue

                    prefix = chunk_text[
                        max(0, start - 35):start
                    ].lower()

                    if any(
                        key in prefix
                        for key in ("dob", "birth", "born")
                    ):
                        entity_type = "DATE_OF_BIRTH"
                    elif any(
                        key in prefix
                        for key in ("date:", "dated", "effective")
                    ):
                        continue

                # Convert chunk-relative offsets into offsets
                # relative to the original extracted text.
                entity = cls._make_entity(
                    text=text,
                    start=base_offset + start,
                    end=base_offset + end,
                    entity_type=entity_type,
                    confidence=score,
                    source="OpenAI_Privacy_Filter",
                    raw_label=label,
                )

                if entity:
                    candidates.append(entity)

        return cls.merge_entities(candidates, len(text))

    # -----------------------------------------------------
    # Duplicate and overlap resolution
    # -----------------------------------------------------

    @staticmethod
    def merge_entities(
        candidates: list[dict[str, Any]],
        text_length: int,
    ) -> list[dict[str, Any]]:
        """
        Remove duplicate detections caused by overlapping chunks.
        Prefer higher-confidence entities when spans overlap.
        """
        valid = [
            dict(entity)
            for entity in candidates
            if 0 <= entity["start"] < entity["end"] <= text_length
        ]

        # Deduplicate identical spans and labels, keeping the
        # strongest prediction.
        unique = {}

        for entity in valid:
            key = (
                entity["start"],
                entity["end"],
                entity["entity_type"],
            )

            previous = unique.get(key)

            if (
                previous is None
                or entity["confidence"] > previous["confidence"]
            ):
                unique[key] = entity

        # Prioritise confidence, then longer spans.
        ranked = sorted(
            unique.values(),
            key=lambda entity: (
                -entity["confidence"],
                -(entity["end"] - entity["start"]),
                entity["start"],
            ),
        )

        selected = []

        for entity in ranked:
            overlaps = any(
                entity["start"] < other["end"]
                and other["start"] < entity["end"]
                for other in selected
            )

            if not overlaps:
                selected.append(entity)

        return sorted(selected, key=lambda entity: entity["start"])

    # -----------------------------------------------------
    # Selective redaction
    # -----------------------------------------------------

    @classmethod
    def redact_text(
        cls,
        text: str,
        confidence_threshold: float = CONFIDENCE_THRESHOLD,
        replacement_format: str = "[{entity_type}]",
    ) -> dict[str, Any]:
        """
        Redact only detected PII spans.

        If the model fails, FAIL_CLOSED=True means the original
        text is not returned as if it were safe.
        """
        if not text:
            return {
                "text": text,
                "entities": [],
                "redacted_count": 0,
                "scan_status": "empty_input",
            }

        try:
            entities = cls.detect_in_text(
                text,
                confidence_threshold=confidence_threshold,
            )
        except PrivacyFilterError as exc:
            return {
                "text": None if FAIL_CLOSED else text,
                "entities": [],
                "redacted_count": 0,
                "scan_status": "failed",
                "error": str(exc),
            }

        redacted_text = text

        # Right-to-left replacement preserves all earlier offsets.
        for entity in reversed(entities):
            replacement = replacement_format.format(
                entity_type=entity["entity_type"]
            )

            redacted_text = (
                redacted_text[:entity["start"]]
                + replacement
                + redacted_text[entity["end"]:]
            )

        return {
            "text": redacted_text,
            "entities": entities,
            "redacted_count": len(entities),
            "scan_status": "completed",
        }


# ---------------------------------------------------------
# Example usage
# ---------------------------------------------------------

if __name__ == "__main__":

    logging.basicConfig(level=logging.INFO)

    sample_text = """
To: john.smith@example.com
Employee: EMP-12345
Department: Cybersecurity
Incident review scheduled for Monday.
"""

    result = OpenAIPrivacyFilterEngine.redact_text(sample_text)

    print("Scan status:", result["scan_status"])

    if result["scan_status"] == "completed":
        print("\nRedacted text:\n")
        print(result["text"])

        print("\nDetected entities:")
        for entity in result["entities"]:
            print(
                entity["entity_type"],
                repr(entity["value"]),
                entity["confidence"],
                entity["source"],
            )

        print("\nTotal redactions:", result["redacted_count"])

    else:
        print("Document blocked:", result.get("error"))
