"""Custom Presidio recognizers for Indian identifiers: Aadhaar, PAN, and Voter ID."""

from __future__ import annotations

import re
from presidio_analyzer import Pattern, PatternRecognizer, RecognizerResult

# Verhoeff algorithm tables for Aadhaar checksum validation
_VERHOEFF_D = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
    [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
    [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
    [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
    [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
    [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
    [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
    [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
]

_VERHOEFF_P = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
    [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
    [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
    [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
    [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
    [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
]


def is_valid_verhoeff(num_str: str) -> bool:
    """Validate 12-digit Aadhaar using Verhoeff checksum algorithm."""
    clean = re.sub(r"[\s-]", "", num_str)
    if len(clean) != 12 or not clean.isdigit():
        return False
    c = 0
    for i, ch in enumerate(reversed(clean)):
        c = _VERHOEFF_D[c][_VERHOEFF_P[i % 8][int(ch)]]
    return c == 0


class AadhaarRecognizer(PatternRecognizer):
    """Recognizer for Indian Aadhaar Numbers (UIDAI).

    Supports:
      - 12 digits formatted as XXXX XXXX XXXX
      - 12 digits formatted as XXXX-XXXX-XXXX
      - 12 continuous digits (boosted by context or Verhoeff checksum)
    """

    PATTERNS = [
        # Spaced: 1286 1111 2233
        Pattern("aadhaar_spaced", r"\b\d{4}\s\d{4}\s\d{4}\b", 0.9),
        # Hyphenated: 1286-1111-2233
        Pattern("aadhaar_hyphen", r"\b\d{4}-\d{4}-\d{4}\b", 0.9),
        # Continuous: 128611112233 (very common in OCR text)
        Pattern("aadhaar_continuous", r"\b\d{12}\b", 0.8),
    ]

    CONTEXT = [
        "aadhaar", "aadhar", "uidai", "uid", "adhaar", "adhaarnumber",
        "aadharno", "aadhaarno", "unique identification", "mera aadhaar",
        "identity card", "gov of india", "government of india", "governmentoeindia",
        "father", "name", "dob", "gender", "address",
    ]

    def __init__(self):
        super().__init__(
            supported_entity="IN_AADHAAR",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
            name="IndianAadhaarRecognizer",
        )

    def validate_result(self, pattern_text: str) -> bool:
        clean = re.sub(r"[\s-]", "", pattern_text)
        return len(clean) == 12 and clean.isdigit()


class PanRecognizer(PatternRecognizer):
    """Recognizer for Indian Permanent Account Number (PAN Card)."""

    PATTERNS = [
        Pattern("pan_card", r"\b[A-Z]{5}[0-9]{4}[A-Z]\b", 0.85),
    ]

    CONTEXT = [
        "pan", "pan card", "pancard", "permanent account number",
        "income tax", "nsdl", "uti", "pan no", "panno",
    ]

    def __init__(self):
        super().__init__(
            supported_entity="IN_PAN",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
            name="IndianPanRecognizer",
        )


class VoterIdRecognizer(PatternRecognizer):
    """Recognizer for Indian Voter ID (EPIC Number)."""

    PATTERNS = [
        Pattern("voter_id", r"\b[A-Z]{3}[0-9]{7}\b", 0.8),
    ]

    CONTEXT = [
        "voter", "voter id", "voterid", "epic", "election commission",
        "elector", "identity card", "eci",
    ]

    def __init__(self):
        super().__init__(
            supported_entity="IN_VOTER_ID",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
            name="IndianVoterIdRecognizer",
        )


def register_indian_recognizers(analyzer) -> None:
    """Register all Indian PII recognizers into the AnalyzerEngine registry."""
    analyzer.registry.add_recognizer(AadhaarRecognizer())
    analyzer.registry.add_recognizer(PanRecognizer())
    analyzer.registry.add_recognizer(VoterIdRecognizer())
