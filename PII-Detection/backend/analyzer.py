"""Shared Presidio analyzer instance — backed by BERT (dslim/bert-base-NER)."""

from __future__ import annotations

import re
from functools import lru_cache
from typing import Any

from presidio_analyzer import AnalyzerEngine
from presidio_analyzer.nlp_engine import NlpEngineProvider

from .indian_recognizers import register_indian_recognizers

# All Presidio entity types to detect (including Indian identifiers)
PII_ENTITIES = [
    "PERSON", "EMAIL_ADDRESS", "PHONE_NUMBER", "CREDIT_CARD",
    "DATE_TIME", "IBAN_CODE", "IP_ADDRESS", "LOCATION",
    "US_BANK_NUMBER", "US_DRIVER_LICENSE", "US_ITIN", "US_PASSPORT", "US_SSN",
    "IN_AADHAAR", "IN_PAN", "IN_VOTER_ID",
]

_SCORE_THRESHOLD = 0.5
_ADDRESS_CONTEXT = re.compile(
    r"\b(?:(?:home|residential|mailing|customer|client|borrower|employee)\s+)?"
    r"(?:street\s+)?address\b\s*(?:no\.?|number)?\s*[:=#-]?",
    re.IGNORECASE,
)
_BIRTH_DATE_CONTEXT = re.compile(
    r"\b(?:date\s+of\s+birth|birth\s+date|dob)\b\s*[:=#-]?",
    re.IGNORECASE,
)

# BERT model config: uses dslim/bert-base-NER for NER,
# spaCy en_core_web_sm for tokenization. All runs locally.
_NLP_CONFIGURATION = {
    "nlp_engine_name": "transformers",
    "models": [
        {
            "lang_code": "en",
            "model_name": {
                "spacy": "en_core_web_sm",
                "transformers": "dslim/bert-base-NER",
            },
        }
    ],
}


@lru_cache(maxsize=1)
def get_analyzer() -> AnalyzerEngine:
    """Build and cache the AnalyzerEngine with BERT NLP backend."""
    provider = NlpEngineProvider(nlp_configuration=_NLP_CONFIGURATION)
    nlp_engine = provider.create_engine()
    engine = AnalyzerEngine(
        nlp_engine=nlp_engine,
        supported_languages=["en"],
    )
    register_indian_recognizers(engine)
    return engine


def analyze(text: str) -> list:
    """Detect likely PII, requiring context for generic locations and dates."""
    results = get_analyzer().analyze(
        text=text,
        language="en",
        entities=PII_ENTITIES,
        score_threshold=_SCORE_THRESHOLD,
    )
    filtered_results: list[Any] = []
    for result in results:
        if result.entity_type == "LOCATION":
            context = text[max(0, result.start - 60):result.start]
            if not _ADDRESS_CONTEXT.search(context):
                continue
        elif result.entity_type == "DATE_TIME":
            context = text[max(0, result.start - 40):result.start]
            if not _BIRTH_DATE_CONTEXT.search(context):
                continue
        filtered_results.append(result)
    return filtered_results
