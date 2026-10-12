"""
Hybrid Multi-Tier PII Detection Engine.
Integrates:
- Tier 1: Deterministic regex and algorithmic checksum validators (Luhn, ABA, PAN, Aadhaar)
- Tier 2: OpenAI Privacy Filter local bidirectional token-classification neural model
- Tier 3: Cadence contextual heuristics (labelled roles, corporate identifiers)
- Tier 4: Microsoft Presidio NER (fallback for general language)
- Tier 5: Contextual disambiguation & false-positive pruning

Uses configurable detection rules and optional NER; performance must be measured against labeled data.
"""
import re
from typing import List, Dict, Any, Optional
from extractors.models import DocumentContent, ContentBlock
from detector.pii_models import PIIEntity, PII_CATEGORY_MAP, PII_SEVERITY_MAP
from detector.pattern_library import PatternLibrary
from detector.openai_privacy_filter import OpenAIPrivacyFilterEngine

# Lazy-loaded Presidio Analyzer
_PRESIDIO_ANALYZER = None

def get_presidio_analyzer():
    global _PRESIDIO_ANALYZER
    if _PRESIDIO_ANALYZER is None:
        try:
            from presidio_analyzer import AnalyzerEngine
            from presidio_analyzer.nlp_engine import NlpEngineProvider
            config = {
                "nlp_engine_name": "spacy",
                "models": [{"lang_code": "en", "model_name": "en_core_web_sm"}]
            }
            provider = NlpEngineProvider(nlp_configuration=config)
            engine = provider.create_engine()
            _PRESIDIO_ANALYZER = AnalyzerEngine(nlp_engine=engine)
        except Exception:
            _PRESIDIO_ANALYZER = False
    return _PRESIDIO_ANALYZER if _PRESIDIO_ANALYZER is not False else None

class PIIEngine:
    PII_CONTEXT = re.compile(r"(?:name|person|borrower|beneficiary|guarantor|contact|author|officer|employee|account|passport|ssn|email|phone|address)\s*(?:#|no\.?|number)?\s*[:=]", re.IGNORECASE)
    NAME_LABEL_PATTERNS = [
        re.compile(r'\b(?:Full\s*Name|Client\s*Name|Borrower|Primary\s*Borrower|Beneficiary(?:\s*Name)?|Guarantor|Underwriter|Senior\s*Underwriter|Author|Officer|Primary\s*Contact|Emergency\s*Contact|Lead\s*Contractor|Senior\s*Risk\s*Manager|Name)[:\s]+([A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,3})\b'),
        re.compile(r'\b(?:Mr\.|Ms\.|Mrs\.|Dr\.)\s+([A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,2})\b'),
    ]

    # Whitelist of corporate, financial, and reporting terms that NER often falsely flags as PII
    FALSE_POSITIVE_WHITELIST = {
        "checking", "savings", "escrow", "settlement", "balance", "balance usd",
        "operating checking", "escrow reserve", "visa infinite", "corporate card",
        "institution", "underwriting", "assessment", "policy", "cadence",
        "cadence financial services", "cadence commercial", "citibank", "citibank n.a.",
        "jpmorgan chase", "jpmorgan chase ny", "department", "division",
        "strictly confidential", "confidential", "incident review",
        "lead contractor", "senior risk manager", "senior underwriter",
        "table", "n/a", "na", "direct", "cell", "phone", "email",
        "credit risk", "commercial", "operating", "memo", "memorandum",
        "total", "rate", "usd", "account", "borrower", "client", "officer",
        "risk governance division", "private wealth management",
        "optiv", "optiv consulting", "optiv automated pii gateway", "pii gateway", "gateway",
        "automated pii gateway", "aadhaar", "pan", "pan card", "passport", "ssn",
        "license", "driver license", "tprm", "ai governance committee",
        "vendor api", "security incident review", "recommendation"
    }

    @classmethod
    def detect_in_document(cls, doc: DocumentContent, skip_neural: bool = False) -> List[PIIEntity]:
        all_entities: List[PIIEntity] = []

        # Analyze block by block to preserve source traceability (page, line, table)
        for block in doc.blocks:
            block_entities = cls.detect_in_text(block.text, block_id=block.block_id, location=block.location, skip_neural=skip_neural)
            all_entities.extend(block_entities)

        return all_entities

    @classmethod
    def detect_in_text(cls, text: str, block_id: Optional[str] = None, location: Optional[Dict[str, Any]] = None, skip_neural: bool = False) -> List[PIIEntity]:
        if not text or not text.strip():
            return []

        candidates: List[Dict[str, Any]] = []

        # 1. Tier 1: Deterministic Pattern & Checksum Engine (Highest Precision & Mathematical Grounding)
        pattern_matches = PatternLibrary.find_all_matches(text)
        candidates.extend(pattern_matches)

        # 2. Tier 2: OpenAI Privacy Filter (Local Neural Token-Classification)
        if not skip_neural:
            openai_matches = OpenAIPrivacyFilterEngine.detect_in_text(text)
            candidates.extend(openai_matches)

        # 3. Contextual name and role heuristics add candidates for labeled fields.
        for pat in cls.NAME_LABEL_PATTERNS:
            for m in pat.finditer(text):
                s, e = m.start(1), m.end(1)
                while s < e and text[s].isspace():
                    s += 1
                while e > s and text[e - 1].isspace():
                    e -= 1
                if s >= e:
                    continue
                name_val = text[s:e]
                candidates.append({
                    "entity_type": "PERSON",
                    "value": name_val,
                    "start": s,
                    "end": e,
                    "confidence": 0.98,
                    "source": "Cadence_Contextual_Rule"
                })

        # 4. Tier 4: Presidio Analyzer (Broad NER Cross-Validation)
        analyzer = get_presidio_analyzer()
        if analyzer:
            try:
                presidio_results = analyzer.analyze(
                    text=text,
                    language="en",
                    entities=["PERSON", "LOCATION", "EMAIL_ADDRESS", "PHONE_NUMBER"]
                )
                for res in presidio_results:
                    val = text[res.start:res.end].strip()
                    if len(val) <= 2:
                        continue

                    e_type = res.entity_type
                    # Filter out financial and non-PII terms from Presidio
                    if cls._is_safe_whitelist_match(text, res.start, res.end, val):
                        continue

                    # If tagged as location but contains common financial tokens, drop
                    if e_type == "LOCATION" and any(w in val.lower() for w in ["checking", "escrow", "savings", "balance", "total", "credit"]):
                        continue

                    candidates.append({
                        "entity_type": e_type,
                        "value": val,
                        "start": res.start,
                        "end": res.end,
                        "confidence": round(res.score, 2),
                        "source": "Presidio_NER"
                    })
            except Exception:
                pass

        # 5. Tier 5: Conflict Resolution, Span Merging & Strict False-Positive Filtering
        resolved = cls._resolve_overlapping_entities(text, candidates, block_id, location)
        return resolved

    @classmethod
    def _resolve_overlapping_entities(cls, text: str, candidates: List[Dict[str, Any]], 
                                       block_id: Optional[str], location: Optional[Dict[str, Any]]) -> List[PIIEntity]:
        if not candidates:
            return []

        # Filter out obvious false positives before sorting and normalize spans
        filtered_candidates = []
        for c in candidates:
            s, e = c["start"], c["end"]
            while s < e and text[s].isspace():
                s += 1
            while e > s and text[e - 1].isspace():
                e -= 1
            if s >= e:
                continue

            c["start"] = s
            c["end"] = e
            c["value"] = text[s:e]

            val_clean = c["value"].strip()
            val_lower = val_clean.lower()

            # Discard whitelist items
            if cls._is_safe_whitelist_match(text, c["start"], c["end"], val_clean):
                continue

            # Discard standalone dollar values (e.g. $1,450,200) falsely matched
            if val_clean.startswith("$") and any(ch.isdigit() for ch in val_clean):
                continue

            # Discard table headers or labels falsely tagged
            if val_lower in {"client name", "tax id / ssn", "account number", "contact email", "phone", "institution", "primary borrower", "underwriter"}:
                continue

            filtered_candidates.append(c)

        # Priority weights: deterministic checksums > OpenAI Privacy Filter > contact/IDs > NER
        priority_map = {
            "US_SSN": 10,
            "CREDIT_CARD": 10,
            "IN_PAN": 10,
            "IN_AADHAAR": 10,
            "SECRET_KEY": 10,
            "US_PASSPORT": 10,
            "US_DRIVER_LICENSE": 10,
            "EMPLOYEE_ID": 10,
            "STUDENT_ID": 9,
            "BANK_ACCOUNT": 9,
            "BANK_ROUTING": 9,
            "SWIFT_BIC": 8,
            "IFSC_CODE": 8,
            "EMAIL_ADDRESS": 8,
            "PHONE_NUMBER": 8,
            "DATE_OF_BIRTH": 7,
            "PERSON": 7,
            "STREET_ADDRESS": 6,
            "FINANCIAL_ACCOUNT": 6,
            "URL_ADDRESS": 5,
            "IP_ADDRESS": 5,
            "LOCATION": 3
        }

        # Source priority bonus: Regex Checksum (+2) > OpenAI Privacy Filter (+1.5) > Contextual Rule (+1) > Presidio (+0)
        source_bonus = {
            "Regex_Checksum_Engine": 2.0,
            "Cadence_Financial_Engine": 2.0,
            "Cadence_Corporate_Engine": 2.0,
            "OpenAI_Privacy_Filter": 1.5,
            "Cadence_Contextual_Rule": 1.2,
            "Cadence_Rule": 1.2,
            "Cadence_Contextual_Engine": 1.0,
            "Presidio_NER": 0.0
        }

        # Sort by effective priority desc, then length desc, then confidence desc, then start asc
        sorted_candidates = sorted(
            filtered_candidates,
            key=lambda c: (
                -(priority_map.get(c["entity_type"], 1) + source_bonus.get(c.get("source", ""), 0)),
                -(c["end"] - c["start"]),
                -c["confidence"],
                c["start"]
            )
        )

        merged: List[Dict[str, Any]] = []
        for cand in sorted_candidates:
            c_start = cand["start"]
            c_end = cand["end"]
            # Non-overlapping condition: cannot overlap with ANY already accepted candidate
            if not any(not (c_end <= existing["start"] or c_start >= existing["end"]) for existing in merged):
                merged.append(cand)

        # Sort merged back by start position
        merged.sort(key=lambda x: x["start"])

        # Convert to PIIEntity dataclass with context capture
        entities: List[PIIEntity] = []
        for item in merged:
            s, e = item["start"], item["end"]
            ctx_start = max(0, s - 30)
            ctx_end = min(len(text), e + 30)
            ctx_before = text[ctx_start:s].replace("\n", " ")
            ctx_after = text[e:ctx_end].replace("\n", " ")

            entity = PIIEntity(
                entity_type=item["entity_type"],
                value=item["value"],
                start=s,
                end=e,
                confidence=item["confidence"],
                source=item.get("source", "PIIEngine"),
                category=PII_CATEGORY_MAP.get(item["entity_type"], "General Personal Data"),
                severity=PII_SEVERITY_MAP.get(item["entity_type"], "MEDIUM"),
                context_before=ctx_before,
                context_after=ctx_after,
                block_id=block_id,
                location=location or {}
            )
            entities.append(entity)

        return entities

    @classmethod
    def _is_safe_whitelist_match(cls, text: str, start: int, end: int, value: str) -> bool:
        """Whitelist ordinary terms only when nearby text does not label them as PII."""
        if value.lower() not in cls.FALSE_POSITIVE_WHITELIST:
            return False
        prefix = text[max(0, start - 45):start]
        return not cls.PII_CONTEXT.search(prefix)
