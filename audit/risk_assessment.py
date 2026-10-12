"""
Risk Assessment, Regulatory Compliance Evaluation, and Source Traceability Audit Engine.
Calculates Cadence PII Exposure Index, evaluates regulatory liabilities (GLBA, NYDFS, GDPR),
and formats structured audit trails.
"""
from dataclasses import dataclass, field
from typing import List, Dict, Any
import pandas as pd
from detector.pii_models import PIIEntity
from extractors.models import DocumentContent

@dataclass
class AuditReport:
    file_name: str
    file_type: str
    total_words: int
    total_pii_count: int
    pii_density_per_100w: float
    exposure_score: int # 0 - 100
    exposure_level: str # CRITICAL, HIGH, MEDIUM, LOW
    breakdown_by_category: Dict[str, int]
    breakdown_by_severity: Dict[str, int]
    regulatory_impacts: List[Dict[str, str]]
    traceability_records: List[Dict[str, Any]]
    llm_guard_status: str = "UNVERIFIED"

class RiskAssessmentEngine:
    @classmethod
    def generate_audit_report(cls, doc: DocumentContent, entities: List[PIIEntity]) -> AuditReport:
        total_pii = len(entities)
        words = max(1, doc.total_words)
        density = round((total_pii / words) * 100, 2)

        # Categorization breakdown
        category_counts: Dict[str, int] = {}
        severity_counts: Dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}

        for e in entities:
            category_counts[e.category] = category_counts.get(e.category, 0) + 1
            severity_counts[e.severity] = severity_counts.get(e.severity, 0) + 1

        # Calculate Exposure Score (Weighted)
        # CRITICAL = 15 pts each, HIGH = 8 pts each, MEDIUM = 3 pts each, LOW = 1 pt each
        raw_score = (
            severity_counts["CRITICAL"] * 15 +
            severity_counts["HIGH"] * 8 +
            severity_counts["MEDIUM"] * 3 +
            severity_counts["LOW"] * 1
        )
        exposure_score = min(100, raw_score)

        if severity_counts["CRITICAL"] > 0 or exposure_score >= 50:
            exposure_level = "CRITICAL"
        elif severity_counts["HIGH"] > 0 or exposure_score >= 30:
            exposure_level = "HIGH"
        elif exposure_score >= 10:
            exposure_level = "MEDIUM"
        else:
            exposure_level = "LOW"

        # Regulatory Impacts Analysis
        reg_impacts = []
        if severity_counts["CRITICAL"] > 0 or "Financial & Banking" in category_counts:
            reg_impacts.append({
                "framework": "GLBA (Gramm-Leach-Bliley Act)",
                "mandate": "Safeguards Rule § 314.4",
                "risk": "Transmission of nonpublic personal financial customer records to unauthorized third-party LLMs carries severe regulatory enforcement and non-compliance fines."
            })
            reg_impacts.append({
                "framework": "NYDFS 23 NYCRR 500",
                "mandate": "Cybersecurity Requirements for Financial Services",
                "risk": "Exposure of confidential banking credentials and SSNs requires mandatory 72-hour notification to the Superintendent."
            })
        if "Government Identification" in category_counts or "Direct Personal Identity" in category_counts:
            reg_impacts.append({
                "framework": "GDPR / CCPA / CPRA",
                "mandate": "Article 6 / 9 (Special Category Data) & CPRA § 1798.100",
                "risk": "Processing biometric or government identifiers in generative AI without explicit consent violates cross-border data protection treaties."
            })
        if "Corporate / Internal Credentials" in category_counts:
            reg_impacts.append({
                "framework": "Internal Information Security Policy",
                "mandate": "Cadence AI Governance Directive 2026-R4",
                "risk": "Exposure of internal staff IDs and wire officer routing creates targeted spear-phishing and operational security vulnerabilities."
            })

        # Build Traceability Records
        traceability = []
        for idx, e in enumerate(entities, start=1):
            loc_str = " | ".join(f"{k}: {v}" for k, v in e.location.items()) if e.location else f"Block: {e.block_id}"
            masked_val = cls._mask_value(e.value, e.entity_type)

            traceability.append({
                "id": idx,
                "entity_type": e.entity_type,
                "category": e.category,
                "severity": e.severity,
                "masked_value": masked_val,
                "surrogate_token": e.surrogate_token or f"[{e.entity_type}_{idx}]",
                "confidence": f"{int(e.confidence * 100)}%",
                "source": e.source,
                "location": loc_str
            })

        return AuditReport(
            file_name=doc.file_name,
            file_type=doc.file_type,
            total_words=words,
            total_pii_count=total_pii,
            pii_density_per_100w=density,
            exposure_score=exposure_score,
            exposure_level=exposure_level,
            breakdown_by_category=category_counts,
            breakdown_by_severity=severity_counts,
            regulatory_impacts=reg_impacts,
            traceability_records=traceability
        )

    @staticmethod
    def _mask_value(val: str, entity_type: str) -> str:
        # Audit exports must not retain even partial identifiers (for example,
        # last-four digits or an email domain). Entity type and token provide
        # traceability without exporting the original value.
        return "[REDACTED]"
