"""
Data structures for detected PII entities and classification taxonomies.
"""
from dataclasses import dataclass, field
from typing import Dict, Any, Optional

PII_CATEGORY_MAP = {
    "US_SSN": "Government Identification",
    "US_PASSPORT": "Government Identification",
    "US_DRIVER_LICENSE": "Government Identification",
    "IN_PAN": "Government Identification",
    "IN_AADHAAR": "Government Identification",
    "CREDIT_CARD": "Financial & Banking",
    "BANK_ACCOUNT": "Financial & Banking",
    "BANK_ROUTING": "Financial & Banking",
    "SWIFT_BIC": "Financial & Banking",
    "IFSC_CODE": "Financial & Banking",
    "IBAN_CODE": "Financial & Banking",
    "PERSON": "Direct Personal Identity",
    "DATE_OF_BIRTH": "Direct Personal Identity",
    "STREET_ADDRESS": "Direct Personal Identity",
    "EMAIL_ADDRESS": "Contact Information",
    "PHONE_NUMBER": "Contact Information",
    "EMPLOYEE_ID": "Corporate / Internal Credentials",
    "STUDENT_ID": "Corporate / Internal Credentials",
    "SECRET_KEY": "Corporate / Internal Credentials",
    "IP_ADDRESS": "Technical Identifier",
    "URL_ADDRESS": "Technical Identifier",
    "LOCATION": "Geographic / Location Data",
    "FINANCIAL_ACCOUNT": "Financial & Banking",
}

PII_SEVERITY_MAP = {
    "US_SSN": "CRITICAL",
    "CREDIT_CARD": "CRITICAL",
    "US_PASSPORT": "CRITICAL",
    "IN_PAN": "CRITICAL",
    "IN_AADHAAR": "CRITICAL",
    "SECRET_KEY": "CRITICAL",
    "BANK_ACCOUNT": "HIGH",
    "BANK_ROUTING": "HIGH",
    "SWIFT_BIC": "HIGH",
    "US_DRIVER_LICENSE": "HIGH",
    "PERSON": "HIGH",
    "DATE_OF_BIRTH": "HIGH",
    "FINANCIAL_ACCOUNT": "HIGH",
    "EMPLOYEE_ID": "MEDIUM",
    "STUDENT_ID": "MEDIUM",
    "EMAIL_ADDRESS": "MEDIUM",
    "PHONE_NUMBER": "MEDIUM",
    "STREET_ADDRESS": "MEDIUM",
    "LOCATION": "LOW",
    "IP_ADDRESS": "LOW",
    "URL_ADDRESS": "LOW",
}

@dataclass
class PIIEntity:
    entity_type: str
    value: str
    start: int
    end: int
    confidence: float
    source: str  # 'Presidio_NER', 'Regex_Checksum_Engine', 'Cadence_Rule'
    category: str = "General Personal Data"
    severity: str = "MEDIUM"
    context_before: str = ""
    context_after: str = ""
    block_id: Optional[str] = None
    location: Dict[str, Any] = field(default_factory=dict)
    surrogate_token: Optional[str] = None

    def __post_init__(self):
        if not self.category or self.category == "General Personal Data":
            self.category = PII_CATEGORY_MAP.get(self.entity_type, "General Personal Data")
        if not self.severity:
            self.severity = PII_SEVERITY_MAP.get(self.entity_type, "MEDIUM")
