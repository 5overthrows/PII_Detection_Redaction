"""
High-Precision Pattern Library and Algorithmic Checksum Validators.
Provides deterministic candidate matching for financial instruments, government
credentials, and corporate identifiers. Pattern matches still require validation.
"""
import re
from typing import List, Dict, Any, Tuple

def luhn_checksum(card_number_str: str) -> bool:
    """Validates credit card numbers using the standard Luhn algorithm."""
    digits = [int(c) for c in card_number_str if c.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False
    checksum = 0
    reverse_digits = digits[::-1]
    for idx, num in enumerate(reverse_digits):
        if idx % 2 == 1:
            doubled = num * 2
            checksum += doubled - 9 if doubled > 9 else doubled
        else:
            checksum += num
    return checksum % 10 == 0

def aba_routing_checksum(routing_str: str) -> bool:
    """Validates 9-digit US ABA routing transit numbers using standard weights (3, 7, 1)."""
    digits = [int(c) for c in routing_str if c.isdigit()]
    if len(digits) != 9:
        return False
    weights = [3, 7, 1, 3, 7, 1, 3, 7, 1]
    total = sum(d * w for d, w in zip(digits, weights))
    return total % 10 == 0

class PatternLibrary:
    # 1. Government IDs
    SSN_PATTERN = re.compile(r'\b\d{3}-\d{2}-\d{4}\b')
    PASSPORT_KEYWORD_PATTERNS = [
        re.compile(r'\b(?:(?:US\s*)?Passport(?:\s*(?:no|number|id|#))?[:\s]+)([A-Z0-9]{8,9})\b', re.IGNORECASE),
        re.compile(r'\b(?:Passport\s*ID[:\s]+)([A-Z0-9]{8,9})\b', re.IGNORECASE),
    ]
    US_DL_PATTERNS = [
        re.compile(r'\b(?:NY-DL|NY-DL\s*#?|DL|Driver\s*License(?:\s*#)?[:\s]+)([A-Z0-9\-]{7,14})\b', re.IGNORECASE),
        re.compile(r'\bNY-DL([0-9]{7,12})\b', re.IGNORECASE),
    ]
    IN_PAN_PATTERNS = [
        re.compile(r'\b[A-Z]{5}[0-9]{4}[A-Z]\b'),
        re.compile(r'\b(?:PAN(?:\s*Card)?[:\s]+)([A-Z]{5}[0-9]{4}[A-Z])\b', re.IGNORECASE),
    ]
    IN_AADHAAR_PATTERNS = [
        re.compile(r'(?<!\d[\s-])(?<!\d)[2-9][0-9]{3}[\s-][0-9]{4}[\s-][0-9]{4}(?!\s*[-]?\d{4})(?!\d)'),
        re.compile(r'\b(?:Aadhaar(?:\s*(?:no|number|id|#|\(overseas specialist\)))?[:\s]+)([0-9\s-]{12,16})\b', re.IGNORECASE),
    ]

    # 2. Financial & Banking
    CREDIT_CARD_PATTERNS = [
        re.compile(r'\b(?:(?:credit|corporate)\s*card(?:\s*(?:no|number|id|#))?[:\s]+)((?:\d{4}[-\s]?){3}\d{4})\b', re.IGNORECASE),
        re.compile(r'\b(?:\d{4}[-\s]?){3}\d{4}\b|\b3[47]\d{13}\b'),
    ]
    BANK_ACCOUNT_PATTERNS = [
        re.compile(r'\b(?:(?:Assigned\s*)?(?:Bank\s*)?(?:Wire\s*)?Account(?:\s*(?:no|number|id|#))?|Acc\s*No|Checking|Escrow|Settlement(?:\s*Account)?|ACCT)[:\s#-]*([0-9]{8,16})\b', re.IGNORECASE),
        re.compile(r'\bACCT-([0-9]{8,16})\b', re.IGNORECASE),
    ]
    BANK_ROUTING_PATTERN = re.compile(r'\b(?:Routing(?:\s*Number)?|ABA|RTN)[:\s#-]*([0-9]{9})\b', re.IGNORECASE)
    SWIFT_BIC_PATTERN = re.compile(r'\b(?:SWIFT|BIC)[:\s#-]*([A-Z]{4}[A-Z]{2}[A-Z0-9]{2}(?:[A-Z0-9]{3})?)\b|\b[A-Z]{6}[A-Z0-9]{2}[A-Z0-9]{3}\b')
    IFSC_PATTERN = re.compile(r'\b[A-Z]{4}0[A-Z0-9]{6}\b')
    IBAN_PATTERN = re.compile(r'\b[A-Z]{2}[0-9]{2}[A-Z0-9]{4}[0-9]{7}([A-Z0-9]?){0,16}\b')

    # 3. Direct Personal & Contact
    EMAIL_PATTERN = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b')
    PHONE_PATTERNS = [
        re.compile(r'(?<!\d)\+91[\s.-]?[6-9]\d{4}[\s.-]?\d{5}(?!\d)'),         # Indian 5+5 e.g. +91 98840 12345
        re.compile(r'(?<!\d)\+91[\s.-]?[6-9]\d{9}(?!\d)'),                    # Indian 10-digit e.g. +91 9876543210
        re.compile(r'(?<!\d)(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}(?!\d)'), # US e.g. +1 (212) 555-0194
        re.compile(r'\b(?:Phone|Cell|Mobile|Direct|Tel)[:\s]+(\+?[0-9\s().-]{10,20})\b', re.IGNORECASE),
    ]
    DOB_PATTERNS = [
        re.compile(r'\b(?:DOB|Date of Birth|Birth Date)[:\s]+([0-9]{1,2}[\/\-][0-9]{1,2}[\/\-][0-9]{2,4}|[0-9]{1,2}\s+[A-Za-z]+\s+[0-9]{4})\b', re.IGNORECASE),
    ]
    ADDRESS_LINE_PATTERN = re.compile(r'\b\d{1,5}\s+[A-Za-z0-9\s,.-]+?\b(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Terrace|Way|Drive|Dr|Nagar|Lane|Ln|Apt|Suite)\b', re.IGNORECASE)
    ADDRESS_BLOCK_PATTERN = re.compile(r'\b(?:Address|Residential\s*Address)[:\s]*\n([0-9]{1,5}\s+[^\n]+(?:\n[^\n]+){1,3})', re.IGNORECASE)

    # 4. Corporate & Educational Identifiers
    CADENCE_EMP_ID_PATTERN = re.compile(r'\b(?:EMP|EID|STAFF|Emp\s*ID|Employee\s*ID)[:\s#-]*([0-9]{4,6})\b|\bEMP-[0-9]{4,6}\b', re.IGNORECASE)
    STUDENT_ID_PATTERNS = [
        re.compile(r'\b[0-9]{2}[A-Z]{3}[0-9]{4}\b'),
        re.compile(r'\b(?:Student\s*ID(?:\s*#)?[:\s]+)([A-Z0-9]{6,12})\b', re.IGNORECASE),
    ]

    @classmethod
    def find_all_matches(cls, text: str) -> List[Dict[str, Any]]:
        matches: List[Dict[str, Any]] = []

        # 1. SSN
        for m in cls.SSN_PATTERN.finditer(text):
            matches.append({
                "entity_type": "US_SSN",
                "value": m.group(0),
                "start": m.start(),
                "end": m.end(),
                "confidence": 1.0,
                "source": "Regex_Checksum_Engine"
            })

        # 2. Credit Cards with keyword or Luhn validation
        for pat in cls.CREDIT_CARD_PATTERNS:
            for m in pat.finditer(text):
                val = m.group(1) if m.groups() else m.group(0)
                s = m.start(1) if m.groups() else m.start()
                e = m.end(1) if m.groups() else m.end()
                cleaned = "".join(filter(str.isdigit, val))
                if m.groups() or luhn_checksum(cleaned):
                    matches.append({
                        "entity_type": "CREDIT_CARD",
                        "value": val,
                        "start": s,
                        "end": e,
                        "confidence": 1.0,
                        "source": "Regex_Checksum_Engine"
                    })

        # 3. Indian PAN
        for pat in cls.IN_PAN_PATTERNS:
            for m in pat.finditer(text):
                val = m.group(1) if m.groups() else m.group(0)
                s = m.start(1) if m.groups() else m.start()
                e = m.end(1) if m.groups() else m.end()
                if len(val) == 10 and val[3] in "PCAFHTLJG":
                    matches.append({
                        "entity_type": "IN_PAN",
                        "value": val,
                        "start": s,
                        "end": e,
                        "confidence": 0.98,
                        "source": "Regex_Checksum_Engine"
                    })

        # 4. Indian Aadhaar
        for pat in cls.IN_AADHAAR_PATTERNS:
            for m in pat.finditer(text):
                val = m.group(1).strip() if m.groups() else m.group(0).strip()
                s = m.start(1) if m.groups() else m.start()
                e = m.end(1) if m.groups() else m.end()
                digits_only = "".join(filter(str.isdigit, val))
                if len(digits_only) == 12:
                    matches.append({
                        "entity_type": "IN_AADHAAR",
                        "value": val,
                        "start": s,
                        "end": e,
                        "confidence": 0.96,
                        "source": "Regex_Checksum_Engine"
                    })

        # 5. Bank Account Numbers
        for pat in cls.BANK_ACCOUNT_PATTERNS:
            for m in pat.finditer(text):
                val = m.group(1).strip() if m.groups() else m.group(0).strip()
                s = m.start(1) if m.groups() else m.start()
                e = m.end(1) if m.groups() else m.end()
                # Ensure it's not a dollar amount, standard year, or employee id
                if not val.startswith("$") and len(val) >= 8 and not any(k in val.lower() for k in ["emp", "eid"]):
                    matches.append({
                        "entity_type": "BANK_ACCOUNT",
                        "value": val,
                        "start": s,
                        "end": e,
                        "confidence": 0.95,
                        "source": "Cadence_Financial_Engine"
                    })

        # 6. Bank Routing Numbers
        for m in cls.BANK_ROUTING_PATTERN.finditer(text):
            val = m.group(1)
            valid = aba_routing_checksum(val)
            matches.append({
                "entity_type": "BANK_ROUTING",
                "value": val,
                "start": m.start(1),
                "end": m.end(1),
                "confidence": 0.99 if valid else 0.85,
                "source": "Regex_Checksum_Engine"
            })

        # 7. SWIFT / BIC
        for m in cls.SWIFT_BIC_PATTERN.finditer(text):
            if m.group(1):
                val = m.group(1)
                s, e = m.start(1), m.end(1)
            else:
                val = m.group(0)
                s, e = m.start(), m.end()
            matches.append({
                "entity_type": "SWIFT_BIC",
                "value": val,
                "start": s,
                "end": e,
                "confidence": 0.92,
                "source": "Regex_Checksum_Engine"
            })

        # 8. IFSC Code
        for m in cls.IFSC_PATTERN.finditer(text):
            matches.append({
                "entity_type": "IFSC_CODE",
                "value": m.group(0),
                "start": m.start(),
                "end": m.end(),
                "confidence": 0.98,
                "source": "Regex_Checksum_Engine"
            })

        # 9. Passports
        for pat in cls.PASSPORT_KEYWORD_PATTERNS:
            for m in pat.finditer(text):
                val = m.group(1).strip()
                s = m.start(1)
                e = m.end(1)
                matches.append({
                    "entity_type": "US_PASSPORT",
                    "value": val,
                    "start": s,
                    "end": e,
                    "confidence": 0.96,
                    "source": "Cadence_Rule"
                })

        # 10. Driver's License
        for pat in cls.US_DL_PATTERNS:
            for m in pat.finditer(text):
                val = m.group(1).strip() if m.groups() else m.group(0).strip()
                s = m.start(1) if m.groups() else m.start()
                e = m.end(1) if m.groups() else m.end()
                matches.append({
                    "entity_type": "US_DRIVER_LICENSE",
                    "value": val,
                    "start": s,
                    "end": e,
                    "confidence": 0.94,
                    "source": "Cadence_Rule"
                })

        # 11. Employee IDs
        for m in cls.CADENCE_EMP_ID_PATTERN.finditer(text):
            matches.append({
                "entity_type": "EMPLOYEE_ID",
                "value": m.group(0),
                "start": m.start(),
                "end": m.end(),
                "confidence": 0.96,
                "source": "Cadence_Corporate_Engine"
            })

        # 12. Student IDs
        for pat in cls.STUDENT_ID_PATTERNS:
            for m in pat.finditer(text):
                val = m.group(1).strip() if m.groups() else m.group(0).strip()
                s = m.start(1) if m.groups() else m.start()
                e = m.end(1) if m.groups() else m.end()
                matches.append({
                    "entity_type": "STUDENT_ID",
                    "value": val,
                    "start": s,
                    "end": e,
                    "confidence": 0.94,
                    "source": "Regex_Checksum_Engine"
                })

        # 13. Date of Birth
        for pat in cls.DOB_PATTERNS:
            for m in pat.finditer(text):
                matches.append({
                    "entity_type": "DATE_OF_BIRTH",
                    "value": m.group(1).strip(),
                    "start": m.start(1),
                    "end": m.end(1),
                    "confidence": 0.95,
                    "source": "Cadence_Rule"
                })

        # 14. Emails
        for m in cls.EMAIL_PATTERN.finditer(text):
            matches.append({
                "entity_type": "EMAIL_ADDRESS",
                "value": m.group(0),
                "start": m.start(),
                "end": m.end(),
                "confidence": 1.0,
                "source": "Regex_Checksum_Engine"
            })

        # 15. Phones
        for pat in cls.PHONE_PATTERNS:
            for m in pat.finditer(text):
                val = m.group(1).strip() if m.groups() else m.group(0).strip()
                s = m.start(1) if m.groups() else m.start()
                e = m.end(1) if m.groups() else m.end()
                digits = "".join(filter(str.isdigit, val))
                if len(digits) >= 10:
                    matches.append({
                        "entity_type": "PHONE_NUMBER",
                        "value": val,
                        "start": s,
                        "end": e,
                        "confidence": 0.92,
                        "source": "Regex_Checksum_Engine"
                    })

        # 16. Street Addresses
        for m in cls.ADDRESS_BLOCK_PATTERN.finditer(text):
            matches.append({
                "entity_type": "STREET_ADDRESS",
                "value": m.group(1).strip(),
                "start": m.start(1),
                "end": m.end(1),
                "confidence": 0.90,
                "source": "Cadence_Contextual_Engine"
            })

        for m in cls.ADDRESS_LINE_PATTERN.finditer(text):
            matches.append({
                "entity_type": "STREET_ADDRESS",
                "value": m.group(0).strip(),
                "start": m.start(),
                "end": m.end(),
                "confidence": 0.88,
                "source": "Cadence_Contextual_Engine"
            })

        # Deduplicate overlapping exact matches from multiple rules and ensure exact span bounds
        seen = set()
        deduped = []
        for m in matches:
            s, e = m["start"], m["end"]
            while s < e and text[s].isspace():
                s += 1
            while e > s and text[e - 1].isspace():
                e -= 1
            if s >= e:
                continue
            m["start"] = s
            m["end"] = e
            m["value"] = text[s:e]
            key = (m["start"], m["end"], m["entity_type"])
            if key not in seen:
                seen.add(key)
                deduped.append(m)

        return deduped
